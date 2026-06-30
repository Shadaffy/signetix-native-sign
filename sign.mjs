#!/usr/bin/env node
/**
 * Signetix native-key signer — Ed25519 signing tool with local hash verification.
 *
 * Pairs with the in-browser flows at /sign-in/native, the proposal sign panel,
 * the fee-sign panel, and the account-creation panel. Each panel exposes a
 * "sign payload" JSON blob containing { intent_hash_hex, subintent_header,
 * manifest }. This tool recomputes the partial-transaction hash locally from
 * the manifest + header, refuses to sign if the recomputed hash does not match
 * the one Signetix served, and then signs.
 *
 * That refusal is the whole point: Signetix could otherwise display one
 * manifest while serving a different hash, and a blind signer would sign
 * something other than what they thought they were authorising. Computing the
 * hash here, off the web tier, breaks that exposure — the engine accepts only
 * the signature over the canonical (manifest, header) pair, so if our locally-
 * derived hash matches the served one, the manifest the user is signing is
 * provably the one whose hash the engine will check against.
 *
 * Why a standalone tool: pasting private keys into a webpage is the exact
 * pattern wallets exist to prevent, so Signetix deliberately does not accept
 * your key in the browser. This script runs locally and prints only the
 * signature.
 *
 * Requirements: Node 18+ (Windows, macOS, Linux). One small dep installed
 * via `npm install` — see README for the no-clone install path.
 *
 * Usage — verified (recommended):
 *   node sign.mjs --payload payload.json
 *   $env:SIGNETIX_PAYLOAD = '<json>'; node sign.mjs    # Windows
 *   SIGNETIX_PAYLOAD='<json>' node sign.mjs            # macOS / Linux
 *
 *   # Or with manifest + header in separate files plus the hash:
 *   node sign.mjs --manifest m.txt --header h.json <hash-hex>
 *
 * Usage — blind (LEGACY, prints a loud warning):
 *   node sign.mjs <hash-hex>
 *
 * The tool always prints the derived public key so you can sanity-check
 * that you used the right private key before pasting the signature.
 */
import crypto from 'node:crypto';
import readline from 'node:readline';
import { readFileSync } from 'node:fs';

import { RadixEngineToolkit, Convert } from '@steleaio/radix-engine-toolkit';

const HEX = /^[0-9a-fA-F]+$/;

// ─── Arg parsing ──────────────────────────────────────────────────────────────

function usage(msg) {
  if (msg) console.error(`\n  Error: ${msg}\n`);
  console.error('  Usage:');
  console.error('    node sign.mjs --payload <file>            # JSON blob from the Signetix UI');
  console.error('    node sign.mjs --manifest <file> --header <file> <hash-hex>');
  console.error('    node sign.mjs <hash-hex>                  # legacy blind-sign, prints a warning');
  console.error('');
  console.error('    Set SIGNETIX_PAYLOAD env var to inline the JSON instead of using a file.');
  console.error('    Private key from interactive prompt or NATIVE_PRIVKEY_HEX env var.');
  console.error('');
  process.exit(1);
}

function parseArgs(argv) {
  const out = { payload: null, manifest: null, header: null, positional: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--payload') out.payload = argv[++i] ?? usage('--payload requires a value');
    else if (a === '--manifest') out.manifest = argv[++i] ?? usage('--manifest requires a file path');
    else if (a === '--header') out.header = argv[++i] ?? usage('--header requires a file path');
    else if (a === '-h' || a === '--help') usage();
    else if (a.startsWith('--')) usage(`unknown flag: ${a}`);
    else out.positional.push(a);
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));

// ─── Load the sign payload ────────────────────────────────────────────────────

/**
 * Resolve { hashHex, manifest, header } from CLI args + env. Three valid shapes:
 *   1. --payload <file|-|stdin>    or SIGNETIX_PAYLOAD env var → parses the JSON
 *      response from /sign-payload / /fee-sign-payload / /native-create-sign-payload
 *   2. --manifest + --header + positional hash arg → files + literal hash
 *   3. positional hash arg only → legacy blind-sign mode (no manifest)
 */
function loadPayload() {
  // (1) JSON blob from --payload or env.
  const payloadSource = args.payload ?? (process.env.SIGNETIX_PAYLOAD ? '<env>' : null);
  if (payloadSource) {
    let raw;
    if (args.payload) {
      try { raw = readFileSync(args.payload, 'utf8'); }
      catch (e) { usage(`could not read --payload file: ${e.message}`); }
    } else {
      raw = process.env.SIGNETIX_PAYLOAD;
    }
    let json;
    try { json = JSON.parse(raw); }
    catch (e) { usage(`payload is not valid JSON: ${e.message}`); }

    const hash = (json.intent_hash_hex ?? json.intentHashHex ?? '').toLowerCase();
    const manifest = json.manifest ?? json.fee_manifest ?? json.feeManifest;
    const header = normaliseHeader(json.subintent_header ?? json.subintentHeader ?? json.header);
    if (!hash) usage('payload is missing intent_hash_hex');
    if (!manifest) usage('payload is missing manifest (or fee_manifest)');
    if (!header) usage('payload is missing subintent_header');
    return { hashHex: hash, manifest, header, mode: 'verified' };
  }

  // (2) --manifest + --header + positional hash.
  if (args.manifest || args.header) {
    if (!args.manifest) usage('--manifest is required when --header is provided');
    if (!args.header) usage('--header is required when --manifest is provided');
    if (args.positional.length === 0) usage('hash-hex positional arg is required');
    let manifest, headerRaw;
    try { manifest = readFileSync(args.manifest, 'utf8'); }
    catch (e) { usage(`could not read --manifest file: ${e.message}`); }
    try { headerRaw = JSON.parse(readFileSync(args.header, 'utf8')); }
    catch (e) { usage(`could not read --header file: ${e.message}`); }
    const header = normaliseHeader(headerRaw);
    if (!header) usage('--header file does not contain a valid subintent header');
    return {
      hashHex: args.positional[0].toLowerCase(),
      manifest,
      header,
      mode: 'verified',
    };
  }

  // (3) Legacy blind-sign.
  if (args.positional.length !== 1) usage('expected exactly one hash-hex positional arg');
  return { hashHex: args.positional[0].toLowerCase(), manifest: null, header: null, mode: 'blind' };
}

/**
 * Accept any of the field-name conventions Signetix ships:
 *   wire form (snake_case):  { network_id, start_epoch_inclusive, ... }
 *   client form (camelCase): { networkId, startEpochInclusive, ... }
 * Returns the camelCase shape the V2 toolkit's IntentHeaderV2 expects, with
 * epoch / discriminator fields normalised to BigInt.
 */
function normaliseHeader(h) {
  if (!h || typeof h !== 'object') return null;
  const networkId = h.network_id ?? h.networkId;
  const startEpochInclusive = h.start_epoch_inclusive ?? h.startEpochInclusive;
  const endEpochExclusive = h.end_epoch_exclusive ?? h.endEpochExclusive;
  const intentDiscriminator = h.intent_discriminator ?? h.intentDiscriminator;
  // R8: the wallet always signs `setExpiration('atTime', maxProposerTimestamp)`,
  // so for any wallet-co-signable proposal this is part of the signed subintent.
  // Omitting it here would make the recomputed hash disagree with Signetix's and
  // make this tool wrongly refuse to sign. Absent/null → kept out (single-signer
  // subintents that have no proposer-timestamp).
  const maxProposerTimestamp =
    h.max_proposer_timestamp ?? h.maxProposerTimestampExclusive ?? h.maxProposerTimestamp;
  if (
    typeof networkId !== 'number' ||
    startEpochInclusive === undefined ||
    endEpochExclusive === undefined ||
    intentDiscriminator === undefined
  ) {
    return null;
  }
  return {
    networkId,
    startEpochInclusive: BigInt(startEpochInclusive),
    endEpochExclusive: BigInt(endEpochExclusive),
    intentDiscriminator: BigInt(intentDiscriminator),
    ...(maxProposerTimestamp != null
      ? { maxProposerTimestampExclusive: BigInt(maxProposerTimestamp) }
      : {}),
  };
}

// ─── Resolve inputs + validate hash ───────────────────────────────────────────

const { hashHex, manifest, header, mode } = loadPayload();
if (!HEX.test(hashHex) || hashHex.length !== 64) {
  usage(`hash must be exactly 64 hex chars (32 bytes); got "${hashHex}" (${hashHex.length})`);
}

// ─── Verification — recompute the subintent hash locally ──────────────────────

if (mode === 'verified') {
  process.stderr.write('\nVerifying served hash against locally-recomputed hash …\n');
  let recomputed;
  try {
    const hashResult = await RadixEngineToolkit.SubintentV2.hash({
      intentCore: {
        header,
        instructions: manifest,
        blobs: [],
        message: { kind: 'None' },
        children: [],
      },
    });
    recomputed = Convert.Uint8Array.toHexString(hashResult.hash).toLowerCase();
  } catch (e) {
    console.error('\n  ✗ Local hash computation failed.');
    console.error(`    ${e?.message ?? e}`);
    console.error('\n  The manifest text Signetix served does not compile against the toolkit\'s');
    console.error('  V2 manifest grammar. Refusing to sign — please report this to Signetix support.\n');
    process.exit(2);
  }

  if (recomputed !== hashHex) {
    console.error('\n  ✗ HASH MISMATCH — refusing to sign.\n');
    console.error(`    Hash served by Signetix : ${hashHex}`);
    console.error(`    Hash from local manifest: ${recomputed}\n`);
    console.error('  The manifest text and the partial-transaction hash disagree. Either');
    console.error('  the manifest was altered in transit, or the server is misbehaving.');
    console.error('  Do not paste this signature back.\n');
    process.exit(3);
  }
  process.stderr.write('  ✓ Recomputed hash matches the served hash.\n');

  // Show the manifest so the signer can read what they\'re actually authorising.
  process.stderr.write('\n──── Manifest ────────────────────────────────────────────────────────\n');
  process.stderr.write(manifest.trimEnd() + '\n');
  process.stderr.write('──────────────────────────────────────────────────────────────────────\n');
  process.stderr.write('\nNetwork:    ');
  process.stderr.write(header.networkId === 1 ? 'mainnet' : header.networkId === 2 ? 'stokenet' : `network_id=${header.networkId}`);
  process.stderr.write(`\nEpoch:      [${header.startEpochInclusive}, ${header.endEpochExclusive})`);
  process.stderr.write(`\nNonce:      ${header.intentDiscriminator}\n`);
} else {
  // Legacy blind-sign: warn loudly.
  process.stderr.write('\n  ⚠  BLIND SIGN — no manifest provided.\n');
  process.stderr.write('     You are about to sign a hash without verifying it matches the\n');
  process.stderr.write('     manifest Signetix displayed. A malicious server could have swapped\n');
  process.stderr.write('     the manifest behind the hash. Prefer `--payload payload.json`.\n');
}

// ─── Private key — env var, piped stdin, or interactive prompt ────────────────

async function readPrivkey() {
  if (process.env.NATIVE_PRIVKEY_HEX) return process.env.NATIVE_PRIVKEY_HEX.trim();
  if (!process.stdin.isTTY) {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf8').trim();
  }
  process.stderr.write('\nPrivate key (64 hex chars): ');
  const rl = readline.createInterface({ input: process.stdin });
  const answer = await new Promise((resolve) => rl.once('line', resolve));
  rl.close();
  return answer.trim();
}

const privkeyHex = (await readPrivkey()).toLowerCase();
if (!HEX.test(privkeyHex) || privkeyHex.length !== 64) {
  usage(`private key must be exactly 64 hex chars (32 bytes); got ${privkeyHex.length}`);
}

// ─── Sign with Node stdlib (no extra crypto deps) ─────────────────────────────

// PKCS#8 wrapper for a raw 32-byte Ed25519 seed. The 16-byte prefix encodes
// SEQUENCE → version 0 → AlgorithmIdentifier(Ed25519 OID 1.3.101.112) →
// OCTET STRING → inner OCTET STRING(32 bytes). RFC 8410.
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const pkcs8 = Buffer.concat([PKCS8_PREFIX, Buffer.from(privkeyHex, 'hex')]);

let privKey;
try {
  privKey = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
} catch (err) {
  console.error(`\n  Failed to import private key: ${err.message}\n`);
  process.exit(1);
}

const pubKey = crypto.createPublicKey(privKey);
const pubJwk = pubKey.export({ format: 'jwk' });
const derivedPubkeyHex = Buffer.from(pubJwk.x, 'base64url').toString('hex');

const signature = crypto.sign(null, Buffer.from(hashHex, 'hex'), privKey);

// ─── Output ───────────────────────────────────────────────────────────────────

process.stderr.write(`\nDerived public key: ${derivedPubkeyHex}\n`);
process.stderr.write('Signature (paste this into the Signetix page):\n\n');
process.stdout.write(signature.toString('hex') + '\n');
