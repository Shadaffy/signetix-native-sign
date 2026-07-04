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
 * Requirements: Node 18+ (Windows, macOS, Linux). Hash-only signing (the
 * sign-in flow) has zero dependencies. Verified mode (`--payload`) needs the
 * Radix Engine Toolkit installed via `npm install` — see README for the
 * no-clone install path.
 *
 * Usage — verified transaction signing (recommended):
 *   node sign.mjs --payload payload.json
 *   $env:SIGNETIX_PAYLOAD = '<json>'; node sign.mjs    # Windows
 *   SIGNETIX_PAYLOAD='<json>' node sign.mjs            # macOS / Linux
 *
 *   # Or with manifest + header in separate files plus the hash:
 *   node sign.mjs --manifest m.txt --header h.json <hash-hex>
 *
 * Usage — verified sign-in (login challenge, zero deps):
 *   node sign.mjs --auth --challenge <hex> --address <account> --pubkey <hex> <hash-hex>
 *
 *   Recomputes Blake2b-256("SIGNETIX-NATIVE-V1\0" || challenge ||
 *   vlen(addr) || addr || vlen(pk) || pk) locally and refuses to sign if it
 *   doesn't match the served hash. A login hash is domain-separated, so it
 *   can never double as a transaction hash — signing it proves key ownership
 *   and nothing else.
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

const HEX = /^[0-9a-fA-F]+$/;

// ─── Arg parsing ──────────────────────────────────────────────────────────────

function usage(msg) {
  if (msg) console.error(`\n  Error: ${msg}\n`);
  console.error('  Usage:');
  console.error('    node sign.mjs --payload <file>            # JSON blob from the Signetix UI');
  console.error('    node sign.mjs --manifest <file> --header <file> <hash-hex>');
  console.error('    node sign.mjs --auth --challenge <hex> --address <account> --pubkey <hex> <hash-hex>');
  console.error('                                              # sign-in / login challenge (verified)');
  console.error('    node sign.mjs <hash-hex>                  # legacy blind-sign, prints a warning');
  console.error('');
  console.error('    Set SIGNETIX_PAYLOAD env var to inline the JSON instead of using a file.');
  console.error('    Private key from interactive prompt or NATIVE_PRIVKEY_HEX env var.');
  console.error('');
  process.exit(1);
}

function parseArgs(argv) {
  const out = {
    payload: null, manifest: null, header: null,
    auth: false, challenge: null, address: null, pubkey: null,
    positional: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--payload') out.payload = argv[++i] ?? usage('--payload requires a value');
    else if (a === '--manifest') out.manifest = argv[++i] ?? usage('--manifest requires a file path');
    else if (a === '--header') out.header = argv[++i] ?? usage('--header requires a file path');
    else if (a === '--auth') out.auth = true;
    else if (a === '--challenge') out.challenge = argv[++i] ?? usage('--challenge requires a hex value');
    else if (a === '--address') out.address = argv[++i] ?? usage('--address requires an account address');
    else if (a === '--pubkey') out.pubkey = argv[++i] ?? usage('--pubkey requires a hex value');
    else if (a === '-h' || a === '--help') usage();
    else if (a.startsWith('--')) usage(`unknown flag: ${a}`);
    else out.positional.push(a);
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));

// ─── Load the sign payload ────────────────────────────────────────────────────

/**
 * Resolve { hashHex, manifest, header } from CLI args + env. Four valid shapes:
 *   1. --payload <file|-|stdin>    or SIGNETIX_PAYLOAD env var → parses the JSON
 *      response from /sign-payload / /fee-sign-payload / /native-create-sign-payload
 *   2. --auth --challenge --address --pubkey (+ optional served hash) → login
 *      challenge; the hash is recomputed locally and compared if one is given
 *   3. --manifest + --header + positional hash arg → files + literal hash
 *   4. positional hash arg only → legacy blind-sign mode (no manifest)
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

  // (2) --auth + --challenge + --address + --pubkey (+ optional served hash).
  if (args.auth || args.challenge || args.address || args.pubkey) {
    if (!args.challenge) usage('--challenge is required in auth mode');
    if (!args.address) usage('--address is required in auth mode');
    if (!args.pubkey) usage('--pubkey is required in auth mode');
    if (!HEX.test(args.challenge) || args.challenge.length !== 64) {
      usage('--challenge must be exactly 64 hex chars (32 bytes)');
    }
    if (!HEX.test(args.pubkey) || args.pubkey.length !== 64) {
      usage('--pubkey must be exactly 64 hex chars (32 bytes)');
    }
    const recomputed = buildNativeAuthPayloadHashHex({
      challengeHex: args.challenge.toLowerCase(),
      accountAddress: args.address,
      publicKeyHex: args.pubkey.toLowerCase(),
    });
    const served = args.positional[0]?.toLowerCase() ?? null;
    return {
      hashHex: recomputed,
      servedHashHex: served,
      manifest: null,
      header: null,
      mode: 'auth',
    };
  }

  // (3) --manifest + --header + positional hash.
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

  // (4) Legacy blind-sign.
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

// ─── Blake2b-256 (pure JS) — for recomputing the login-challenge hash ─────────
//
// Node's OpenSSL only exposes blake2b512; the auth payload uses Blake2b-256,
// whose parameter block (digest length) changes the IV, so it cannot be
// derived from blake2b512 output. Inlined here (RFC 7693, unkeyed) to keep
// the sign-in path zero-deps.

const B2B_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];
const B2B_SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];
const U64_MASK = (1n << 64n) - 1n;
const rotr64 = (x, n) => ((x >> n) | (x << (64n - n))) & U64_MASK;

function blake2b(data, outLen) {
  const h = B2B_IV.slice();
  h[0] ^= 0x01010000n ^ BigInt(outLen);
  const block = new Uint8Array(128);
  const view = new DataView(block.buffer);
  const v = new Array(16);
  const m = new Array(16);
  let t = 0n;

  const G = (a, b, c, d, x, y) => {
    v[a] = (v[a] + v[b] + m[x]) & U64_MASK;
    v[d] = rotr64(v[d] ^ v[a], 32n);
    v[c] = (v[c] + v[d]) & U64_MASK;
    v[b] = rotr64(v[b] ^ v[c], 24n);
    v[a] = (v[a] + v[b] + m[y]) & U64_MASK;
    v[d] = rotr64(v[d] ^ v[a], 16n);
    v[c] = (v[c] + v[d]) & U64_MASK;
    v[b] = rotr64(v[b] ^ v[c], 63n);
  };

  const compress = (last) => {
    for (let i = 0; i < 16; i++) m[i] = view.getBigUint64(i * 8, true);
    for (let i = 0; i < 8; i++) { v[i] = h[i]; v[i + 8] = B2B_IV[i]; }
    v[12] ^= t & U64_MASK;
    v[13] ^= t >> 64n;
    if (last) v[14] ^= U64_MASK;
    for (let r = 0; r < 12; r++) {
      const s = B2B_SIGMA[r % 10];
      G(0, 4, 8, 12, s[0], s[1]);
      G(1, 5, 9, 13, s[2], s[3]);
      G(2, 6, 10, 14, s[4], s[5]);
      G(3, 7, 11, 15, s[6], s[7]);
      G(0, 5, 10, 15, s[8], s[9]);
      G(1, 6, 11, 12, s[10], s[11]);
      G(2, 7, 8, 13, s[12], s[13]);
      G(3, 4, 9, 14, s[14], s[15]);
    }
    for (let i = 0; i < 8; i++) h[i] = h[i] ^ v[i] ^ v[i + 8];
  };

  let offset = 0;
  while (data.length - offset > 128) {
    block.set(data.subarray(offset, offset + 128));
    t += 128n;
    compress(false);
    offset += 128;
  }
  block.fill(0);
  block.set(data.subarray(offset));
  t += BigInt(data.length - offset);
  compress(true);

  const out = Buffer.alloc(64);
  for (let i = 0; i < 8; i++) out.writeBigUInt64LE(h[i], i * 8);
  return out.subarray(0, outLen);
}

/**
 * Identical formula to the API's `buildNativeAuthPayload` and the web app's
 * `buildNativeAuthPayloadHash`:
 *   Blake2b-256("SIGNETIX-NATIVE-V1\0" || challenge || vlen(addr) || addr || vlen(pk) || pk)
 * The label domain-separates login signatures from everything else, so a
 * signature over this hash can never authorise a transaction.
 */
function buildNativeAuthPayloadHashHex({ challengeHex, accountAddress, publicKeyHex }) {
  const varint = (n) => {
    const bytes = [];
    while (n >= 0x80) { bytes.push((n & 0x7f) | 0x80); n >>>= 7; }
    bytes.push(n & 0x7f);
    return Buffer.from(bytes);
  };
  const addr = Buffer.from(accountAddress, 'utf8');
  const pubkey = Buffer.from(publicKeyHex, 'hex');
  const message = Buffer.concat([
    Buffer.from('SIGNETIX-NATIVE-V1\0', 'utf8'),
    Buffer.from(challengeHex, 'hex'),
    varint(addr.length), addr,
    varint(pubkey.length), pubkey,
  ]);
  return blake2b(message, 32).toString('hex');
}

// ─── Resolve inputs + validate hash ───────────────────────────────────────────

const { hashHex, servedHashHex, manifest, header, mode } = loadPayload();
if (!HEX.test(hashHex) || hashHex.length !== 64) {
  usage(`hash must be exactly 64 hex chars (32 bytes); got "${hashHex}" (${hashHex.length})`);
}

// ─── Verification — recompute the subintent hash locally ──────────────────────

if (mode === 'verified') {
  // The toolkit is only needed to recompute the hash, so hash-only signing
  // (e.g. the /sign-in/native auth challenge) stays zero-deps.
  let RadixEngineToolkit, Convert;
  try {
    ({ RadixEngineToolkit, Convert } = await import('@steleaio/radix-engine-toolkit'));
  } catch {
    console.error('\n  ✗ The Radix Engine Toolkit is not installed.');
    console.error('    Verified mode recomputes the partial-tx hash locally and needs it.');
    console.error('    In the directory containing sign.mjs, download the package.json from');
    console.error('    https://github.com/Shadaffy/signetix-native-sign and run: npm install\n');
    process.exit(1);
  }

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
} else if (mode === 'auth') {
  process.stderr.write('\nSIGN-IN — recomputing the login-challenge hash locally …\n');
  if (servedHashHex && servedHashHex !== hashHex) {
    console.error('\n  ✗ HASH MISMATCH — refusing to sign.\n');
    console.error(`    Hash shown by Signetix  : ${servedHashHex}`);
    console.error(`    Hash recomputed locally : ${hashHex}\n`);
    console.error('  The challenge/address/pubkey and the hash the page displayed disagree.');
    console.error('  Do not paste this signature back.\n');
    process.exit(3);
  }
  process.stderr.write(
    servedHashHex
      ? '  ✓ Recomputed hash matches the one the page displayed.\n'
      : '  ⓘ No served hash given to compare — signing the locally recomputed hash.\n',
  );
  process.stderr.write('\nYou are signing a Signetix LOGIN CHALLENGE — it proves control of your\n');
  process.stderr.write('key so you can sign in. It is domain-separated ("SIGNETIX-NATIVE-V1"),\n');
  process.stderr.write('so it cannot authorise a transaction or move funds.\n');
  process.stderr.write(`\nAccount:   ${args.address}\n`);
  process.stderr.write(`Challenge: ${args.challenge.toLowerCase()}\n`);
} else {
  // Legacy blind-sign: warn loudly.
  process.stderr.write('\n  ⚠  BLIND SIGN — bare hash, nothing to verify it against.\n');
  process.stderr.write('     You are about to sign a hash without verifying what it commits to.\n');
  process.stderr.write('     A malicious server could hand you a transaction hash disguised as\n');
  process.stderr.write('     something harmless. Prefer `--payload payload.json` for transactions\n');
  process.stderr.write('     or `--auth --challenge … --address … --pubkey …` for sign-in.\n');
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

// In auth mode the pubkey is baked into the signed hash — signing with a
// different key would just fail server-side, so catch the mix-up here.
if (mode === 'auth' && derivedPubkeyHex !== args.pubkey.toLowerCase()) {
  console.error('\n  ✗ KEY MISMATCH — refusing to sign.\n');
  console.error(`    Public key in the challenge : ${args.pubkey.toLowerCase()}`);
  console.error(`    Public key of the entered private key: ${derivedPubkeyHex}\n`);
  console.error('  You entered a private key that does not belong to the public key this');
  console.error('  login challenge was issued for.\n');
  process.exit(1);
}

const signature = crypto.sign(null, Buffer.from(hashHex, 'hex'), privKey);

// ─── Output ───────────────────────────────────────────────────────────────────

process.stderr.write(`\nDerived public key: ${derivedPubkeyHex}\n`);
process.stderr.write('Signature (paste this into the Signetix page):\n\n');
process.stdout.write(signature.toString('hex') + '\n');
