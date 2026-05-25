#!/usr/bin/env node
/**
 * Signetix native-key signer — zero-dependency Ed25519 signing tool.
 *
 * Pairs with the in-browser flow at /sign-in/native: the page shows a
 * 32-byte Blake2b-256 payload hash; this script signs that hash with your
 * raw Ed25519 private key and prints the 64-byte signature in hex for you
 * to paste back.
 *
 * Why a standalone tool: pasting private keys into a webpage is the exact
 * pattern wallets exist to prevent, so Signetix deliberately does not
 * accept your key in the browser. This script runs locally on your
 * machine, talks to nothing, and uses only Node's stdlib crypto module
 * (no `npm install` step).
 *
 * Requirements: Node 18+ (Windows, macOS, Linux). No npm packages.
 *
 * Usage:
 *   node sign.mjs <hash-hex>
 *   (the private key is prompted for so it never lands in shell history)
 *
 *   # Or pipe it in for scripting:
 *   echo $PRIVKEY_HEX | node sign.mjs <hash-hex>
 *
 *   # Or via env var:
 *   NATIVE_PRIVKEY_HEX=<...> node sign.mjs <hash-hex>
 *
 * The tool also prints the derived public key so you can sanity-check
 * that you used the right private key before pasting the signature.
 */
import crypto from 'node:crypto';
import readline from 'node:readline';

const HEX = /^[0-9a-fA-F]+$/;

// ─── Args ─────────────────────────────────────────────────────────────────────

function usage(msg) {
  if (msg) console.error(`\n  Error: ${msg}\n`);
  console.error('  Usage: node sign.mjs <hash-hex>');
  console.error('         (private key from stdin or NATIVE_PRIVKEY_HEX env var)\n');
  process.exit(1);
}

const hashHex = (process.argv[2] ?? '').trim().toLowerCase();
if (!hashHex) usage('missing <hash-hex> argument');
if (!HEX.test(hashHex) || hashHex.length !== 64) {
  usage(`hash must be exactly 64 hex chars (32 bytes); got ${hashHex.length}`);
}

// ─── Private key — env var, piped stdin, or interactive prompt ────────────────

async function readPrivkey() {
  if (process.env.NATIVE_PRIVKEY_HEX) {
    return process.env.NATIVE_PRIVKEY_HEX.trim();
  }
  if (!process.stdin.isTTY) {
    // Piped input
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    return Buffer.concat(chunks).toString('utf8').trim();
  }
  // Interactive prompt — stderr so a redirected stdout stays clean
  process.stderr.write('Private key (64 hex chars): ');
  const rl = readline.createInterface({ input: process.stdin });
  const answer = await new Promise((resolve) => rl.once('line', resolve));
  rl.close();
  return answer.trim();
}

const privkeyHex = (await readPrivkey()).toLowerCase();
if (!HEX.test(privkeyHex) || privkeyHex.length !== 64) {
  usage(`private key must be exactly 64 hex chars (32 bytes); got ${privkeyHex.length}`);
}

// ─── Sign with Node stdlib (no npm packages) ──────────────────────────────────

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
process.stderr.write('Signature (paste this into the Signetix sign-in page):\n\n');
process.stdout.write(signature.toString('hex') + '\n');
