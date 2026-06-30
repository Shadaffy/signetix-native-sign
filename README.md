# Signetix native-key signer

> Distribution mirror: <https://github.com/Shadaffy/signetix-native-sign>
> (public). The canonical source lives here in `tools/native-sign/`;
> when this script changes, copy the file across and tag a release on
> the public repo.

A standalone Ed25519 signing tool for Signetix's no-wallet flow. Pairs with
the in-browser panels at `/sign-in/native`, `/proposals/<id>`, and
`/accounts/new` (step 4 — native path). The page exposes a JSON **sign
payload**; this script

1. recomputes the partial-transaction hash locally from the manifest +
   subintent header in the payload,
2. **refuses to sign if the recomputed hash doesn't match** the one
   Signetix served, and
3. only then signs and prints the signature for you to paste back.

That refusal is the point. Without it, a malicious or buggy server could
display one manifest while serving a different hash, and a blind signer
would end up authorising something other than what they thought they
saw. The Radix engine accepts only the signature over the canonical
`(manifest, header)` pair — so if our locally-derived hash matches what
the server served, the manifest the user is signing is provably the one
the engine will check.

**Your private key never leaves your machine.** It is prompted on stdin
so it does not land in shell history, signed in-process with Node's
built-in `crypto` module, and not transmitted anywhere.

## Why a separate tool

Pasting your private key into a webpage is the exact pattern wallets
exist to prevent. Signetix deliberately does not accept your private key
in the browser. This script runs locally, talks to nothing, and you can
read every line of it.

## Requirements

- **Node 18 or newer** ([nodejs.org](https://nodejs.org))
- **One npm install** — for the Radix Engine Toolkit, which the script
  uses to recompute the partial-tx hash. We dropped the previous
  "zero-deps" stance because real verification is worth one
  `npm install` step.

## Install (once)

### Windows (PowerShell)

```powershell
# 1. Download the script and the package manifest
mkdir signetix-sign; cd signetix-sign
Invoke-WebRequest `
  -Uri https://raw.githubusercontent.com/Shadaffy/signetix-native-sign/main/sign.mjs `
  -OutFile sign.mjs
Invoke-WebRequest `
  -Uri https://raw.githubusercontent.com/Shadaffy/signetix-native-sign/main/package.json `
  -OutFile package.json

# 2. Install dependencies (one-time)
npm install
```

### macOS / Linux

```bash
mkdir signetix-sign && cd signetix-sign
curl -O https://raw.githubusercontent.com/Shadaffy/signetix-native-sign/main/sign.mjs
curl -O https://raw.githubusercontent.com/Shadaffy/signetix-native-sign/main/package.json
npm install
```

## Sign (verified — recommended)

Save the sign-payload JSON the page shows you to a file and run:

```bash
node sign.mjs --payload payload.json
```

The script will:

- Recompute the partial-tx hash from `payload.manifest` and
  `payload.subintent_header`.
- Compare it against `payload.intent_hash_hex`.
- Print the manifest and the epoch / nonce / network so you can read
  what you're authorising.
- Prompt for your private key on stdin (it never lands in shell
  history).
- Print the derived public key plus the 64-byte signature.

If the hashes mismatch, the script exits with code `3` and refuses to
sign. **Do not paste a signature obtained any other way back into the
page.**

### Alternative: inline JSON via env var

```powershell
$env:SIGNETIX_PAYLOAD = '<paste the JSON from the page>'
node sign.mjs
Remove-Item Env:SIGNETIX_PAYLOAD
```

```bash
SIGNETIX_PAYLOAD='<paste the JSON from the page>' node sign.mjs
```

### Alternative: manifest + header + hash in separate args

```bash
node sign.mjs --manifest manifest.txt --header header.json <hash-hex>
```

Where `header.json` looks like:

```json
{
  "network_id": 2,
  "start_epoch_inclusive": 12345,
  "end_epoch_exclusive": 12445,
  "intent_discriminator": 1234567890
}
```

## Sign (legacy blind mode — discouraged)

```bash
node sign.mjs <hash-hex>
```

Prints a loud warning and signs the hash without verifying anything.
Kept for backward compatibility and for cases where you have the hash
out-of-band; prefer the `--payload` form for any real flow.

## Other ways to feed the private key

For automation:

```bash
# Pipe it in
echo "$PRIVKEY_HEX" | node sign.mjs --payload payload.json

# Or via env var
NATIVE_PRIVKEY_HEX=<...> node sign.mjs --payload payload.json
```

## Exit codes

| Code | Meaning                                              |
|------|------------------------------------------------------|
| `0`  | Signed successfully                                  |
| `1`  | Argument / input error                               |
| `2`  | Manifest didn't compile against the V2 toolkit       |
| `3`  | Hash mismatch — refused to sign                      |

## Reproducing the test fixture

The Signetix repo ships a public test key under
[`test/fixtures/native-keys.json`](../../test/fixtures/native-keys.json).
Its derived stokenet address is
`account_tdx_2_1297nsd60q7xjq6c5dvkkkafjuspp2gnznendu3an930lkhfg4h64qr`.
The matching private key lives in `apps/api/.env.test`. If you want to
walk the full flow without supplying your own key, paste the fixture
pubkey into `/sign-in/native`, then feed this script the fixture privkey
when it prompts.
