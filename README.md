# signetix-native-sign

A tiny, **zero-dependency** Ed25519 signing tool for the Signetix native-key
sign-in flow. Pairs with [stokenet.signetix.app/sign-in/native](https://stokenet.signetix.app/sign-in/native)
— the page shows you a 32-byte hash to sign; this script signs it locally
with your raw Ed25519 private key and prints the 64-byte signature for you
to paste back.

**It uses only Node's stdlib `crypto` module.** No `npm install`. Your
private key never leaves your machine.

## Why a separate tool

Pasting a private key into a webpage is the exact pattern wallets exist to
prevent. Signetix deliberately does not accept your key in the browser.
This script runs locally on your machine, talks to nothing, and you can
read every line of it.

## Requirements

- **Node 18 or newer** ([nodejs.org](https://nodejs.org)). That's it.

## Quickstart

### Windows (PowerShell)

```powershell
# 1. Download the script (once)
Invoke-WebRequest `
  -Uri https://raw.githubusercontent.com/Shadaffy/signetix-native-sign/main/sign.mjs `
  -OutFile sign.mjs

# 2. Run it (paste the hash from /sign-in/native, then your private key when prompted)
node sign.mjs <hash-hex-from-browser>
```

### macOS / Linux

```bash
# 1. Download the script (once)
curl -O https://raw.githubusercontent.com/Shadaffy/signetix-native-sign/main/sign.mjs

# 2. Run it
node sign.mjs <hash-hex-from-browser>
```

On both platforms the script prompts for your private key on stdin so it
never lands in your shell history. It prints:

- The **derived public key** — confirm this matches the one you pasted into
  the browser before continuing.
- The **64-byte signature in hex** — paste this back into the Signetix page.

## Other ways to feed the private key

For automation / scripting:

```bash
# Pipe it in
echo "$PRIVKEY_HEX" | node sign.mjs <hash>

# Or via env var
NATIVE_PRIVKEY_HEX=<...> node sign.mjs <hash>
```

```powershell
# PowerShell env var
$env:NATIVE_PRIVKEY_HEX = "<64-hex-bytes>"
node sign.mjs <hash>
Remove-Item Env:NATIVE_PRIVKEY_HEX
```

## What it does, in 30 lines

1. Wraps your 32-byte raw secret key in the standard PKCS#8 envelope for
   Ed25519 (RFC 8410).
2. Calls Node's `crypto.sign(null, hash, privKey)` — which uses OpenSSL's
   Ed25519 under the hood.
3. Derives the public key from the private key and shows it so you can
   verify you used the right one.
4. Prints the signature hex to stdout. Diagnostic messages go to stderr so
   you can pipe the signature into something else if you want.

That's the whole program — read [`sign.mjs`](./sign.mjs) yourself; it's
deliberately small.

## License

MIT — see [LICENSE](./LICENSE).
