# Decrypt Me — frontend

Local-only browser tool for decrypting common payloads.

Supports: Fernet (token + bytea hex), AES-GCM/CBC/CTR with raw or PBKDF2-derived
keys, CryptoJS / OpenSSL passphrase-based AES, and plain Base64/hex decoding.

Decryption runs entirely in the browser via Web Crypto + crypto-js. Nothing is
sent over the network.

## Scripts

```bash
npm run dev      # local dev server
npm run lint     # ESLint (next/core-web-vitals + next/typescript)
npm run test     # vitest run
npm run build    # production build
```

## Threat model

- All decryption is client-side; no key ever leaves the browser tab.
- The "Remember key on this device" checkbox saves the Fernet key in
  `localStorage`, wrapped with a non-extractable AES-GCM CryptoKey stored in
  IndexedDB. This protects against **passive disk inspection** only — any
  same-origin script (including XSS) can call the same wrapping flow and read
  the key. Leave the checkbox unchecked on shared machines.
- The CryptoJS passphrase mode uses OpenSSL's `EVP_BytesToKey` with MD5; weak
  by modern standards, included for decrypt-only compatibility with legacy
  payloads.
- A baseline CSP is set via `next.config.mjs`. `'unsafe-inline'` is still
  required by Next.js for inline runtime scripts; tighten with a nonce-based
  middleware if you need a stricter policy.

## Layout

- `app/` — Next.js App Router entry.
- `components/decrypt/` — main UI.
- `components/json/` — collapsible JSON tree.
- `lib/decrypt.ts` — algorithm dispatch + Fernet implementation.
- `lib/secure-storage.ts` — IndexedDB-wrapped key persistence.
- `test/` — vitest specs (node for crypto, jsdom for storage).
