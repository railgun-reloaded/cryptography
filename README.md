# @railgun-reloaded/cryptography

Cryptographic primitives shared across the RAILGUN reloaded packages.

This package wraps the underlying WASM/JS libraries (`circomlibjs`,
`poseidon-lite`, `@noble/hashes`) and exposes a small, validated surface for
use by `wallet-node`, `merkletree-manager`, and other consumers in the RAILGUN SDK.

## Installation

```bash
npm install @railgun-reloaded/cryptography
```

## What's included

| Primitive | Symbols | Notes |
|---|---|---|
| Poseidon (circomlibjs, BabyJubJub field) | `poseidon`, `poseidonBuild`, `initCircomlib` | Used for note hashes and key derivation. Inputs are 32-byte field elements. |
| Poseidon (poseidon-lite, n-input variants) | `poseidonFunc` | Convenience wrapper for `poseidon1..poseidon14`. Sync. Accepts bigint, number, string, or Uint8Array inputs. |
| EDDSA over BabyJubJub | `eddsa`, `initializeEddsa` | Sign and verify with Poseidon hashing. |
| AES-256-GCM / AES-256-CTR | `AES`, `Ciphertext`, `CiphertextCTR` | Authenticated and streaming symmetric encryption. |
| Keccak-256 | `keccak256` | Thin wrapper over `@noble/hashes/sha3`. |

What's **not** here: BIP32/BIP39 mnemonic derivation, SLIP-10 paths, secp256k1
signing — those live in `@railgun-reloaded/wallet-node` since they are
wallet-shaped concerns rather than primitives.

## Initialization

Poseidon and EDDSA wrap WASM modules and must be initialized before use:

```ts
import { initCircomlib, initializeEddsa } from '@railgun-reloaded/cryptography'

await initCircomlib('wasm')   // populates the wasm-backed poseidon
await initCircomlib('pure')   // optional fallback in pure JS
await initializeEddsa()       // ready to sign/verify
```

`poseidon` prefers `wasm` and falls back to `pure` automatically; calling it
without any `initCircomlib` call throws.

`poseidonFunc`, `keccak256`, and `AES` are synchronous and require no
initialization.

## Usage

```ts
import { AES, eddsa, keccak256, poseidon, poseidonFunc } from '@railgun-reloaded/cryptography'

// Poseidon over field elements (Uint8Array, ≤32 bytes each)
const noteHash = poseidon([npk, tokenHash, valueBytes])

// poseidon-lite convenience wrapper (sync, accepts mixed input types)
const h = poseidonFunc([1n, 2n, 3n])              // Uint8Array
const hAsBigInt = poseidonFunc([1n, 2n, 3n], true) // bigint

// EDDSA roundtrip (after initializeEddsa())
const pubKey = eddsa.privateKeyToPublicKey(privateKey)
const [r8x, r8y, s] = eddsa.signPoseidon(privateKey, message)

// AES-256-GCM (authenticated)
const ct = AES.encryptGCM([plaintext], key)
const [recovered] = AES.decryptGCM(ct, key)

// Keccak-256
const digest = keccak256(input)
```

## Scripts

```bash
npm run build     # tsc --build
npm run lint      # eslint
npm run lint:fix  # eslint --fix
npm test          # build + brittle test suite
```

## License

MIT
