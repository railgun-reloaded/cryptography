# @railgun-reloaded/cryptography

Cryptographic primitives shared across the RAILGUN reloaded packages.

This package wraps the underlying JS libraries (`@noble/ciphers`, `@noble/hashes`,
`poseidon-lite`, `@iden3/js-crypto`) and exposes a small, validated surface for
use by `wallet-node`, `merkletree-manager`, and other consumers in the RAILGUN SDK.

## Installation

```bash
npm install @railgun-reloaded/cryptography
```

## What's included

| Primitive | Symbols | Notes |
|---|---|---|
| Poseidon (BabyJubJub field) | `poseidon`, `poseidonHex` | Note hashes and key derivation. `poseidon` takes `Uint8Array` field elements (≤32 bytes each) and returns a 32-byte digest; `poseidonHex` takes/returns hex strings. |
| Poseidon (n-input variants) | `poseidonFunc` | Convenience wrapper for `poseidon1..poseidon14`. Accepts bigint, number, string, or Uint8Array inputs; returns `Uint8Array` (or bigint when requested). |
| EDDSA over BabyJubJub | `eddsa`, `BABYJUBJUB_SUBGROUP_ORDER`, `EddsaSignature` | Derive, sign, and verify with Poseidon hashing. |
| AES-256-GCM / AES-256-CTR | `AES`, `Ciphertext`, `CiphertextCTR` | Authenticated and streaming symmetric encryption. |
| SHA-256 | `sha256` | Thin wrapper over `@noble/hashes/sha2`. |
| Keccak-256 | `keccak256` | Thin wrapper over `@noble/hashes/sha3`. |

Errors thrown by this package are instances of `CryptographyError`, discriminated
by a `code` (`CryptographyErrorCode`).

What's **not** here: BIP32/BIP39 mnemonic derivation, SLIP-10 paths, secp256k1
signing — those live in `@railgun-reloaded/wallet-node` since they are
wallet-shaped concerns rather than primitives.

## Usage

Every primitive is synchronous and requires no initialization.

```ts
import { AES, eddsa, keccak256, poseidon, poseidonFunc, poseidonHex, sha256 } from '@railgun-reloaded/cryptography'

// Poseidon over field elements (Uint8Array, ≤32 bytes each)
const noteHash = poseidon([npk, tokenHash, valueBytes])
const hex = poseidonHex(['0x1', '0x2'])

// poseidon-lite convenience wrapper (accepts mixed input types)
const h = poseidonFunc([1n, 2n, 3n])               // Uint8Array
const hAsBigInt = poseidonFunc([1n, 2n, 3n], true) // bigint

// EDDSA roundtrip
const pubKey = eddsa.privateKeyToPublicKey(privateKey)
const [r8x, r8y, s] = eddsa.signPoseidon(privateKey, message)
const ok = eddsa.verifyEDDSA(message, { R8: [r8x, r8y], S: bytesToBigInt(s) }, pubKey)

// AES-256-GCM (authenticated)
const ct = AES.encryptGCM([plaintext], key)
const [recovered] = AES.decryptGCM(ct, key)

// Hashes
const sha = sha256(input)
const digest = keccak256(input)
```

## Scripts

```bash
npm run build     # tsc --build
npm run lint      # eslint
npm run lint:fix  # eslint --fix
npm test          # build + node:test suite
```

## License

MIT
