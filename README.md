# @railgun-reloaded/cryptography

Cryptographic primitives shared across the RAILGUN reloaded packages.

This package builds on the [noble](https://paulmillr.com/noble/) libraries
(`@noble/ciphers`, `@noble/curves`, `@noble/hashes`) and exposes a small,
validated surface for use by `wallet-node`, `merkletree-manager`, and other
consumers in the RAILGUN SDK.

Every runtime dependency is MIT-licensed, ESM, and browser-compatible: there are
no Node built-ins, no `Buffer`, and no WASM in the dependency graph.

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

// n-input convenience wrapper (accepts mixed input types)
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

## Implementation notes

Two decisions are worth knowing about before changing anything in `src/primitives`.

**Poseidon constants are derived, not vendored.** circomlib generated its round
constants and MDS matrices with the reference Grain LFSR script; noble's
`grainGenConstants` reproduces that output exactly at `skipMDS = 0`. Deriving
them keeps ~850 KB of opaque tables out of the bundle and puts both the
permutation and the generator inside the audited surface of
`@noble/curves/abstract/poseidon.js`. The tradeoff is that a change to the
upstream generator would silently alter every hash, so each arity is checked
against a pinned digest the first time it is built and throws
`PoseidonConstantMismatch` on any mismatch. `test/poseidon.test.ts` pins all 14
arities independently.

**The EdDSA scheme is implemented here, deliberately.** `@noble/curves` exports
a `babyjubjub` object with `sign`/`getPublicKey`, but those are a *generic*
EdDSA wrapper — upstream documents that it "is not the BabyJubJub stack used by
iden3/circomlib" and is "not meant as an interoperability target" for it. Using
it would produce keys incompatible with the RAILGUN circuits. Only the curve
arithmetic and `blake512` are reused; the circomlib scheme itself lives in
`src/primitives/eddsa/eddsa.ts` and is pinned by the circomlibjs reference
vectors in `test/eddsa.test.ts`. Secret scalars use noble's constant-time
`multiply`; only public verification values use `multiplyUnsafe`.

## Scripts

```bash
npm run build          # tsc --build
npm run lint           # eslint
npm run lint:fix       # eslint --fix
npm test               # build + node:test suite
npm run check:browser  # verify the bundle has no Node-only dependencies
npm run check:package  # publint: verify package/exports metadata
```

## License

MIT
