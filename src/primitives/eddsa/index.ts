import { bigIntToBytes } from '@railgun-reloaded/bytes'

import { assertEddsaReady } from './eddsa'

type CircomlibSignature = {
  R8: [Uint8Array, Uint8Array];
  S: bigint;
}

const eddsa = {
  /**
   * Convert a babyJubJub private key to its public key.
   * @param privateKey - 32-byte private key.
   * @returns The public key as a tuple of two 32-byte coordinates.
   * @throws CryptographyError(EddsaNotInitialized) if `initializeEddsa` has
   *         not been awaited.
   */
  privateKeyToPublicKey (privateKey: Uint8Array): [Uint8Array, Uint8Array] {
    const build = assertEddsaReady()
    const [x, y] = build.prv2pub(privateKey)

    return [
      build.F.fromMontgomery(x).reverse(),
      build.F.fromMontgomery(y).reverse(),
    ]
  },

  /**
   * Sign a message under the babyJubJub EDDSA scheme using Poseidon as the
   * hash function.
   * @param key - 32-byte private key.
   * @param message - Message bytes to sign.
   * @returns Signature as a 3-tuple `[R8x, R8y, S]`, each 32 bytes.
   * @throws CryptographyError(EddsaNotInitialized) if `initializeEddsa` has
   *         not been awaited.
   */
  signPoseidon (
    key: Uint8Array,
    message: Uint8Array
  ): [Uint8Array, Uint8Array, Uint8Array] {
    const build = assertEddsaReady()
    const montgomery = build.F.toMontgomery(new Uint8Array(message).reverse())
    const sig = build.signPoseidon(key, montgomery)
    const r8: [Uint8Array, Uint8Array] = [
      build.F.fromMontgomery(sig.R8[0]).reverse(),
      build.F.fromMontgomery(sig.R8[1]).reverse(),
    ]

    return [
      r8[0],
      r8[1],
      bigIntToBytes(sig.S, 32)
    ]
  },

  /**
   * Verify a babyJubJub EDDSA signature created with Poseidon.
   * @param message - Original message bytes.
   * @param signature - Signature decoded into `{ R8, S }` shape.
   * @param pubkey - Public key tuple matching the signing key.
   * @returns True when the signature verifies.
   * @throws CryptographyError(EddsaNotInitialized) if `initializeEddsa` has
   *         not been awaited.
   */
  verifyEDDSA (
    message: Uint8Array,
    signature: CircomlibSignature,
    pubkey: [Uint8Array, Uint8Array]
  ): boolean {
    const build = assertEddsaReady()
    const montgomery = build.F.toMontgomery(new Uint8Array(message).reverse())
    const r8: [Uint8Array, Uint8Array] = [
      build.F.toMontgomery(new Uint8Array(signature.R8[0]).reverse()),
      build.F.toMontgomery(new Uint8Array(signature.R8[1]).reverse()),
    ]
    const newPubKey: [Uint8Array, Uint8Array] = [
      build.F.toMontgomery(new Uint8Array(pubkey[0]).reverse()),
      build.F.toMontgomery(new Uint8Array(pubkey[1]).reverse()),
    ]

    return build.verifyPoseidon(montgomery, { R8: r8, S: signature.S }, newPubKey)
  },
}

export type { CircomlibSignature }
export { eddsa }
