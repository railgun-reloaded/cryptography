import { randomBytes } from '@noble/hashes/utils'

import { poseidon } from '../poseidon/poseidon-circomlibjs'
import { bigintToUint8Array, bytesToHex } from '../utils'

import { eddsaBuild } from './eddsa'

const eddsa = {
  /**
   * Convert eddsa-babyjubjub private key to public key
   * @param privateKey - babyjubjub private key
   * @returns public key
   */
  async privateKeyToPublicKey (
    privateKey: Uint8Array
  ): Promise<[Uint8Array, Uint8Array]> {
    // Derive key
    const key = eddsaBuild.ed
      .prv2pub(privateKey)
      .map((element: any) =>
        eddsaBuild.ed.F.fromMontgomery(element).reverse()
      ) as [Uint8Array, Uint8Array]

    return key
  },

  /**
   * Generates a random babyJubJub point
   * @returns random point
   */
  genRandomPoint (): Promise<Uint8Array> {
    return poseidon([BigInt('0x' + bytesToHex(randomBytes(32)))])
  },

  /**
   * Creates eddsa-babyjubjub signature with poseidon hash
   * @param key - private key
   * @param message - message to sign
   * @returns signature
   */
  async signPoseidon (
    key: Uint8Array,
    message: Uint8Array
  ): Promise<[Uint8Array, Uint8Array, Uint8Array]> {
    if (typeof eddsaBuild === 'undefined') {
      throw new Error('Invalid')
    }
    // Get montgomery representation
    const montgomery = eddsaBuild.F.toMontgomery(
      new Uint8Array(message).reverse()
    )

    // Sign
    const sig = eddsaBuild.signPoseidon(key, montgomery)

    // Convert R8 elements from montgomery and to BE
    const r8 = sig.R8.map((element: any) =>
      eddsaBuild.F.fromMontgomery(element).reverse()
    )

    return [r8[0], r8[1], bigintToUint8Array(sig.S, 32)]
  },
}
export { eddsa }
