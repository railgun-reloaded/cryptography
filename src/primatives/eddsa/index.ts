import { randomBytes } from '@noble/hashes/utils'

import { poseidon } from '../poseidon/poseidon-circomlibjs'
import { bigintToUint8Array, bytesToHex } from '../utils'

import { eddsaBuild } from './eddsa'

interface CircomlibSignature {
  R8: [Uint8Array, Uint8Array];
  S: bigint;
}

const eddsa = {
  /**
   * Convert eddsa-babyjubjub private key to public key
   * @param privateKey - babyjubjub private key
   * @returns public key
   */
  privateKeyToPublicKey(
    privateKey: Uint8Array
  ): [Uint8Array, Uint8Array] {
    // Derive key
    const key = eddsaBuild
      .prv2pub(privateKey)
    // .map((element: any) =>
    //   eddsaBuild.F.fromMontgomery(element).reverse()
    // ) as [Uint8Array, Uint8Array]

    return key
  },

  /**
   * Generates a random babyJubJub point
   * @returns random point
   */
  genRandomPoint(): Uint8Array {
    return poseidon([BigInt('0x' + bytesToHex(randomBytes(32)))])
  },

  /**
   * Creates eddsa-babyjubjub signature with poseidon hash
   * @param key - private key
   * @param message - message to sign
   * @returns signature
   */
  signPoseidon(
    key: Uint8Array,
    message: Uint8Array
  ): [Uint8Array, Uint8Array, Uint8Array] {
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
    const r8 = sig.R8
    // .map((element: any) =>
    //   eddsaBuild.F.fromMontgomery(element).reverse()
    // )

    return [r8[0], r8[1], bigintToUint8Array(sig.S, 32)]
  },

  /**
   * Verifies an EDDSA signature using the Poseidon hash function.
   * @param message - The message to be verified as a Uint8Array.
   * @param signature - The EDDSA signature to verify, represented as a CircomlibSignature object.
   * @param pubkey - The public key used for verification, represented as a tuple of two Uint8Array elements.
   * @returns A boolean indicating whether the signature is valid.
   * @throws An error if the `eddsaBuild` module is not defined.
   */
  verifyEDDSA(message: Uint8Array, signature: CircomlibSignature, pubkey: [Uint8Array, Uint8Array]) {
    if (typeof eddsaBuild === 'undefined') {
      throw new Error('Invalid')
    }
    // Get montgomery representation
    const montgomery = eddsaBuild.F.toMontgomery(
      new Uint8Array(message).reverse()
    )
    const newSig: {
      R8: Uint8Array[],
      S: bigint
    } = {
      R8: [],
      S: signature.S
    }
    newSig.R8 = signature.R8.map((element) => {
      return eddsaBuild.F.fromMontgomery(element).reverse()
    })

    // console.log(eddsaBuild)
    return eddsaBuild.verifyPoseidon(montgomery, signature, pubkey)
  }
}
export { eddsa }
