// @ts-ignore -- ignore typecheck.
import { buildPoseidon, buildPoseidonOpt } from 'circomlibjs'

import { bigintToUint8Array, uint8ArrayToBigInt } from '../utils'

const constructors = {
  pure: buildPoseidonOpt, // optimized js implementation
  wasm: buildPoseidon,
}

const poseidonBuild: any = {
  pure: null,
  wasm: null,
}

/**
 * Initializes the Poseidon cryptographic hash function from the circomlib library
 * using the specified implementation type.
 * @param type - The type of implementation to use for Poseidon.
 *               Options are:
 *               - `'pure'`: Uses the optimized implementation.
 *               - `'wasm'`: Uses the WebAssembly implementation.
 * @returns A promise that resolves once the Poseidon implementation is initialized.
 */
const initCircomlib = async (type: 'pure' | 'wasm') => {
  const poseidonPromise = constructors[type]()
  poseidonBuild[type] = await poseidonPromise
}

/**
 * Computes the Poseidon hash for the given inputs using the appropriate implementation
 * (either WebAssembly or pure JavaScript) based on availability.
 * @param inputs - An array of Uint8Array objects representing the input data to be hashed.
 * @returns The computed Poseidon hash as a Uint8Array.
 * @throws Will throw an error if the Poseidon implementation has not been loaded.
 */
const poseidon = (inputs: Uint8Array[]) => {
  // prefer wasm, (dev) must be manually initialized as such.
  const p = typeof typeof poseidonBuild.wasm === 'undefined' ? poseidonBuild.pure : poseidonBuild.wasm
  if (typeof p === 'undefined') {
    throw new Error('Poseidon has not been loaded.')
  }
  // poseidon expect input of bigint
  const result = p.F.fromMontgomery(
    p(inputs.map((input) => p.F.toMontgomery(new Uint8Array(input).reverse())))
  )
  return result.reverse()
}

/**
 * Computes a Poseidon hash for the given array of hexadecimal string inputs.
 * This function takes an array of hexadecimal strings, converts them to BigInt,
 * computes the Poseidon hash using the `poseidon` function, and then converts
 * the resulting hash from a Uint8Array to a BigInt.
 * @param inputs - An array of hexadecimal strings to be hashed.
 * @returns The Poseidon hash as a BigInt.
 */
const poseidonHex = (inputs: string[]) => {
  // TODO: sanitize inputs 32 bytes
  const result = poseidon(inputs.map(BigInt).map(bigintToUint8Array))
  return uint8ArrayToBigInt(result)
}

export { poseidonBuild, initCircomlib, poseidon, poseidonHex }
