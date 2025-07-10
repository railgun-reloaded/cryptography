// @ts-ignore -- ignore typecheck.
import { buildPoseidon, buildPoseidonOpt } from 'circomlibjs'

const constructors = {
  pure: buildPoseidonOpt, // optimized js implementation
  wasm: buildPoseidon,
}

const poseidonBuild: any = {
  optimized: null,
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
  const p = typeof typeof poseidonBuild.wasm === 'undefined' ? poseidonBuild.pure : poseidonBuild.wasm
  if (typeof p === 'undefined') {
    throw new Error('Poseidon has not been loaded.')
  }
  // poseidon expect input of uint8Array
  return p(inputs)
}

export { poseidonBuild, initCircomlib, poseidon }
