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
export { poseidonBuild, initCircomlib }
