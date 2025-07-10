// @ts-ignore -- ignore typecheck.
import { buildEddsa } from 'circomlibjs'

import { poseidonBuild } from '../poseidon/poseidon-circomlibjs'

let eddsaBuild: any
/**
 * Initializes the EdDSA cryptographic primitive by asynchronously building its instance.
 * This function waits for the EdDSA instance to be constructed and assigns it to `eddsaBuild.ed`.
 * @async
 * @param injectPoseidon - An optional parameter to inject a custom Poseidon implementation.
 *                         If not provided, the default implementation will be used.
 * @throws {Error} If the EdDSA instance fails to build.
 */
const initializeEddsa = async (injectPoseidon?: any) => {
  const eddsaPromise = buildEddsa(injectPoseidon)
  eddsaBuild = await eddsaPromise
}

/**
 * Asynchronously initializes the EdDSA cryptographic primitives by determining
 * the appropriate Poseidon library to use based on the build configuration.
 * This function checks whether the Poseidon library has a WebAssembly (wasm) build
 * available. If it does, it uses the WebAssembly version; otherwise, it defaults
 * to the pure JavaScript implementation. The selected library is then passed to
 * the `initializeEddsa` function for initialization.
 * @async
 * @returns Resolves when the EdDSA initialization is complete.
 */
const autoInitialize = async () => {
  // check which poseidon was built.
  const poseidonLib = typeof poseidonBuild.wasm !== 'undefined' ? poseidonBuild.pure : poseidonBuild.wasm
  await initializeEddsa(poseidonLib)
}

export { initializeEddsa, autoInitialize, eddsaBuild }
