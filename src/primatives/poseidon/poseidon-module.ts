import { initCircomlib, poseidonBuild } from './poseidon-circomlibjs'

/**
 * Initializes the Poseidon cryptographic module.
 *
 * This function attempts to initialize the Poseidon module using the WebAssembly (WASM) implementation
 * if available. If the WASM implementation is not available or an error occurs during initialization,
 * it falls back to the JavaScript implementation, which does not require initialization.
 * @returns A promise that resolves when the initialization is complete.
 * @throws An `Error` if a non-error value is thrown during initialization.
 */
const initPoseidon = async (): Promise<void> => {
  try {
    // Try WASM implementation.
    await initCircomlib('wasm')
    if (typeof poseidonBuild.wasm === 'function') {
      return Promise.resolve()
    }
  } catch (cause) {
    // TODO: redesign poseidon-hash-wasm?
    if (!(cause instanceof Error)) {
      throw new Error('Non-error thrown from initPoseidon', { cause })
    }
    // Fallback to Javascript.
    await initCircomlib('pure')
    return Promise.resolve()
  }
}

export { initPoseidon }
