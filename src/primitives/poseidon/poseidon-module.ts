import { CryptographyError } from '../errors'

import { initCircomlib, poseidonBuild } from './poseidon-circomlibjs'

/**
 * One-shot initialization for the Poseidon module. Tries the WASM build first
 * for speed; on any failure (or if WASM is loaded but unset), falls back to
 * the pure-JS build.
 *
 * Lower-level callers that want explicit control of which build is loaded
 * can call `initCircomlib('wasm' | 'pure')` directly.
 * @returns Resolves once at least one Poseidon implementation is loaded.
 * @throws CryptographyError(PoseidonNotLoaded) if both WASM and pure-JS
 *         initialization fail, with the underlying error attached as `cause`.
 */
const initPoseidon = async (): Promise<void> => {
  try {
    await initCircomlib('wasm')
    if (poseidonBuild.wasm !== null) return
  } catch {
    // Fall through to pure-JS; the failure surfaces below if pure also fails.
  }

  try {
    await initCircomlib('pure')
  } catch (cause) {
    throw new CryptographyError(
      'PoseidonNotLoaded',
      'Both WASM and pure-JS Poseidon initialization failed.',
      { cause }
    )
  }
}

export { initPoseidon }
