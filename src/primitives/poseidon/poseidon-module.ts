import { initCircomlib, poseidonBuild } from './poseidon-circomlibjs'

/**
 * One-shot initialization for the Poseidon module. Tries the WASM build first
 * for speed; on any failure (or if WASM is loaded but unset), falls back to
 * the pure-JS build.
 *
 * Mirrors the engine's `initPoseidonPromise` startup pattern so consumers
 * porting from engine code paths can `await initPoseidon()` once and have a
 * usable Poseidon afterwards. Lower-level callers that want explicit control
 * of which build is loaded can still call `initCircomlib('wasm' | 'pure')`
 * directly.
 * @returns Resolves once at least one Poseidon implementation is loaded.
 * @throws If both WASM and pure-JS init fail, or if a non-Error is thrown.
 */
const initPoseidon = async (): Promise<void> => {
  try {
    await initCircomlib('wasm')
    if (poseidonBuild.wasm !== null) return
  } catch (cause) {
    if (!(cause instanceof Error)) {
      throw new Error('Non-error thrown from initPoseidon', { cause })
    }
  }
  await initCircomlib('pure')
}

export { initPoseidon }
