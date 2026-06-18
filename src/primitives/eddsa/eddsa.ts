// @ts-ignore -- circomlibjs ships no upstream type definitions
import { buildEddsa } from 'circomlibjs'

import { CryptographyError } from '../errors.js'

/**
 * Minimal type for the circomlibjs EDDSA build object covering the surface
 * that this package consumes.
 */
type EddsaBuild = {
  F: {
    toMontgomery: (value: Uint8Array) => Uint8Array
    fromMontgomery: (value: Uint8Array) => Uint8Array
  }
  prv2pub: (privateKey: Uint8Array) => [Uint8Array, Uint8Array]
  signPoseidon: (
    key: Uint8Array,
    message: Uint8Array
  ) => { R8: [Uint8Array, Uint8Array]; S: bigint }
  verifyPoseidon: (
    message: Uint8Array,
    signature: { R8: [Uint8Array, Uint8Array]; S: bigint },
    pubkey: [Uint8Array, Uint8Array]
  ) => boolean
}

let eddsaBuild: EddsaBuild | undefined

/**
 * Initialize the circomlibjs EDDSA build. Must be awaited before any
 * `eddsa.*` operation.
 *
 * circomlibjs builds its own internal poseidon instance. Sharing the
 * existing `poseidonBuild` is not supported here because circomlibjs's
 * upstream `buildEddsa` does not accept a poseidon argument.
 * @returns Resolves once the EDDSA build is ready.
 */
const initializeEddsa = async (): Promise<void> => {
  eddsaBuild = (await buildEddsa()) as EddsaBuild
}

/**
 * Throw `CryptographyError(EddsaNotInitialized)` if `initializeEddsa` has not
 * been awaited; otherwise return the initialized EDDSA build.
 * @returns The initialized EDDSA build.
 */
const assertEddsaReady = (): EddsaBuild => {
  if (eddsaBuild === undefined) {
    throw new CryptographyError(
      'EddsaNotInitialized',
      'EDDSA not initialized. Await initializeEddsa() first.'
    )
  }
  return eddsaBuild
}

export type { EddsaBuild }
export { initializeEddsa, assertEddsaReady }
