import { bigIntToBytes, bytesToHex, padBytesLeft } from '@railgun-reloaded/bytes'
// @ts-ignore -- circomlibjs ships no upstream type definitions
import { buildPoseidon, buildPoseidonOpt } from 'circomlibjs'

import { CryptographyError } from '../errors'

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
 *
 * Inputs shorter than 32 bytes are left-padded with zeros to match the
 * BabyJubJub field size. Inputs longer than 32 bytes throw `ByteLengthExceeded`
 * — they cannot represent a valid field element.
 * @param inputs - An array of byte arrays, each at most 32 bytes, representing
 * the input data to be hashed.
 * @returns The computed Poseidon hash as a 32-byte Uint8Array.
 * @throws Will throw an error if the Poseidon implementation has not been loaded.
 * @throws {BytesError} `code: 'ByteLengthExceeded'` if any input is longer than 32 bytes.
 */
const poseidon = (inputs: Uint8Array[]): Uint8Array => {
  // Prefer wasm if it has been initialized; otherwise fall back to pure.
  const p = poseidonBuild.wasm ?? poseidonBuild.pure
  if (p === null) {
    throw new CryptographyError('PoseidonNotLoaded', 'Poseidon has not been loaded.')
  }
  // Pad each input to the 32-byte field size before passing to circomlibjs.
  // Strict mode rejects >32-byte inputs since they can't represent a field element.
  const padded = inputs.map((input) => padBytesLeft(input, 32, { strict: true }))
  // poseidon expect input of bigint
  const result = p.F.fromMontgomery(
    p(padded.map((input) => p.F.toMontgomery(new Uint8Array(input).reverse())))
  )
  return result.reverse()
}

/**
 * Compute a Poseidon hash over hex-string inputs. Each input is parsed as a
 * BabyJubJub field element (with or without `0x` prefix, padded internally to
 * 32 bytes). Output is a lowercase 64-character hex string.
 *
 * Mirrors the engine's `poseidonHex` API so consumers porting from engine
 * code paths (e.g. merkle tree node hashing, key-derivation random scalars)
 * can use the same shape.
 * @param inputs - Hex-encoded field elements.
 * @returns Poseidon hash as a 64-character lowercase hex string.
 * @throws CryptographyError(PoseidonNotLoaded) if poseidon has not been loaded.
 */
const poseidonHex = (inputs: string[]): string => {
  const padded = inputs.map((input) => {
    const stripped = input.startsWith('0x') ? input.slice(2) : input
    const value = stripped.length === 0 ? 0n : BigInt('0x' + stripped)
    return bigIntToBytes(value, 32)
  })
  return bytesToHex(poseidon(padded))
}

export { poseidonBuild, initCircomlib, poseidon, poseidonHex }
