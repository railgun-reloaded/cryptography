import { bigIntToBytes, bytesToBigInt, bytesToHex, padBytesLeft } from '@railgun-reloaded/bytes'
import * as poseidonLib from 'poseidon-lite'

import { CryptographyError } from '../errors.js'

type PoseidonFnName = Extract<keyof typeof poseidonLib, `poseidon${number}`>

/**
 * Compute a Poseidon hash for 1 to 14 inputs.
 *
 * Each input may be a bigint, number, string (parsed as BigInt), or Uint8Array
 * (interpreted big-endian via `bytesToBigInt`). When `nOuts > 1`, returns an
 * array of values.
 *
 * Does not mutate the input array.
 * @param inputs - Between 1 and 14 values to hash.
 * @param returnBigInt - Return bigint values when true, Uint8Array otherwise.
 * @param nOuts - Number of outputs to produce. Defaults to 1.
 * @returns The hash output in the chosen representation.
 * @throws CryptographyError(InvalidInputCount) if `inputs.length` is outside 1..14.
 * @throws CryptographyError(NullInput) if any element is null/undefined.
 * @throws CryptographyError(InvalidInputType) for unsupported element types.
 * @throws CryptographyError(InvalidOutputType) if poseidon-lite returns an
 *         unexpected output shape.
 */
const poseidonFunc = (
  inputs: (bigint | number | string | Uint8Array)[],
  returnBigInt = false,
  nOuts: number = 1
): bigint | bigint[] | Uint8Array | Uint8Array[] => {
  if (inputs.length < 1 || inputs.length > 14) {
    throw new CryptographyError(
      'InvalidInputCount',
      'Poseidon function index must be between 1 and 14'
    )
  }

  const bigInputs = inputs.map((input, i) => {
    if (input === undefined || input === null) {
      throw new CryptographyError('NullInput', `Input at index ${i} is undefined or null`)
    }
    if (typeof input === 'bigint') return input
    if (typeof input === 'string') return BigInt(input)
    if (typeof input === 'number') return BigInt(input)
    if (input instanceof Uint8Array) return bytesToBigInt(input)
    throw new CryptographyError('InvalidInputType', `Invalid input type: ${typeof input}`)
  })

  const fnName = `poseidon${inputs.length}` as PoseidonFnName
  const output = poseidonLib[fnName](bigInputs, nOuts)

  if (nOuts === 1) {
    if (typeof output !== 'bigint') {
      throw new CryptographyError(
        'InvalidOutputType',
        `Expected output to be a bigint, got ${typeof output}`
      )
    }

    return returnBigInt ? output : bigIntToBytes(output, 32)
  }

  if (!Array.isArray(output) || output.length !== nOuts) {
    throw new CryptographyError(
      'InvalidOutputType',
      `Expected output to be an array of length ${nOuts}`
    )
  }

  return returnBigInt
    ? (output as bigint[])
    : output.map((o) => bigIntToBytes(o as bigint, 32))
}

/**
 * Compute a Poseidon hash over byte-array inputs.
 *
 * Each input is interpreted as a big-endian BabyJubJub field element and
 * left-padded to the 32-byte field size; inputs longer than 32 bytes are
 * rejected. Returns the 32-byte big-endian digest.
 * @param inputs - Field-element byte arrays, each at most 32 bytes.
 * @returns The Poseidon digest as a 32-byte Uint8Array.
 * @throws CryptographyError(InvalidInputCount) if `inputs.length` is outside 1..14.
 * @throws {BytesError} `code: 'ByteLengthExceeded'` if any input exceeds 32 bytes.
 */
const poseidon = (inputs: Uint8Array[]): Uint8Array => {
  const padded = inputs.map((input) => padBytesLeft(input, 32, { strict: true }))

  return poseidonFunc(padded.map((input) => bytesToBigInt(input))) as Uint8Array
}

/**
 * Compute a Poseidon hash over hex-string inputs. Each input is parsed as a
 * BabyJubJub field element (with or without `0x` prefix) and padded to 32
 * bytes. Output is a lowercase 64-character hex string.
 * @param inputs - Hex-encoded field elements.
 * @returns Poseidon digest as a 64-character lowercase hex string.
 * @throws CryptographyError(InvalidInputCount) if `inputs.length` is outside 1..14.
 */
const poseidonHex = (inputs: string[]): string => {
  const padded = inputs.map((input) => {
    const stripped = input.startsWith('0x') ? input.slice(2) : input
    const value = stripped.length === 0 ? 0n : BigInt('0x' + stripped)
    return bigIntToBytes(value, 32)
  })

  return bytesToHex(poseidon(padded))
}

export { poseidonFunc, poseidon, poseidonHex }
