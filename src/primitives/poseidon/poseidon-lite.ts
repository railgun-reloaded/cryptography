import { bigIntToBytes, bytesToBigInt } from '@railgun-reloaded/bytes'
import * as poseidonLib from 'poseidon-lite'

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
 * @throws If `inputs.length` is outside 1..14, if any element is null/undefined,
 *         or if an element has an unsupported type.
 */
const poseidonFunc = (
  inputs: (bigint | number | string | Uint8Array)[],
  returnBigInt = false,
  nOuts: number = 1
): bigint | bigint[] | Uint8Array | Uint8Array[] => {
  if (inputs.length < 1 || inputs.length > 14) {
    throw new Error('Poseidon function index must be between 1 and 14')
  }

  const bigInputs = inputs.map((input, i) => {
    if (input === undefined || input === null) {
      throw new Error(`Input at index ${i} is undefined or null`)
    }
    if (typeof input === 'bigint') return input
    if (typeof input === 'string') return BigInt(input)
    if (typeof input === 'number') return BigInt(input)
    if (input instanceof Uint8Array) return bytesToBigInt(input)
    throw new Error(`Invalid input type: ${typeof input}`)
  })

  const fnName = `poseidon${inputs.length}` as PoseidonFnName
  const output = poseidonLib[fnName](bigInputs, nOuts)

  if (nOuts === 1) {
    if (typeof output !== 'bigint') {
      throw new Error(`Expected output to be a bigint, got ${typeof output}`)
    }
    return returnBigInt ? output : bigIntToBytes(output, 32)
  }

  if (!Array.isArray(output) || output.length !== nOuts) {
    throw new Error(`Expected output to be an array of length ${nOuts}`)
  }
  return returnBigInt
    ? (output as bigint[])
    : output.map((o) => bigIntToBytes(o as bigint, 32))
}

export { poseidonFunc }
