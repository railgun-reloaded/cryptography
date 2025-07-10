import { bigintToUint8Array, poseidonLib, uint8ArrayToBigInt } from '../index'

type PoseidonFunc = (input: (bigint | number | string)[], nOuts?: number) => bigint
const poseidonFuncs: PoseidonFunc[] = []

type PoseidonFnName = Extract<keyof typeof poseidonLib, `poseidon${number}`>

/**
 * Initializes the Poseidon functions by generating and storing them in the `poseidonFuncs` array.
 * This function iterates from 1 to 16, creating Poseidon functions for each index using `getPoseidonFunc`.
 * Although up to 16 functions are generated, only 13 are actively used.
 * Poseidon is a cryptographic hash function often used in zero-knowledge proofs and other cryptographic applications.
 * This initialization process ensures that the required Poseidon functions are readily available for use.
 */
const initializePoseidonFuncs = () => {
  for (let i = 1; i <= 16; i++) {
    // theres up to 16 but we only use 13,
    poseidonFuncs.push(getPoseidonFunc(i) as PoseidonFunc)
  }
}

/**
 * Retrieves a Poseidon hash function based on the specified number of inputs.
 * @param n - The number of inputs for the Poseidon hash function. This determines
 *            the specific variant of the Poseidon function to retrieve.
 * @returns The Poseidon hash function corresponding to the given number of inputs,
 *          or `undefined` if the function is not found in the library.
 */
const getPoseidonFunc = (n: number) => {
  // error vs return undefined?
  const fnName = `poseidon${n}` as PoseidonFnName
  return poseidonLib[fnName]
}

/**
 * Computes the Poseidon hash function for the given inputs.
 * @param inputs - An array of inputs to the Poseidon function. Each input can be of type `bigint`, `number`, `string`, or `Uint8Array`.
 *                 If the input is a `string` or `number`, it will be converted to `bigint`. If the input is a `Uint8Array`,
 *                 it will be converted to `bigint` using the `uint8ArrayToBigInt` function.
 * @param returnBigInt - A boolean indicating whether the output should be returned as `bigint`. If `false`, the output will be
 *                       converted to `Uint8Array`. Defaults to `false`.
 * @param nOuts - The number of outputs to generate. Defaults to `1` if not specified.
 * @returns The Poseidon hash output. If `nOuts` is `1`, returns a single value (`bigint` or `Uint8Array` depending on `returnBigInt`).
 *          If `nOuts` is greater than `1`, returns an array of values (`bigint[]` or `Uint8Array[]` depending on `returnBigInt`).
 * @throws {Error} If the number of inputs is less than `1` or greater than `14`.
 * @throws {Error} If any input is `undefined` or `null`.
 * @throws {Error} If an input is of an invalid type.
 * @throws {Error} If the output type does not match the expected type (`bigint` or `Uint8Array`).
 * @throws {Error} If the number of outputs does not match the specified `nOuts`.
 */
const poseidonFunc = (inputs: (bigint | number | string)[], returnBigInt = false, nOuts?: number) => {
  const inputLen = inputs.length
  if (nOuts === undefined) {
    nOuts = 1 // Default to 1 output if not specified
  }

  if (inputLen < 1 || inputLen > 14) {
    throw new Error('Poseidon function index must be between 1 and 16')
  }

  // check if the inputs are uint8arrays, if they are convert to bigint
  for (let i = 0; i < inputs.length; i++) {
    const input: any = inputs[i]
    if (input === undefined || input === null) {
      throw new Error(`Input at index ${i} is undefined or null`)
    }
    if (typeof input === 'string') {
      inputs[i] = BigInt(input)
    } else if (typeof input === 'number') {
      inputs[i] = BigInt(input)
    } else if (input instanceof Uint8Array) {
      inputs[i] = uint8ArrayToBigInt(input) // Ensure the input is a valid Uint8Array
    } else if (typeof inputs[i] !== 'bigint') {
      throw new Error(`Invalid input type: ${typeof input}`)
    }
  }

  const func = getPoseidonFunc(inputLen)!
  const output = func(inputs, nOuts)
  // convert this back into uint8array if nOuts is 1
  if (returnBigInt) {
    if (nOuts === 1) {
      // If nOuts is 1, return a single bigint
      if (typeof output !== 'bigint') {
        throw new Error(`Expected output to be a bigint, got ${typeof output}`)
      }
      return output
    } else {
      // If nOuts > 1, return an array of bigints
      if (!Array.isArray(output) || output.length !== nOuts) {
        throw new Error(`Expected output to be an array of length ${nOuts}`)
      }
      return output.map((out: bigint) => {
        if (typeof out !== 'bigint') {
          throw new Error(`Expected output to be a bigint, got ${typeof out}`)
        }
        return out
      })
    }
  } else {
    if (nOuts === 1) {
      return bigintToUint8Array(output as bigint)
    } else {
      // If nOuts > 1, return an array of uint8arrays
      if (!Array.isArray(output) || output.length !== nOuts) {
        throw new Error(`Expected output to be an array of length ${nOuts}`)
      }
      return output.map((out: bigint) => {
        return bigintToUint8Array(out as bigint)
      })
    }
  }
}

// Initialize the poseidon functions on module load
export { getPoseidonFunc, poseidonFunc, initializePoseidonFuncs }
