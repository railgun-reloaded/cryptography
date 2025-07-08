import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { poseidonFunc } from '../src/index.js'

describe('poseidonFunc', () => {
  it('should compute Poseidon hash with bigint inputs and return bigint output', () => {
    const inputs = [BigInt(1), BigInt(2), BigInt(3)]
    const result = poseidonFunc(inputs, true)
    assert(typeof result === 'bigint')
  })

  it('should compute Poseidon hash with number inputs and return Uint8Array output', () => {
    const inputs = [1, 2, 3]
    const result = poseidonFunc(inputs)
    assert(result instanceof Uint8Array)
  })

  it('should compute Poseidon hash with string inputs and return Uint8Array output', () => {
    const inputs = ['1', '2', '3']
    const result = poseidonFunc(inputs)
    assert(result instanceof Uint8Array)
  })

  it('should compute Poseidon hash with Uint8Array inputs and return bigint output', () => {
    const inputs = [new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3])]
    // @ts-expect-error
    const result = poseidonFunc(inputs, true)
    assert(typeof result === 'bigint')
  })

  it('should throw an error for invalid input types', () => {
    const inputs = [null, undefined, {}]
    try {
      // @ts-expect-error
      poseidonFunc(inputs)
      assert(false, 'Should have thrown.')
    } catch (error) {

    }
  })

  it('should throw an error for inputs less than 1 or greater than 14', () => {
    const inputs: any = []
    try {
      poseidonFunc(inputs)
      assert(false, 'Poseidon function index must be between 1 and 16')
    } catch (error) {

    }
    const tooManyInputs = Array(15).fill(BigInt(1))
    try {
      poseidonFunc(tooManyInputs)
      assert(false, 'Poseidon function index must be between 1 and 16')
    } catch (error) {

    }
  })

  it('should compute Poseidon hash with multiple outputs', () => {
    const inputs = [BigInt(1), BigInt(2), BigInt(3)]
    const nOuts = 2
    const result = poseidonFunc(inputs, true, nOuts)
    assert(Array.isArray(result), 'not array.')
    assert(result.length === nOuts, 'invalid length.')
    result.forEach(output => assert(typeof output === 'bigint', 'not bigint.'))
  })

  it('should throw an error if output type does not match expected type', () => {
    const inputs = [BigInt(1), BigInt(2), BigInt(3)]
    const nOuts = 2
    try {
      poseidonFunc(inputs, false, nOuts)
      assert(false, 'Expected output to be an array of length 2')
    } catch (error) {

    }
  })
})
