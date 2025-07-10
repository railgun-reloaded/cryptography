/* eslint-disable @typescript-eslint/no-unused-vars */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { initCircomlib, poseidon, poseidonBuild, poseidonHex } from '../../../src/index'

describe('Initialize Module', () => {
  it('PoseidonWASM', async () => {
    await initCircomlib('wasm')
    assert(poseidonBuild.wasm, 'WASM was not built properly.')
  })

  it('should test hashing speed optimized v wasm.', async () => {
    const testSet = new Array(20_000)
    console.time('wasm')
    testSet.map((_, x) => {
      return poseidonBuild.wasm([BigInt(x), 2n, 3n])
    })
    console.timeEnd('wasm')
    console.time('wasm-forEach')
    testSet.forEach((_, x) => {
      return poseidonBuild.wasm([BigInt(x), 2n, 3n])
    })
    console.timeEnd('wasm-forEach')

    console.time('wasm-forOf')
    let counter = 0
    for (const _a of testSet) {
      counter += 1
      poseidonBuild.wasm([BigInt(counter), 2n, 3n])
    }
    console.timeEnd('wasm-forOf')
  })
  it('should test hashing speed optimized v wasm.', async () => {
    await initCircomlib('pure')
    const testSet = new Array(20_000)
    console.time('optimized')
    testSet.map((_, x) => {
      return poseidonBuild.pure([BigInt(x), 2n, 3n])
    })
    console.timeEnd('optimized')
    console.time('optimized-forEach')
    testSet.forEach((_, x) => {
      return poseidonBuild.pure([BigInt(x), 2n, 3n])
    })
    console.timeEnd('optimized-forEach')

    console.time('optimized-forOf')
    let counter = 0

    for (const _a of testSet) {
      counter += 1
      poseidonBuild.pure([BigInt(counter), 2n, 3n])
    }
    console.timeEnd('optimized-forOf')
  })

  it('poseidon function test', () => {
    const testSet = new Array(20_000)
    testSet.forEach((_, x) => {
      return poseidon([BigInt(x), 2n, 3n])
    })
  })
  it('poseidonHex function test', () => {
    const testSet = new Array(20_000)
    testSet.forEach((_, x) => {
      const result = poseidonHex([BigInt(x).toString(16), '0x1235', '0x1234'])
      console.log('result', result)
    })
  })
})
