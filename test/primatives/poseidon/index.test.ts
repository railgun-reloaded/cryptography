/* eslint-disable @typescript-eslint/no-unused-vars */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import {
  eddsa, initCircomlib,
  poseidon,
  //  poseidon,
  poseidonBuild, poseidonHex
} from '../../../src/index'

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
    let counter = 0

    for (const _a of testSet) {
      counter += 1
      poseidon([new Uint8Array([counter]), new Uint8Array([2]), new Uint8Array([3])])
    }
  })
  it('poseidonHex function test', () => {
    const testSet = new Array(20_000)
    let counter = 0
    for (const _a of testSet) {
      counter += 1
      poseidonHex(['0x' + BigInt(counter).toString(16), '0x1234', '0x1235'])
    }
  })
  it.only('should have same privekey', () => {
    const publickey = new Uint8Array([
      207, 255, 35, 123, 225, 202, 70, 139,
      250, 120, 235, 158, 5, 168, 39, 1,
      112, 61, 67, 88, 24, 249, 103, 47,
      111, 29, 181, 35, 120, 93, 148, 41
    ])
    const expectedPrivKey = [
      new Uint8Array([
        30, 223, 15, 39, 142, 51, 141, 235,
        7, 92, 200, 201, 5, 67, 246, 241,
        209, 89, 11, 252, 121, 116, 202, 28,
        218, 122, 231, 182, 229, 49, 49, 109
      ]),
      new Uint8Array([
        1, 43, 134, 211, 238, 155, 36, 192,
        38, 46, 63, 206, 87, 145, 249, 254,
        9, 193, 223, 88, 129, 152, 98, 172,
        138, 129, 97, 26, 93, 174, 178, 235
      ])
    ]

    const privkey = eddsa.privateKeyToPublicKey(publickey)
    assert.deepStrictEqual(expectedPrivKey, privkey)
  })
})
