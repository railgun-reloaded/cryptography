import { hexToBytes } from '@noble/hashes/utils'
import { bytesToBigInt } from '@railgun-reloaded/bytes'
import { test } from 'brittle'

import { keccak256 } from '../src/index'

const VECTORS = [
  {
    preImage: '',
    array: new Uint8Array([]),
    expected: 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
  },
  {
    preImage: '5241494c47554e',
    array: new Uint8Array([82, 65, 73, 76, 71, 85, 78]),
    expected: 'ef0394c8ea7550db58adcb1b8ffb98f76fca939554a4084889b6bffa01aac296',
  },
  {
    preImage: '50524956414359202620414e4f4e594d495459',
    array: new Uint8Array([
      80, 82, 73, 86, 65, 67, 89, 32, 38, 32, 65, 78, 79, 78, 89, 77, 73, 84, 89,
    ]),
    expected: '5c7d261b35e3b58c6ca6663e44b736a7fbbc0e2265cd050959f4976f8667d306',
  },
] as const

test('keccak256 matches known test vectors via hex preimage', (t) => {
  for (const vector of VECTORS) {
    const hash = keccak256(hexToBytes(vector.preImage))
    t.is(bytesToBigInt(hash).toString(16), vector.expected)
  }
})

test('keccak256 matches known test vectors via Uint8Array preimage', (t) => {
  for (const vector of VECTORS) {
    const hash = keccak256(vector.array)
    t.is(bytesToBigInt(hash).toString(16), vector.expected)
  }
})

test('keccak256 returns a 32-byte digest', (t) => {
  t.is(keccak256(new Uint8Array([1, 2, 3])).length, 32)
})
