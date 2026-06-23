import assert from 'node:assert/strict'
import { test } from 'node:test'

import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'

import { keccak256 } from '../src/index.js'

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

test('keccak256 matches known test vectors via hex preimage', () => {
  for (const vector of VECTORS) {
    const hash = keccak256(hexToBytes(vector.preImage))
    assert.equal(bytesToHex(hash), vector.expected)
  }
})

test('keccak256 matches known test vectors via Uint8Array preimage', () => {
  for (const vector of VECTORS) {
    const hash = keccak256(vector.array)
    assert.equal(bytesToHex(hash), vector.expected)
  }
})

test('keccak256 returns a 32-byte digest', () => {
  assert.equal(keccak256(new Uint8Array([1, 2, 3])).length, 32)
})

// Keccak-256 known-answer vectors from the Keccak team's ShortMsgKAT_256.txt
// (KeccakKAT submission — original 0x01-padded Keccak, the variant used by
// Ethereum, not FIPS-202 SHA3-256). Only byte-aligned (Len % 8 === 0) cases.
// Source: https://keccak.team (KeccakKAT-3.zip, ShortMsgKAT_256.txt)
const KAT_VECTORS = [
  { msg: '', expected: 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470' },
  { msg: 'cc', expected: 'eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a' },
  { msg: '41fb', expected: 'a8eaceda4d47b3281a795ad9e1ea2122b407baf9aabcb9e18b5717b7873537d2' },
  { msg: '1f877c', expected: '627d7bc1491b2ab127282827b8de2d276b13d7d70fb4c5957fdf20655bc7ac30' },
  { msg: 'c1ecfdfc', expected: 'b149e766d7612eaf7d55f74e1a4fdd63709a8115b14f61fcd22aa4abc8b8e122' },
  { msg: '21f134ac57', expected: '67f05544dbe97d5d6417c1b1ea9bc0e3a99a541381d1cd9b08a9765687eb5bb4' },
  { msg: 'c6f50bb74e29', expected: '923062c4e6f057597220d182dbb10e81cd25f60b54005b2a75dd33d6dac518d0' },
  { msg: '119713cc83eeef', expected: 'feb8405dcd315d48c6cbf7a3504996de8e25cc22566efec67433712eda99894f' },
] as const

test('keccak256 matches Keccak team ShortMsgKAT_256 vectors', () => {
  for (const v of KAT_VECTORS) {
    assert.equal(bytesToHex(keccak256(hexToBytes(v.msg))), v.expected)
  }
})
