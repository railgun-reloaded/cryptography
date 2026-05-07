import { hexToBytes } from '@noble/hashes/utils'
import { bytesToBigInt } from '@railgun-reloaded/bytes'
import { test } from 'brittle'

import { sha256 } from '../src/index'

const VECTORS = [
  {
    preImage: '',
    expected: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  },
  {
    preImage: '616263', // "abc"
    expected: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  },
] as const

test('sha256 matches NIST FIPS-180-4 test vectors', (t) => {
  for (const vector of VECTORS) {
    const digest = sha256(hexToBytes(vector.preImage))
    t.is(bytesToBigInt(digest).toString(16).padStart(64, '0'), vector.expected)
  }
})

test('sha256 returns a 32-byte digest', (t) => {
  t.is(sha256(new Uint8Array([1, 2, 3])).length, 32)
})
