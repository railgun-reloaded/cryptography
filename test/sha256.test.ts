import assert from 'node:assert/strict'
import { test } from 'node:test'

import { bytesToHex, hexToBytes } from '@noble/hashes/utils'

import { sha256 } from '../src/index'

// SHA-256 known-answer vectors:
//   - FIPS 180-4 Appendix B.1: empty string and "abc".
//   - NIST CAVS 11.0 SHA256ShortMsg.rsp: byte-aligned short messages.
//     Source: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
const VECTORS = [
  {
    preImage: '',
    expected: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  },
  {
    preImage: '616263', // "abc"
    expected: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  },
  {
    preImage: 'd3',
    expected: '28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1',
  },
  {
    preImage: '11af',
    expected: '5ca7133fa735326081558ac312c620eeca9970d1e70a4b95533d956f072d1f98',
  },
  {
    preImage: 'b4190e',
    expected: 'dff2e73091f6c05e528896c4c831b9448653dc2ff043528f6769437bc7b975c2',
  },
  {
    preImage: '74ba2521',
    expected: 'b16aa56be3880d18cd41e68384cf1ec8c17680c45a02b1575dc1518923ae8b0e',
  },
  {
    preImage: '5738c929c4f4ccb6',
    expected: '963bb88f27f512777aab6c8b1a02c70ec0ad651d428f870036e1917120fb48bf',
  },
  {
    preImage: '9baf69cba317f422fe26a9a0',
    expected: 'fe56287cd657e4afc50dba7a3a54c2a6324b886becdcd1fae473b769e551a09b',
  },
] as const

test('sha256 matches NIST FIPS-180-4 / CAVS test vectors', () => {
  for (const vector of VECTORS) {
    const digest = sha256(hexToBytes(vector.preImage))
    assert.equal(bytesToHex(digest), vector.expected)
  }
})

test('sha256 returns a 32-byte digest', () => {
  assert.equal(sha256(new Uint8Array([1, 2, 3])).length, 32)
})
