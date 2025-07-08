import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { hexToBytes } from '@noble/hashes/utils'

import { keccak256, poseidonFunc, uint8ArrayToBigInt } from '../src'

describe('Cryptography Module', () => {
  it('Poseidon', () => {
    it('should compute proper hashes for test vectors.', () => {
      const vectors = [
        {
          input: [
            '0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a',
            '0x2a92a4c8d7c21d97d946951043d11954de794cd506093dbbb97ada64c14b203b'
          ],
          expectedHash: '106dc6dc79863b23dc1a63c7ca40e8c22bb830e449b75a2286c7f7b0b87ae6c3'
        },
        {
          input: [
            '0x0db945439b762ad08f144bcccc3746773b332e8a0045a11d87662dc227923df5',
            '0x09ce612d20912e20cde93cd2a03fcccdfdce5910242b555ff35b5373041bf329'
          ],
          expectedHash: '063c1c7dfb4b63255c492bb6b32d57eddddcb1c78cfb990e7b35416cf966ed79'
        },
        {
          input: [
            '0x0db945439b762ad08f144bcccc3746773b332e8a0045a11d87662dc227923df5',
            '0x09ce612d20912e20cde93cd2a03fcccdfdce5910242b555ff35b5373041bf329'
          ],
          expectedHash: '063c1c7dfb4b63255c492bb6b32d57eddddcb1c78cfb990e7b35416cf966ed79',
        }

      ]
      for (const vector of vectors) {
        const result = poseidonFunc(vector.input, true)
        const resultHash = result.toString(16).padStart(64, '0')
        assert(resultHash === vector.expectedHash)
      }
    })
  })
  it('Keccak256', () => {
    it('should compute proper hashes for test vectors.', () => {
      const vectors = [
        {
          preImage: '',
          array: new Uint8Array([]),
          result: 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
        },
        {
          preImage: '5241494c47554e',
          array: new Uint8Array([82, 65, 73, 76, 71, 85, 78]),
          result: 'ef0394c8ea7550db58adcb1b8ffb98f76fca939554a4084889b6bffa01aac296',
        },
        {
          preImage: '50524956414359202620414e4f4e594d495459',
          array: new Uint8Array([
            80, 82, 73, 86, 65, 67, 89, 32, 38, 32, 65, 78, 79, 78, 89, 77, 73, 84, 89,
          ]),
          result: '5c7d261b35e3b58c6ca6663e44b736a7fbbc0e2265cd050959f4976f8667d306',
        },
      ]
      for (const vector of vectors) {
        const bytes = hexToBytes(vector.preImage)
        const hash = keccak256(bytes)
        const arrayHash = keccak256(vector.array)
        const hashBigint = uint8ArrayToBigInt(hash).toString(16)
        const arrayHashBigInt = uint8ArrayToBigInt(arrayHash).toString(16)
        assert(hashBigint === vector.result)
        assert(arrayHashBigInt === vector.result)
      }
    })
  })
})
