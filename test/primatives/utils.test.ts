import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { bytesToHex, hexToBytes } from '../../src/primatives/utils'

describe('hexToBytes', () => {
  it('should convert valid hex string without 0x prefix', () => {
    const hex = 'deadbeef'
    const bytes = hexToBytes(hex)
    assert.deepEqual(bytes, new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
  })

  it('should convert valid hex string with 0x prefix', () => {
    const hex = '0xdeadbeef'
    const bytes = hexToBytes(hex)
    assert.deepEqual(bytes, new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
  })

  it('should handle 32-byte hash', () => {
    const hex = '0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a'
    const bytes = hexToBytes(hex)
    assert.equal(bytes.length, 32)
    assert.equal(bytes[0], 0x11)
    assert.equal(bytes[31], 0x9a)
  })

  it('should handle empty string', () => {
    const bytes = hexToBytes('')
    assert.deepEqual(bytes, new Uint8Array(0))
  })

  it('should handle empty string with 0x prefix', () => {
    const bytes = hexToBytes('0x')
    assert.deepEqual(bytes, new Uint8Array(0))
  })

  it('should throw on odd-length hex string', () => {
    assert.throws(() => {
      hexToBytes('abc')
    }, { message: 'Invalid hex string' })
  })

  it('should throw on odd-length hex string with 0x prefix', () => {
    assert.throws(() => {
      hexToBytes('0xabc')
    }, { message: 'Invalid hex string' })
  })

  it('should throw on invalid hex characters', () => {
    assert.throws(() => {
      hexToBytes('gg')
    }, { message: 'Invalid hex string' })
  })

  it('should throw on invalid hex characters (zz)', () => {
    assert.throws(() => {
      hexToBytes('zz')
    }, { message: 'Invalid hex string' })
  })

  it('should throw on mixed valid and invalid characters', () => {
    assert.throws(() => {
      hexToBytes('12g4')
    }, { message: 'Invalid hex string' })
  })

  it('should handle uppercase hex', () => {
    const hex = 'DEADBEEF'
    const bytes = hexToBytes(hex)
    assert.deepEqual(bytes, new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
  })

  it('should handle mixed case hex', () => {
    const hex = 'DeAdBeEf'
    const bytes = hexToBytes(hex)
    assert.deepEqual(bytes, new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
  })

  it('should handle zero bytes', () => {
    const hex = '0x00000000'
    const bytes = hexToBytes(hex)
    assert.deepEqual(bytes, new Uint8Array([0x00, 0x00, 0x00, 0x00]))
  })
})

describe('bytesToHex', () => {
  it('should convert Uint8Array to hex string', () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
    const hex = bytesToHex(bytes)
    assert.equal(hex, 'deadbeef')
  })

  it('should pad single-digit hex values', () => {
    const bytes = new Uint8Array([0x01, 0x02, 0x0f])
    const hex = bytesToHex(bytes)
    assert.equal(hex, '01020f')
  })

  it('should handle empty array', () => {
    const bytes = new Uint8Array(0)
    const hex = bytesToHex(bytes)
    assert.equal(hex, '')
  })

  it('should handle zero bytes', () => {
    const bytes = new Uint8Array([0x00, 0x00, 0x00])
    const hex = bytesToHex(bytes)
    assert.equal(hex, '000000')
  })

  it('should handle 32-byte array', () => {
    const bytes = new Uint8Array(32).fill(0xff)
    const hex = bytesToHex(bytes)
    assert.equal(hex.length, 64)
    assert.equal(hex, 'f'.repeat(64))
  })
})

describe('hexToBytes and bytesToHex round-trip', () => {
  it('should round-trip correctly', () => {
    const original = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78])
    const hex = bytesToHex(original)
    const recovered = hexToBytes(hex)
    assert.deepEqual(recovered, original)
  })

  it('should round-trip with 0x prefix', () => {
    const original = new Uint8Array([0xde, 0xad, 0xbe, 0xef])
    const hex = '0x' + bytesToHex(original)
    const recovered = hexToBytes(hex)
    assert.deepEqual(recovered, original)
  })

  it('should round-trip empty array', () => {
    const original = new Uint8Array(0)
    const hex = bytesToHex(original)
    const recovered = hexToBytes(hex)
    assert.deepEqual(recovered, original)
  })

  it('should round-trip 32-byte hash', () => {
    const original = new Uint8Array(32)
    for (let i = 0; i < 32; i++) {
      original[i] = i
    }
    const hex = bytesToHex(original)
    const recovered = hexToBytes(hex)
    assert.deepEqual(recovered, original)
  })
})
