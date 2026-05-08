import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { test } from 'node:test'

import type { CryptographyError } from '../src/index'
import { AES } from '../src/index'

/**
 * Generate a fresh 32-byte AES key from system randomness.
 * @returns A 32-byte Uint8Array suitable for AES-256.
 */
const key32 = (): Uint8Array => new Uint8Array(randomBytes(32))

test('AES-256-GCM encrypt + decrypt roundtrip', () => {
  const key = key32()
  const plaintext = [
    new Uint8Array([1, 2, 3, 4]),
    new Uint8Array([5, 6, 7, 8, 9]),
  ]
  const ct = AES.encryptGCM(plaintext, key)
  assert.equal(ct.iv.length, 16, 'iv is 16 bytes')
  assert.equal(ct.tag.length, 16, 'auth tag is 16 bytes')
  const recovered = AES.decryptGCM(ct, key)
  assert.deepEqual(recovered, plaintext)
})

test('AES-256-GCM rejects wrong-length keys on encrypt', () => {
  assert.throws(
    () => AES.encryptGCM([new Uint8Array([1])], new Uint8Array(16)),
    { name: 'CryptographyError', code: 'InvalidKeyLength' satisfies CryptographyError['code'] }
  )
})

test('AES-256-GCM rejects wrong-length keys on decrypt', () => {
  const ct = AES.encryptGCM([new Uint8Array([1])], key32())
  assert.throws(
    () => AES.decryptGCM(ct, new Uint8Array(16)),
    { name: 'CryptographyError', code: 'InvalidKeyLength' satisfies CryptographyError['code'] }
  )
})

test('AES-256-GCM rejects wrong-length iv on decrypt', () => {
  const ct = AES.encryptGCM([new Uint8Array([1])], key32())
  assert.throws(
    () => AES.decryptGCM({ ...ct, iv: new Uint8Array(8) }, key32()),
    { name: 'CryptographyError', code: 'InvalidIvLength' satisfies CryptographyError['code'] }
  )
})

test('AES-256-GCM rejects wrong-length tag on decrypt', () => {
  const key = key32()
  const ct = AES.encryptGCM([new Uint8Array([1])], key)
  assert.throws(
    () => AES.decryptGCM({ ...ct, tag: new Uint8Array(8) }, key),
    { name: 'CryptographyError', code: 'InvalidTagLength' satisfies CryptographyError['code'] }
  )
})

test('AES-256-GCM detects tag tampering', () => {
  const key = key32()
  const ct = AES.encryptGCM([new Uint8Array([1, 2, 3])], key)
  const tampered = { ...ct, tag: new Uint8Array(ct.tag) }
  tampered.tag[0] = (tampered.tag[0]! ^ 0xff) & 0xff
  assert.throws(
    () => AES.decryptGCM(tampered, key),
    { name: 'CryptographyError', code: 'DecryptionFailed' satisfies CryptographyError['code'] }
  )
})

test('AES-256-CTR encrypt + decrypt roundtrip', () => {
  const key = key32()
  const plaintext = [
    new Uint8Array([10, 11, 12]),
    new Uint8Array([13, 14, 15, 16]),
  ]
  const ct = AES.encryptCTR(plaintext, key)
  assert.equal(ct.iv.length, 16, 'iv is 16 bytes')
  const recovered = AES.decryptCTR(ct, key)
  assert.deepEqual(recovered, plaintext)
})

test('AES-256-CTR rejects wrong-length keys', () => {
  assert.throws(
    () => AES.encryptCTR([new Uint8Array([1])], new Uint8Array(16)),
    { name: 'CryptographyError', code: 'InvalidKeyLength' satisfies CryptographyError['code'] }
  )
  assert.throws(
    () => AES.decryptCTR(
      { iv: new Uint8Array(16), data: [new Uint8Array([1])] },
      new Uint8Array(16)
    ),
    { name: 'CryptographyError', code: 'InvalidKeyLength' satisfies CryptographyError['code'] }
  )
})

test('AES-256-CTR rejects wrong-length iv on decrypt', () => {
  const ct = AES.encryptCTR([new Uint8Array([1])], key32())
  assert.throws(
    () => AES.decryptCTR({ ...ct, iv: new Uint8Array(8) }, key32()),
    { name: 'CryptographyError', code: 'InvalidIvLength' satisfies CryptographyError['code'] }
  )
})

test('AES.getRandomIV returns a fresh 16-byte iv each call', () => {
  const a = AES.getRandomIV()
  const b = AES.getRandomIV()
  assert.equal(a.length, 16)
  assert.equal(b.length, 16)
  assert.ok(!a.every((v, i) => v === b[i]), 'two random IVs are not identical')
})
