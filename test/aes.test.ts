import { randomBytes } from 'node:crypto'

import { test } from 'brittle'

import { AES } from '../src/index'

/**
 * Generate a fresh 32-byte AES key from system randomness.
 * @returns A 32-byte Uint8Array suitable for AES-256.
 */
const key32 = (): Uint8Array => new Uint8Array(randomBytes(32))

test('AES-256-GCM encrypt + decrypt roundtrip', (t) => {
  const key = key32()
  const plaintext = [
    new Uint8Array([1, 2, 3, 4]),
    new Uint8Array([5, 6, 7, 8, 9]),
  ]
  const ct = AES.encryptGCM(plaintext, key)
  t.is(ct.iv.length, 16, 'iv is 16 bytes')
  t.is(ct.tag.length, 16, 'auth tag is 16 bytes')
  const recovered = AES.decryptGCM(ct, key)
  t.alike(recovered, plaintext)
})

test('AES-256-GCM rejects wrong-length keys on encrypt', (t) => {
  t.exception(
    () => AES.encryptGCM([new Uint8Array([1])], new Uint8Array(16)),
    /Invalid key length/
  )
})

test('AES-256-GCM rejects wrong-length keys on decrypt', (t) => {
  const ct = AES.encryptGCM([new Uint8Array([1])], key32())
  t.exception(() => AES.decryptGCM(ct, new Uint8Array(16)), /Invalid key length/)
})

test('AES-256-GCM rejects wrong-length iv on decrypt', (t) => {
  const ct = AES.encryptGCM([new Uint8Array([1])], key32())
  t.exception(
    () => AES.decryptGCM({ ...ct, iv: new Uint8Array(8) }, key32()),
    /Invalid iv length/
  )
})

test('AES-256-GCM rejects wrong-length tag on decrypt', (t) => {
  const key = key32()
  const ct = AES.encryptGCM([new Uint8Array([1])], key)
  t.exception(
    () => AES.decryptGCM({ ...ct, tag: new Uint8Array(8) }, key),
    /Invalid tag length/
  )
})

test('AES-256-GCM detects tag tampering', (t) => {
  const key = key32()
  const ct = AES.encryptGCM([new Uint8Array([1, 2, 3])], key)
  const tampered = { ...ct, tag: new Uint8Array(ct.tag) }
  tampered.tag[0] = (tampered.tag[0]! ^ 0xff) & 0xff
  t.exception(() => AES.decryptGCM(tampered, key), /Unable to decrypt ciphertext/)
})

test('AES-256-CTR encrypt + decrypt roundtrip', (t) => {
  const key = key32()
  const plaintext = [
    new Uint8Array([10, 11, 12]),
    new Uint8Array([13, 14, 15, 16]),
  ]
  const ct = AES.encryptCTR(plaintext, key)
  t.is(ct.iv.length, 16, 'iv is 16 bytes')
  const recovered = AES.decryptCTR(ct, key)
  t.alike(recovered, plaintext)
})

test('AES-256-CTR rejects wrong-length keys', (t) => {
  t.exception(
    () => AES.encryptCTR([new Uint8Array([1])], new Uint8Array(16)),
    /Invalid key length/
  )
  t.exception(
    () => AES.decryptCTR(
      { iv: new Uint8Array(16), data: [new Uint8Array([1])] },
      new Uint8Array(16)
    ),
    /Invalid key length/
  )
})

test('AES-256-CTR rejects wrong-length iv on decrypt', (t) => {
  const ct = AES.encryptCTR([new Uint8Array([1])], key32())
  t.exception(
    () => AES.decryptCTR({ ...ct, iv: new Uint8Array(8) }, key32()),
    /Invalid iv length/
  )
})

test('AES.getRandomIV returns a fresh 16-byte iv each call', (t) => {
  const a = AES.getRandomIV()
  const b = AES.getRandomIV()
  t.is(a.length, 16)
  t.is(b.length, 16)
  t.absent(a.every((v, i) => v === b[i]), 'two random IVs are not identical')
})
