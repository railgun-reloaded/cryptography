import assert from 'node:assert/strict'
import { createCipheriv, randomBytes } from 'node:crypto'
import { test } from 'node:test'

import { hexToBytes } from '@railgun-reloaded/bytes'

import type { CryptographyError } from '../src/index.js'
import { AES } from '../src/index.js'

/**
 * Generate a fresh 32-byte AES key from system randomness.
 * @returns A 32-byte Uint8Array suitable for AES-256.
 */
const key32 = (): Uint8Array => new Uint8Array(randomBytes(32))

/**
 * Concatenate byte blocks into a single contiguous Uint8Array.
 * @param blocks - Blocks to join in order.
 * @returns A new Uint8Array holding every block back to back.
 */
const concat = (blocks: Uint8Array[]): Uint8Array => {
  const total = blocks.reduce((sum, block) => sum + block.length, 0)
  const joined = new Uint8Array(total)
  let offset = 0
  for (const block of blocks) {
    joined.set(block, offset)
    offset += block.length
  }
  return joined
}

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

// AES-256-GCM known-answer vectors from Project Wycheproof
// (testvectors_v1/aes_gcm_test.json: keySize=256, ivSize=128, tagSize=128, aad="").
// `encryptGCM` generates its own IV, so these drive `decryptGCM` only.
// Source: https://github.com/C2SP/wycheproof
const wycheproofGcmVectors = [
  {
    tcId: 240,
    key: '00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f',
    iv: '5c2ea9b695fcf6e264b96074d6bfa572',
    ct: '28e1c5232f4ee8161dbe4c036309e0b3254e9212bef0a93431ce5e5604c8f6a73c18a3183018b770',
    tag: 'd5808a1bd11a01129bf3c6919aff2339',
    pt: '00000000000000000000000000000000000000000000000000000000000000000000000000000000',
  },
  {
    tcId: 254,
    key: 'b4cd11db0b3e0b9b34eafd9fe027746976379155e76116afde1b96d21298e34f',
    iv: '00c49f4ebb07393f07ebc3825f7b0830',
    ct: '',
    tag: '306fe8c9645cc849823e333a685b90b2',
    pt: '',
  },
  {
    tcId: 255,
    key: 'b7797eb0c1a6089ad5452d81fdb14828c040ddc4589c32b565aad8cb4de3e4a0',
    iv: '0ad570d8863918fe89124e09d125a271',
    ct: '3f',
    tag: 'fd8f593b83314e33c5a72efbeb7095e8',
    pt: 'ed',
  },
  {
    tcId: 257,
    key: 'e7f7a48df99edd92b81f508618aa96526b279debd9ddb292d385ddbae80b2259',
    iv: '7ee376910f08f497aa6c3aa7113697fd',
    ct: '469478d448f7e97d755541aa09ad95b0',
    tag: '254ada5cf662d90c5e11b2bd9c4db4c4',
    pt: '5e51dbbb861b5ec60751c0996e00527f',
  },
  {
    tcId: 258,
    key: '4f84782bfbb64a973c3de3dcfa3430367fd68bc0b4c3b31e5d7c8141ba3e6a67',
    iv: '5d1bde6fa0994b33efd8f23f531248a7',
    ct: 'cb960201fa5ad41d41d1c2c8037c71d52b72e76b16b589d71b976627c9734c9d',
    tag: '8dfce16467c3a6ebb3e7242c9a551962',
    pt: '78cb6650a1908a842101ea85804fed00cc56fbdafafba0ef4d1ca607dcae57b6',
  },
]

for (const v of wycheproofGcmVectors) {
  test(`AES-256-GCM decrypts Wycheproof vector tcId=${v.tcId}`, () => {
    const recovered = AES.decryptGCM(
      {
        iv: hexToBytes(v.iv),
        tag: hexToBytes(v.tag),
        data: v.ct === '' ? [] : [hexToBytes(v.ct)],
      },
      hexToBytes(v.key)
    )
    const expected = v.pt === '' ? [] : [hexToBytes(v.pt)]
    assert.deepEqual(recovered, expected)
  })
}

// AES-256-CTR known-answer vectors from NIST SP 800-38A Appendix F.5.6
// (CTR-AES256.Decrypt). Same key / initial counter / blocks as F.5.5.
// `encryptCTR` generates its own IV, so these drive `decryptCTR` only.
// Source: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
test('AES-256-CTR decrypts NIST SP 800-38A F.5.6 vectors', () => {
  const key = hexToBytes('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4')
  const iv = hexToBytes('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff')
  const ciphertext = [
    hexToBytes('601ec313775789a5b7a7f504bbf3d228'),
    hexToBytes('f443e3ca4d62b59aca84e990cacaf5c5'),
    hexToBytes('2b0930daa23de94ce87017ba2d84988d'),
    hexToBytes('dfc9c58db67aada613c2dd08457941a6'),
  ]
  const expected = [
    hexToBytes('6bc1bee22e409f96e93d7e117393172a'),
    hexToBytes('ae2d8a571e03ac9c9eb76fac45af8e51'),
    hexToBytes('30c81c46a35ce411e5fbc1191a0a52ef'),
    hexToBytes('f69f2445df4f9b17ad2b417be66c3710'),
  ]
  const recovered = AES.decryptCTR({ iv, data: ciphertext }, key)
  assert.deepEqual(recovered, expected)
})

test('AES-256-GCM preserves uneven, non-block-aligned chunk boundaries', () => {
  const key = key32()
  const plaintext = [
    new Uint8Array(1).fill(0xa1),
    new Uint8Array(16).fill(0xb2),
    new Uint8Array(17).fill(0xc3),
    new Uint8Array(31).fill(0xd4),
    new Uint8Array(5).fill(0xe5),
  ]
  const ct = AES.encryptGCM(plaintext, key)
  assert.equal(ct.data.length, plaintext.length, 'chunk count is preserved')
  assert.deepEqual(
    ct.data.map((chunk) => chunk.length),
    plaintext.map((chunk) => chunk.length),
    'each ciphertext chunk length matches its plaintext chunk'
  )
  assert.deepEqual(AES.decryptGCM(ct, key), plaintext)
})

test('AES-256-CTR preserves uneven, non-block-aligned chunk boundaries', () => {
  const key = key32()
  const plaintext = [
    new Uint8Array(3).fill(0x1f),
    new Uint8Array(16).fill(0x2e),
    new Uint8Array(15).fill(0x3d),
    new Uint8Array(33).fill(0x4c),
  ]
  const ct = AES.encryptCTR(plaintext, key)
  assert.equal(ct.data.length, plaintext.length, 'chunk count is preserved')
  assert.deepEqual(
    ct.data.map((chunk) => chunk.length),
    plaintext.map((chunk) => chunk.length),
    'each ciphertext chunk length matches its plaintext chunk'
  )
  assert.deepEqual(AES.decryptCTR(ct, key), plaintext)
})

test('AES-256-GCM round-trips empty input', () => {
  const key = key32()
  const ct = AES.encryptGCM([], key)
  assert.equal(ct.data.length, 0)
  assert.equal(ct.tag.length, 16)
  assert.deepEqual(AES.decryptGCM(ct, key), [])
})

test('AES-256-CTR round-trips empty input', () => {
  const key = key32()
  const ct = AES.encryptCTR([], key)
  assert.equal(ct.data.length, 0)
  assert.deepEqual(AES.decryptCTR(ct, key), [])
})

test('AES-256-GCM output is byte-identical to node:crypto for a fixed key and iv', () => {
  const key = key32()
  const plaintext = [new Uint8Array([1, 2, 3, 4]), new Uint8Array(20).fill(7)]
  const ct = AES.encryptGCM(plaintext, key)

  const reference = createCipheriv('aes-256-gcm', key, ct.iv, { authTagLength: 16 })
  const referenceBody = concat(plaintext.map((block) => new Uint8Array(reference.update(block))))
  reference.final()
  const referenceTag = new Uint8Array(reference.getAuthTag())

  assert.deepEqual(concat(ct.data), referenceBody, 'ciphertext bytes match node:crypto')
  assert.deepEqual(ct.tag, referenceTag, 'auth tag matches node:crypto')
})

test('AES-256-CTR output is byte-identical to node:crypto for a fixed key and iv', () => {
  const key = key32()
  const plaintext = [new Uint8Array([1, 2, 3]), new Uint8Array(20).fill(9)]
  const ct = AES.encryptCTR(plaintext, key)

  const reference = createCipheriv('aes-256-ctr', key, ct.iv)
  const referenceBody = concat([
    ...plaintext.map((block) => new Uint8Array(reference.update(block))),
    new Uint8Array(reference.final()),
  ])

  assert.deepEqual(concat(ct.data), referenceBody, 'ciphertext bytes match node:crypto')
})
