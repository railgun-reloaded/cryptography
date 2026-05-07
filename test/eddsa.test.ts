import { randomBytes } from 'node:crypto'

import { bytesToHex } from '@noble/hashes/utils'
import { test } from 'brittle'

import { eddsa, initCircomlib, initializeEddsa } from '../src/index'

test('eddsa: signPoseidon roundtrip verifies under verifyEDDSA', async (t) => {
  await initCircomlib('pure')
  await initializeEddsa()

  const privateKey = new Uint8Array(randomBytes(32))
  const message = new Uint8Array(randomBytes(32))
  const pubKey = eddsa.privateKeyToPublicKey(privateKey)
  const signature = eddsa.signPoseidon(privateKey, message)

  t.is(signature.length, 3, 'signature is a 3-tuple [R8x, R8y, S]')

  const verified = eddsa.verifyEDDSA(
    message,
    {
      R8: [signature[0]!, signature[1]!],
      S: BigInt('0x' + bytesToHex(signature[2]!)),
    },
    pubKey
  )
  t.ok(verified, 'signature verifies under the matching public key')
})

test('eddsa: known public key from a fixed input', async (t) => {
  await initCircomlib('pure')
  await initializeEddsa()

  const input = new Uint8Array([
    207, 255, 35, 123, 225, 202, 70, 139,
    250, 120, 235, 158, 5, 168, 39, 1,
    112, 61, 67, 88, 24, 249, 103, 47,
    111, 29, 181, 35, 120, 93, 148, 41,
  ])
  const expected: [Uint8Array, Uint8Array] = [
    new Uint8Array([
      30, 223, 15, 39, 142, 51, 141, 235,
      7, 92, 200, 201, 5, 67, 246, 241,
      209, 89, 11, 252, 121, 116, 202, 28,
      218, 122, 231, 182, 229, 49, 49, 109,
    ]),
    new Uint8Array([
      1, 43, 134, 211, 238, 155, 36, 192,
      38, 46, 63, 206, 87, 145, 249, 254,
      9, 193, 223, 88, 129, 152, 98, 172,
      138, 129, 97, 26, 93, 174, 178, 235,
    ]),
  ]
  const result = eddsa.privateKeyToPublicKey(input)
  t.alike(result[0], expected[0])
  t.alike(result[1], expected[1])
})
