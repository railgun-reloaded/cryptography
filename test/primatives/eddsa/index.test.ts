import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { describe, it } from 'node:test'

import { bytesToHex } from '@noble/hashes/utils'

import { autoInitializeEddsa, eddsa, initCircomlib } from '../../../src'

describe.only('EDDSA module', () => {
  it('Should sign and verify signature', async () => {
    await initCircomlib('pure')
    await autoInitializeEddsa()
    const privateKey = randomBytes(32)
    const pubKey = eddsa.privateKeyToPublicKey(privateKey)
    const message = randomBytes(32)
    eddsa.privateKeyToPublicKey(privateKey)
    const signature = eddsa.signPoseidon(privateKey, message)
    const verified = eddsa.verifyEDDSA(message, {
      R8: [signature[0], signature[1]],
      S: BigInt('0x' + bytesToHex(signature[2]))
    }, pubKey)
    assert(signature, 'Signature not generated.')
    assert(verified, 'Signature not verified.')
  })
})
