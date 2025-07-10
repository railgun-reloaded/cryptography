import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { describe, it } from 'node:test'

import { bytesToHex } from '@noble/hashes/utils'

import { autoInitializeEddsa, eddsa, initCircomlib, poseidonBuild } from '../../../src'

describe('EDDSA module', () => {
  it('Shold sign and verify signature', async () => {
    await initCircomlib('pure')
    console.log(poseidonBuild)
    await autoInitializeEddsa()
    const privateKey = randomBytes(32)
    const pubKey = eddsa.privateKeyToPublicKey(privateKey)
    const message = randomBytes(32)
    eddsa.privateKeyToPublicKey(privateKey)
    const signature = eddsa.signPoseidon(privateKey, message)
    // console.log('signature', signature)
    const verified = eddsa.verifyEDDSA(message, {
      R8: [signature[0], signature[1]],
      S: BigInt('0x' + bytesToHex(signature[2]))
    }, pubKey)
    console.log('verified', verified)
    assert(signature)
  })
})
