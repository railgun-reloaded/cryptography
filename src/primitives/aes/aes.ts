import { createCipheriv, createDecipheriv } from 'node:crypto'

import { randomBytes } from '@noble/hashes/utils'

type Ciphertext = {
  iv: Uint8Array;
  tag: Uint8Array;
  data: Uint8Array[];
}

type CiphertextCTR = {
  iv: Uint8Array;
  data: Uint8Array[];
}

const KEY_BYTES = 32
const IV_BYTES = 16
const TAG_BYTES = 16

/**
 * AES-256 encryption helpers in GCM (authenticated) and CTR (streaming) modes.
 *
 * All inputs and outputs are `Uint8Array`. Keys must be 32 bytes; IVs are
 * generated internally on encrypt and read from the ciphertext bundle on
 * decrypt.
 */
class AES {
  /**
   * Generate a random 16-byte AES IV.
   * @returns A 16-byte Uint8Array suitable for use as an IV.
   */
  static getRandomIV (): Uint8Array {
    return randomBytes(IV_BYTES)
  }

  /**
   * Encrypt blocks of data with AES-256-GCM.
   * @param plaintext - Blocks of plaintext to encrypt.
   * @param key - 32-byte symmetric key.
   * @returns Ciphertext bundle: iv, auth tag, and per-block encrypted data.
   */
  static encryptGCM (plaintext: Uint8Array[], key: Uint8Array): Ciphertext {
    if (key.byteLength !== KEY_BYTES) {
      throw new Error(
        `Invalid key length. Expected ${KEY_BYTES} bytes. Received ${key.byteLength} bytes.`
      )
    }

    const iv = AES.getRandomIV()
    const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES })
    const data = plaintext.map((block) => new Uint8Array(cipher.update(block)))
    cipher.final()

    return {
      iv,
      tag: new Uint8Array(cipher.getAuthTag()),
      data,
    }
  }

  /**
   * Decrypt a ciphertext bundle produced by `encryptGCM`.
   * @param ciphertext - Bundle of iv, tag, and per-block data.
   * @param key - 32-byte symmetric key.
   * @returns Per-block decrypted plaintext.
   * @throws If the key, iv, or tag length is wrong, or the auth tag fails.
   */
  static decryptGCM (ciphertext: Ciphertext, key: Uint8Array): Uint8Array[] {
    try {
      if (key.byteLength !== KEY_BYTES) {
        throw new Error(
          `Invalid key length. Expected ${KEY_BYTES} bytes. Received ${key.byteLength} bytes.`
        )
      }
      if (ciphertext.iv.byteLength !== IV_BYTES) {
        throw new Error(
          `Invalid iv length. Expected ${IV_BYTES} bytes. Received ${ciphertext.iv.byteLength} bytes.`
        )
      }
      if (ciphertext.tag.byteLength !== TAG_BYTES) {
        throw new Error(
          `Invalid tag length. Expected ${TAG_BYTES} bytes. Received ${ciphertext.tag.byteLength} bytes.`
        )
      }

      const decipher = createDecipheriv('aes-256-gcm', key, ciphertext.iv, { authTagLength: TAG_BYTES })
      decipher.setAuthTag(ciphertext.tag)

      const data = ciphertext.data.map((block) => new Uint8Array(decipher.update(block)))
      decipher.final()
      return data
    } catch (cause) {
      throw new Error('Unable to decrypt ciphertext.', { cause })
    }
  }

  /**
   * Encrypt blocks of data with AES-256-CTR.
   * @param plaintext - Blocks of plaintext to encrypt.
   * @param key - 32-byte symmetric key.
   * @returns Ciphertext bundle: iv and per-block encrypted data (no auth tag).
   */
  static encryptCTR (plaintext: Uint8Array[], key: Uint8Array): CiphertextCTR {
    if (key.byteLength !== KEY_BYTES) {
      throw new Error(
        `Invalid key length. Expected ${KEY_BYTES} bytes. Received ${key.byteLength} bytes.`
      )
    }

    const iv = AES.getRandomIV()
    const cipher = createCipheriv('aes-256-ctr', key, iv)
    const data = plaintext.map((block) => new Uint8Array(cipher.update(block)))
    cipher.final()

    return { iv, data }
  }

  /**
   * Decrypt a ciphertext bundle produced by `encryptCTR`.
   * @param ciphertext - Bundle of iv and per-block data.
   * @param key - 32-byte symmetric key.
   * @returns Per-block decrypted plaintext.
   * @throws If the key or iv length is wrong.
   */
  static decryptCTR (ciphertext: CiphertextCTR, key: Uint8Array): Uint8Array[] {
    if (key.byteLength !== KEY_BYTES) {
      throw new Error(
        `Invalid key length. Expected ${KEY_BYTES} bytes. Received ${key.byteLength} bytes.`
      )
    }
    if (ciphertext.iv.byteLength !== IV_BYTES) {
      throw new Error(
        `Invalid iv length. Expected ${IV_BYTES} bytes. Received ${ciphertext.iv.byteLength} bytes.`
      )
    }

    const decipher = createDecipheriv('aes-256-ctr', key, ciphertext.iv)
    const data = ciphertext.data.map((block) => new Uint8Array(decipher.update(block)))
    decipher.final()
    return data
  }
}

export { AES }
export type { Ciphertext, CiphertextCTR }
