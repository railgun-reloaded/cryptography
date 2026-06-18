import { createCipheriv, createDecipheriv } from 'node:crypto'

import { randomBytes } from '@noble/hashes/utils'

import { CryptographyError } from '../errors.js'

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
// 16-byte (128-bit) IVs are kept for wire-format compatibility with existing
// at-rest encrypted data (e.g. wallet master keys) produced by earlier
// versions. NIST SP 800-38D recommends 96-bit IVs for AES-GCM; switching
// here would break decryption of every existing ciphertext, so a change
// must be paired with a migration.
const IV_BYTES = 16
const TAG_BYTES = 16

/**
 * Throw `CryptographyError(InvalidKeyLength)` if the key is not 32 bytes.
 * @param key - Key bytes to validate.
 */
const assertKeyLength = (key: Uint8Array): void => {
  if (key.byteLength !== KEY_BYTES) {
    throw new CryptographyError(
      'InvalidKeyLength',
      `Invalid key length. Expected ${KEY_BYTES} bytes. Received ${key.byteLength} bytes.`
    )
  }
}

/**
 * Throw `CryptographyError(InvalidIvLength)` if the iv is not 16 bytes.
 * @param iv - IV bytes to validate.
 */
const assertIvLength = (iv: Uint8Array): void => {
  if (iv.byteLength !== IV_BYTES) {
    throw new CryptographyError(
      'InvalidIvLength',
      `Invalid iv length. Expected ${IV_BYTES} bytes. Received ${iv.byteLength} bytes.`
    )
  }
}

/**
 * Throw `CryptographyError(InvalidTagLength)` if the tag is not 16 bytes.
 * @param tag - Tag bytes to validate.
 */
const assertTagLength = (tag: Uint8Array): void => {
  if (tag.byteLength !== TAG_BYTES) {
    throw new CryptographyError(
      'InvalidTagLength',
      `Invalid tag length. Expected ${TAG_BYTES} bytes. Received ${tag.byteLength} bytes.`
    )
  }
}

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
   * @throws CryptographyError(InvalidKeyLength) when key is not 32 bytes.
   */
  static encryptGCM (plaintext: Uint8Array[], key: Uint8Array): Ciphertext {
    assertKeyLength(key)

    const iv = AES.getRandomIV()
    const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES })
    const data = plaintext.map((block) => new Uint8Array(cipher.update(block)))
    cipher.final()
    const tag = new Uint8Array(cipher.getAuthTag())

    return { iv, tag, data }
  }

  /**
   * Decrypt a ciphertext bundle produced by `encryptGCM`.
   * @param ciphertext - Bundle of iv, tag, and per-block data.
   * @param key - 32-byte symmetric key.
   * @returns Per-block decrypted plaintext.
   * @throws CryptographyError(InvalidKeyLength | InvalidIvLength | InvalidTagLength)
   *         on length validation failures.
   * @throws CryptographyError(DecryptionFailed) on auth tag failure or any
   *         underlying decipher error.
   */
  static decryptGCM (ciphertext: Ciphertext, key: Uint8Array): Uint8Array[] {
    assertKeyLength(key)
    assertIvLength(ciphertext.iv)
    assertTagLength(ciphertext.tag)

    try {
      const decipher = createDecipheriv('aes-256-gcm', key, ciphertext.iv, { authTagLength: TAG_BYTES })
      decipher.setAuthTag(ciphertext.tag)

      const data = ciphertext.data.map((block) => new Uint8Array(decipher.update(block)))
      decipher.final()

      return data
    } catch (cause) {
      throw new CryptographyError('DecryptionFailed', 'Unable to decrypt ciphertext.', { cause })
    }
  }

  /**
   * Encrypt blocks of data with AES-256-CTR.
   * @param plaintext - Blocks of plaintext to encrypt.
   * @param key - 32-byte symmetric key.
   * @returns Ciphertext bundle: iv and per-block encrypted data (no auth tag).
   * @throws CryptographyError(InvalidKeyLength) when key is not 32 bytes.
   */
  static encryptCTR (plaintext: Uint8Array[], key: Uint8Array): CiphertextCTR {
    assertKeyLength(key)

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
   * @throws CryptographyError(InvalidKeyLength | InvalidIvLength) on length
   *         validation failures.
   */
  static decryptCTR (ciphertext: CiphertextCTR, key: Uint8Array): Uint8Array[] {
    assertKeyLength(key)
    assertIvLength(ciphertext.iv)

    const decipher = createDecipheriv('aes-256-ctr', key, ciphertext.iv)
    const data = ciphertext.data.map((block) => new Uint8Array(decipher.update(block)))
    decipher.final()

    return data
  }
}

export { AES }
export type { Ciphertext, CiphertextCTR }
