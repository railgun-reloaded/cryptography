import crypto from 'node:crypto'

import { randomBytes } from '@noble/hashes/utils'

type Ciphers = Pick<
  // eslint-disable-next-line @typescript-eslint/consistent-type-imports
  typeof import('node:crypto'),
  'createCipheriv' | 'createDecipheriv'
>

const { createCipheriv, createDecipheriv } = crypto as Ciphers

type Ciphertext = {
  iv: Uint8Array;
  tag: Uint8Array;
  data: Uint8Array[];
}

type CiphertextCTR = {
  iv: Uint8Array;
  data: Uint8Array[];
}

/**
 * AES class provides methods for encrypting and decrypting data using AES-256-GCM and AES-256-CTR modes.
 * It includes functionality for generating random initialization vectors (IVs), encrypting plaintext,
 * and decrypting ciphertext. The class ensures proper handling of encryption keys, IVs, and authentication tags.
 *
 * Features:
 * - AES-256-GCM encryption and decryption with authentication tag support.
 * - AES-256-CTR encryption and decryption for streaming data.
 * - Random IV generation for secure encryption.
 *
 * Methods:
 * - `getRandomIV`: Generates a random 16-byte initialization vector (IV).
 * - `encryptGCM`: Encrypts data blocks using AES-256-GCM mode.
 * - `decryptGCM`: Decrypts AES-256-GCM encrypted data blocks.
 * - `encryptCTR`: Encrypts data blocks using AES-256-CTR mode.
 * - `decryptCTR`: Decrypts AES-256-CTR encrypted data blocks.
 *
 * Usage:
 * Ensure that the encryption key is a 32-byte Uint8Array and the IV is a 16-byte Uint8Array.
 * For AES-256-GCM, the authentication tag is automatically handled during encryption and decryption.
 *
 * Example:
 * ```typescript
 * const key = crypto.randomBytes(32); // Generate a 32-byte key
 * const plaintext = [new Uint8Array([1, 2, 3, 4])];
 * const ciphertext = AES.encryptGCM(plaintext, key);
 * const decrypted = AES.decryptGCM(ciphertext, key);
 * ```
 */
class AES {
  /**
   * Generates a random initialization vector (IV) for AES encryption.
   * The IV is a 16-byte (128-bit) array, which is commonly used to ensure
   * that the same plaintext encrypted multiple times will produce different ciphertexts.
   * @returns A randomly generated 16-byte initialization vector.
   */
  static getRandomIV (): Uint8Array {
    return randomBytes(16)
  }

  /**
   * Encrypt blocks of data with AES-256-GCM
   * @param plaintext - plaintext to encrypt
   * @param key - key to encrypt with
   * @returns ciphertext bundle
   */
  static encryptGCM (plaintext: Uint8Array[], key: Uint8Array): Ciphertext {
    // If types are strings, convert to bytes array
    if (key.byteLength !== 32) {
      throw new Error(
        `Invalid key length. Expected 32 bytes. Received ${key.byteLength} bytes.`
      )
    }

    const iv = AES.getRandomIV()

    // Initialize cipher
    const cipher = createCipheriv('aes-256-gcm', key, iv, {
      authTagLength: 16,
    })

    // Loop through data blocks and encrypt
    const data = new Array<Uint8Array>(plaintext.length)
    for (let i = 0; i < plaintext.length; i += 1) {
      data[i] = cipher.update(new Uint8Array(plaintext[i] ?? [0]))
    }
    cipher.final()

    const tag = cipher.getAuthTag()
    const tagFormatted = new Uint8Array(tag)

    // Return encrypted data bundle
    return {
      iv,
      tag: tagFormatted,
      data,
    }
  }

  /**
   * Decrypts AES-256-GCM encrypted data
   * On failure, it throws `Unsupported state or unable to authenticate data`
   * @param ciphertext - ciphertext bundle to decrypt
   * @param key - key to decrypt with
   * @returns - plaintext
   */
  static decryptGCM (ciphertext: Ciphertext, key: Uint8Array): Uint8Array[] {
    try {
      // Ensure that inputs are Uint8Arrays of the correct length

      if (key.byteLength !== 32) {
        throw new Error(
          `Invalid key length. Expected 32 bytes. Received ${key.byteLength} bytes.`
        )
      }
      const ivFormatted = ciphertext.iv
      const tagFormatted = ciphertext.tag

      if (ivFormatted.byteLength !== 16) {
        throw new Error(
          `Invalid iv length. Expected 16 bytes. Received ${ivFormatted.byteLength} bytes.`
        )
      }
      if (tagFormatted.byteLength !== 16) {
        throw new Error(
          `Invalid tag length. Expected 16 bytes. Received ${tagFormatted.byteLength} bytes.`
        )
      }

      // Initialize decipher
      const decipher = createDecipheriv('aes-256-gcm', key, ivFormatted, {
        authTagLength: 16,
      })

      // It will throw exception if the decryption fails due to invalid key, iv, tag
      decipher.setAuthTag(tagFormatted)

      // Loop through ciphertext and decrypt then return
      const data = new Array<Uint8Array>(ciphertext.data.length)
      for (let i = 0; i < ciphertext.data.length; i += 1) {
        data[i] = decipher.update(new Uint8Array(ciphertext.data[i] ?? [0]))
      }
      decipher.final()
      return data
    } catch (cause) {
      throw new Error('Unable to decrypt ciphertext.', { cause })
    }
  }

  /**
   * Encrypt blocks of data with AES-256-CTR
   * @param plaintext - plaintext to encrypt
   * @param key - key to encrypt with
   * @returns ciphertext bundle
   */
  static encryptCTR (plaintext: Uint8Array[], key: Uint8Array): CiphertextCTR {
    // If types are strings, convert to bytes array
    if (key.byteLength !== 32) {
      throw new Error(
        `Invalid key length. Expected 32 bytes. Received ${key.byteLength} bytes.`
      )
    }

    const iv = AES.getRandomIV()

    // Initialize cipher
    const cipher = createCipheriv('aes-256-ctr', key, iv)
    // Loop through data blocks and encrypt
    const data = new Array<Uint8Array>(plaintext.length)
    for (let i = 0; i < plaintext.length; i += 1) {
      const byte = plaintext[i] ?? [0]
      const d = cipher.update(byte as Buffer)
      data[i] = new Uint8Array(d)
    }
    cipher.final()

    // console.log("final", f, cipher.update("  "));
    // Return encrypted data bundle
    return {
      iv,
      data,
    }
  }

  /**
   * Decrypts AES-256-CTR encrypted data
   * On failure, it throws `Unsupported state or unable to authenticate data`
   * @param ciphertext - ciphertext bundle to decrypt
   * @param key - key to decrypt with
   * @returns - plaintext
   */
  static decryptCTR (ciphertext: CiphertextCTR, key: Uint8Array): Uint8Array[] {
    if (key.byteLength !== 32) {
      throw new Error(
        `Invalid key length. Expected 32 bytes. Received ${key.byteLength} bytes.`
      )
    }

    const ivFormatted = ciphertext.iv
    if (ivFormatted.byteLength !== 16) {
      throw new Error(
        `Invalid iv length. Expected 16 bytes. Received ${ivFormatted.byteLength} bytes.`
      )
    }
    // Initialize decipher
    const decipher = createDecipheriv('aes-256-ctr', key, ivFormatted)
    // Loop through ciphertext and decrypt then return
    const data = new Array<Uint8Array>(ciphertext.data.length)
    for (let i = 0; i < ciphertext.data.length; i += 1) {
      data[i] = decipher.update(new Uint8Array(ciphertext.data[i]!))
    }
    decipher.final()
    return data
  }
}

export { AES, }
export type { Ciphertext, CiphertextCTR }
