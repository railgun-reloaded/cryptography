import { ctr, gcm } from '@noble/ciphers/aes.js'
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
 * Concatenate a list of byte blocks into a single contiguous buffer.
 * @param blocks - Blocks to join in order.
 * @returns A new buffer holding every block back to back.
 */
const concatBlocks = (blocks: Uint8Array[]): Uint8Array => {
  let length = 0
  for (const block of blocks) {
    length += block.byteLength
  }

  const joined = new Uint8Array(length)
  let offset = 0
  for (const block of blocks) {
    joined.set(block, offset)
    offset += block.byteLength
  }

  return joined
}

/**
 * Split a buffer back into freshly-owned blocks matching the given lengths.
 * @param buffer - Contiguous buffer to slice.
 * @param lengths - Byte length of each output block, in order.
 * @returns One block per length, each a standalone copy.
 */
const splitBlocks = (buffer: Uint8Array, lengths: number[]): Uint8Array[] => {
  const blocks: Uint8Array[] = []
  let offset = 0
  for (const length of lengths) {
    blocks.push(buffer.slice(offset, offset + length))
    offset += length
  }

  return blocks
}

/**
 * AES-256 encryption helpers in GCM (authenticated) and CTR (streaming) modes.
 *
 * All inputs and outputs are `Uint8Array`. Keys must be 32 bytes; IVs are
 * generated internally on encrypt and read from the ciphertext bundle on
 * decrypt. GCM and CTR are counter-mode stream ciphers, so the per-block
 * data layout is preserved by encrypting the concatenated blocks in one shot
 * and re-splitting the result at the original block boundaries.
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
    const sealed = gcm(key, iv).encrypt(concatBlocks(plaintext))

    const tag = sealed.slice(sealed.byteLength - TAG_BYTES)
    const body = sealed.subarray(0, sealed.byteLength - TAG_BYTES)
    const data = splitBlocks(body, plaintext.map((block) => block.byteLength))

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
      const sealed = concatBlocks([...ciphertext.data, ciphertext.tag])
      const plaintext = gcm(key, ciphertext.iv).decrypt(sealed)

      return splitBlocks(plaintext, ciphertext.data.map((block) => block.byteLength))
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
    const body = ctr(key, iv).encrypt(concatBlocks(plaintext))
    const data = splitBlocks(body, plaintext.map((block) => block.byteLength))

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

    const plaintext = ctr(key, ciphertext.iv).decrypt(concatBlocks(ciphertext.data))

    return splitBlocks(plaintext, ciphertext.data.map((block) => block.byteLength))
  }
}

export { AES }
export type { Ciphertext, CiphertextCTR }
