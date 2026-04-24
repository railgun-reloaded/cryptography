// eslint-disable-next-line camelcase
import { keccak_256 } from '@noble/hashes/sha3'

/**
 * Computes the Keccak-256 hash of the given input bytes.
 * @param bytes - The input data as a Uint8Array to be hashed.
 * @returns A Uint8Array containing the Keccak-256 hash of the input.
 */
const keccak256 = (bytes: Uint8Array): Uint8Array => {
  return keccak_256(bytes)
}

export { keccak256 }
