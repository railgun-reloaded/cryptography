// eslint-disable-next-line camelcase
import { keccak_256 } from '@noble/hashes/sha3'

/**
 * Converts a bigint value into a Uint8Array of a specified length.
 * @param value - The bigint value to be converted.
 * @param length - The desired length of the resulting Uint8Array. Defaults to 32 bytes.
 * @returns A Uint8Array representation of the bigint value, padded or truncated to the specified length.
 * This function extracts the least significant 8 bits of the bigint value iteratively
 * and stores them in the Uint8Array. The value is shifted right by 8 bits in each iteration.
 * If the bigint value exceeds the specified length, the higher bits are truncated.
 * If the bigint value is smaller than the specified length, the resulting Uint8Array is zero-padded.
 */
const bigintToUint8Array = (value: bigint, length = 32): Uint8Array => {
  const bytes = new Uint8Array(length) // 32 bytes for 256-bit
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(value & 0xffn)// Extract last 8 bits
    value >>= 8n // Shift right by 8 bits
  }
  return bytes
}

/**
 * Converts a Uint8Array into a bigint value.
 * @param uint8Array - The Uint8Array to be converted.
 * @returns A bigint representation of the Uint8Array.
 * This function iterates through each byte of the Uint8Array, shifting the result left by 8 bits
 * and performing a bitwise OR operation with the current byte to construct the bigint value.
 */
const uint8ArrayToBigInt = (uint8Array: Uint8Array): bigint => {
  let result = BigInt(0)
  for (const byte of uint8Array) {
    result = (result << BigInt(8)) | BigInt(byte)
  }
  return result
}

/**
 * Computes the Keccak-256 hash of the given input bytes.
 * @param bytes - The input data as a Uint8Array to be hashed.
 * @returns A Uint8Array containing the Keccak-256 hash of the input.
 */
const keccak256 = (bytes: Uint8Array): Uint8Array => {
  return keccak_256(bytes)
}

export { bigintToUint8Array, uint8ArrayToBigInt, keccak256 }
