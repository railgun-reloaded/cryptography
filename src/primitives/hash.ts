import { sha256 as nobleSha256 } from '@noble/hashes/sha2'

/**
 * SHA-256 of a byte sequence.
 *
 * Thin wrapper over `@noble/hashes/sha2` so consumers import from
 * `@railgun-reloaded/cryptography` rather than reaching into `@noble`
 * directly. Behavior is bitwise identical to `@noble/hashes/sha2.sha256`.
 * @param data - Input bytes to hash.
 * @returns 32-byte SHA-256 digest.
 */
function sha256 (data: Uint8Array): Uint8Array {
  return nobleSha256(data)
}

export { sha256 }
