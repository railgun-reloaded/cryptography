import { sha256 as nobleSha256 } from '@noble/hashes/sha2'

/**
 * SHA-256 hash of a byte sequence.
 *
 * Thin wrapper over @noble/hashes/sha2 so consumers import from
 * `@railgun-reloaded/cryptography` rather than reaching into @noble directly.
 */
function sha256 (data: Uint8Array): Uint8Array {
  return nobleSha256(data)
}

export { sha256 }
