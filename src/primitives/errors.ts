/**
 * String-union of every error code this package can throw. Used as the
 * discriminator on `CryptographyError`. Adding a new failure mode is one
 * entry here plus the corresponding `throw` site — no new class scaffolding.
 */
type CryptographyErrorCode =
  | 'InvalidKeyLength'
  | 'InvalidIvLength'
  | 'InvalidTagLength'
  | 'DecryptionFailed'
  | 'EddsaNotInitialized'
  | 'PoseidonNotLoaded'
  | 'InvalidInputCount'
  | 'NullInput'
  | 'InvalidInputType'
  | 'InvalidOutputType'

/**
 * The single error class thrown by every helper in this package. Consumers
 * discriminate via `err instanceof CryptographyError && err.code === '<code>'`.
 *
 * Collapsing this to one class with a code field (rather than one subclass
 * per failure mode) keeps the surface and tests small as new modes are added.
 */
class CryptographyError extends Error {
  /**
   * The discriminator identifying which failure mode raised this error.
   */
  readonly code: CryptographyErrorCode

  /**
   * Construct a CryptographyError.
   * @param code - One of the `CryptographyErrorCode` values.
   * @param message - Human-readable error message.
   * @param options - Optional ErrorOptions for chaining a `cause`.
   */
  constructor (code: CryptographyErrorCode, message?: string, options?: ErrorOptions) {
    super(message, options)
    this.name = 'CryptographyError'
    this.code = code
  }
}

export { CryptographyError }
export type { CryptographyErrorCode }
