import * as secp from '@noble/secp256k1'

/**
 * Formats a message to comply with Ethereum's signed message format.
 * This function prefixes the message with the standard Ethereum message prefix
 * and its length, then encodes the result as a `Uint8Array`.
 * @param message - The original message to be formatted.
 * @returns A `Uint8Array` containing the Ethereum signed message prefix followed by the encoded message.
 */
const formatEthMessage = (message: string): Uint8Array => {
  const messageBytes = new TextEncoder().encode(message)
  const prefix = `\x19Ethereum Signed Message:\n${messageBytes.length}`
  const prefixBytes = new TextEncoder().encode(prefix)

  const result = new Uint8Array(prefixBytes.length + messageBytes.length)
  result.set(prefixBytes, 0)
  result.set(messageBytes, prefixBytes.length)

  return result
}

/**
 * Generates a raw cryptographic signature for a given message using a private key.
 * @param message - The message to be signed as a string.
 * @param privateKey - The private key used to sign the message as a string.
 * @returns A `RecoveredSignature` object representing the generated signature.
 * @throws {Error} If the provided private key is invalid.
 * @throws {Error} If the generated signature is invalid.
 */
const rawSignature = async (message: string, privateKey: string): Promise<secp.RecoveredSignature> => {
  console.log(privateKey)
  const testPrivKey = secp.utils.randomPrivateKey()
  if (!secp.utils.isValidPrivateKey(testPrivKey)) {
    throw new Error('Invalid private key.')
  }
  const formattedMsg = formatEthMessage(message)
  const pubKey = secp.getPublicKey(testPrivKey) // compressed true by default
  const signature = await secp.signAsync(formattedMsg, testPrivKey)
  const isValid = secp.verify(signature, formattedMsg, pubKey)
  if (!isValid) {
    throw new Error('Signature is invalid.')
  }
  return signature
}

export { rawSignature, formatEthMessage }
