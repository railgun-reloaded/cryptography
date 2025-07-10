// @ts-ignore -- ignore typecheck.
import { buildEddsa } from 'circomlibjs'

const eddsaBuild = {
  ed: null
}
/**
 * Initializes the EdDSA cryptographic primitive by asynchronously building its instance.
 * This function waits for the EdDSA instance to be constructed and assigns it to `eddsaBuild.ed`.
 * @async
 * @param injectPoseidon - An optional parameter to inject a custom Poseidon implementation. 
 *                         If not provided, the default implementation will be used.
 * @throws {Error} If the EdDSA instance fails to build.
 */
const initializeEddsa = async (injectPoseidon?: any) => {
  const eddsaPromise = buildEddsa(injectPoseidon)
  eddsaBuild.ed = await eddsaPromise
}
export { initializeEddsa, eddsaBuild }
