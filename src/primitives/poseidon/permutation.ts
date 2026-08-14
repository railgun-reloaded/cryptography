import { Field } from '@noble/curves/abstract/modular.js'
import { grainGenConstants, poseidon as noblePoseidon } from '@noble/curves/abstract/poseidon.js'

import { CryptographyError } from '../errors.js'

/**
 * The circomlib-compatible Poseidon permutation over BabyJubJub, built on
 * `@noble/curves`.
 *
 * Round constants and the MDS matrix are *derived*, not vendored: circomlib
 * generated its tables with the reference Grain LFSR script
 * (`generate_parameters_grain.sage 1 0 254 t 8 R_P 0x30644e72...`), and noble's
 * `grainGenConstants` reproduces that output exactly at `skipMDS = 0`. Deriving
 * them keeps ~850 KB of opaque tables out of the bundle and puts both the
 * permutation and the constant generator inside the audited surface of
 * `@noble/curves/abstract/poseidon.js`.
 *
 * The tradeoff is that derived constants could in principle drift if the
 * upstream generator changed, which would silently alter every hash. To make
 * that impossible to miss, each arity is checked against a pinned digest the
 * first time it is built; a mismatch throws rather than returning wrong data.
 */

const Fp = /* @__PURE__ */ Field(
  21888242871839275222246405745257275088548364400416034343698204186575808495617n
)

// Full rounds are fixed at 8; partial rounds vary with width t = arity + 1.
// Values from the Poseidon paper (table 2/8) as used by circomlib.
const ROUNDS_FULL = 8
const ROUNDS_PARTIAL = [
  56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
] as const

const MIN_ARITY = 1
const MAX_ARITY = 14

// Poseidon(1..n) for each supported arity, captured from the circomlib-derived
// reference implementation. Verified once per arity at construction time; a
// mismatch means the generated constants no longer match circomlib.
const SELF_CHECK_DIGESTS = [
  18586133768512220936620570745912940619677854269274689475585506675881198879027n,
  7853200120776062878684798364095072458815029376092732009249414926327459813530n,
  6542985608222806190361240322586112750744169038454362455181422643027100751666n,
  18821383157269793795438455681495246036402687001665670618754263018637548127333n,
  6183221330272524995739186171720101788151706631170188140075976616310159254464n,
  20400040500897583745843009878988256314335038853985262692600694741116813247201n,
  12748163991115452309045839028154629052133952896122405799815156419278439301912n,
  18604317144381847857886385684060986177838410221561136253933256952257712543953n,
  13589767895268936107593642967621470491511464502761040466226072462545218539640n,
  3657500514307717306974218405144578736633140001277925127187636780142269815841n,
  3572015662710076994097916907865950486270383304442561406230608893458731714472n,
  2501997477381648492950318384533644783248002172679259592360114615426357826485n,
  7041832639553862712666971417715061873827921493498355005117622707743491651590n,
  8354478399926161176778659061636406690034081872658507739535256090879947077494n,
] as const

type Permutation = (state: bigint[]) => bigint[]

// Constant generation costs ~7-32 ms depending on width, so each arity is
// built at most once and reused.
const cache = new Map<number, Permutation>()

/**
 * Build the permutation for a given width, deriving its constants.
 * @param arity - Number of hash inputs; width is `arity + 1`.
 * @returns The permutation over a `t`-element state vector.
 * @throws CryptographyError(PoseidonConstantMismatch) if the derived constants
 *         do not reproduce the pinned reference digest for this arity.
 */
const buildPermutation = (arity: number): Permutation => {
  const t = arity + 1
  const roundsPartial = ROUNDS_PARTIAL[t - 2]!
  const opts = {
    Fp,
    t,
    roundsFull: ROUNDS_FULL,
    roundsPartial,
    sboxPower: 5,
    // circomlib applies the partial-round S-box to state[0], not state[t-1].
    reversePartialPowIdx: false,
  }

  // skipMDS = 0 is what circomlib's parameter script used.
  const permutation = noblePoseidon({ ...opts, ...grainGenConstants(opts, 0) })

  const probe = Array.from({ length: arity }, (_, i) => BigInt(i + 1))
  if (permutation([0n, ...probe])[0] !== SELF_CHECK_DIGESTS[arity - 1]) {
    throw new CryptographyError(
      'PoseidonConstantMismatch',
      `Derived Poseidon constants for arity ${arity} do not match the pinned ` +
      'circomlib reference digest. Refusing to produce hashes that would be ' +
      'incompatible with the RAILGUN circuits.'
    )
  }

  return permutation
}

/**
 * Compute the circomlib-compatible Poseidon hash of one or more field elements.
 * @param inputs - Between 1 and 14 field elements.
 * @param nOuts - Number of state elements to return. Defaults to 1.
 * @returns The first `nOuts` elements of the permuted state.
 * @throws CryptographyError(InvalidInputCount) if `inputs.length` is outside 1..14.
 */
const poseidonPermute = (inputs: bigint[], nOuts: number = 1): bigint[] => {
  const arity = inputs.length
  if (arity < MIN_ARITY || arity > MAX_ARITY) {
    throw new CryptographyError(
      'InvalidInputCount',
      `Poseidon function index must be between ${MIN_ARITY} and ${MAX_ARITY}`
    )
  }

  let permutation = cache.get(arity)
  if (permutation === undefined) {
    permutation = buildPermutation(arity)
    cache.set(arity, permutation)
  }

  return permutation([0n, ...inputs]).slice(0, nOuts)
}

export { poseidonPermute, MIN_ARITY, MAX_ARITY }
