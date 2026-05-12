import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { test } from 'node:test'

import { bytesToHex, hexToBytes } from '@noble/hashes/utils'

import { BABYJUBJUB_SUBGROUP_ORDER, eddsa, initCircomlib, initializeEddsa } from '../src/index'

/**
 * Decodes a big-endian byte array as an unsigned bigint.
 * @param b - big-endian encoded bytes
 * @returns the decoded value as a `bigint`
 */
const bytesToBig = (b: Uint8Array): bigint => BigInt('0x' + bytesToHex(b))

/**
 * Encodes an unsigned bigint as a 32-byte big-endian `Uint8Array`.
 * @param v - non-negative `bigint` that fits in 32 bytes
 * @returns the 32-byte big-endian encoding
 */
const bigToBytesBE = (v: bigint): Uint8Array => hexToBytes(v.toString(16).padStart(64, '0'))

// Non-identity points in the 8-torsion subgroup of BabyJubJub (cofactor 8).
// Order 1 (identity) is exercised separately by the R8 = (0, 1) test above.
// Source: enumerated via circomlibjs babyJub by multiplying the full-order
// generator by subOrder and iterating doublings.
const BABYJUBJUB_SMALL_SUBGROUP_POINTS: ReadonlyArray<[bigint, bigint]> = [
  // order 8
  [
    4342719913949491028786768530115087822524712248835451589697801404893164183326n,
    4826523245007015323400664741523384119579596407052839571721035538011798951543n,
  ],
  // order 4
  [
    18930368022820495955728484915491405972470733850014661777449844430438130630919n,
    0n,
  ],
  // order 2 = (0, -1 mod p)
  [
    0n,
    21888242871839275222246405745257275088548364400416034343698204186575808495616n,
  ],
]

test('eddsa: signPoseidon roundtrip verifies under verifyEDDSA', async () => {
  await initCircomlib('pure')
  await initializeEddsa()

  const privateKey = new Uint8Array(randomBytes(32))
  const message = new Uint8Array(randomBytes(32))
  const pubKey = eddsa.privateKeyToPublicKey(privateKey)
  const signature = eddsa.signPoseidon(privateKey, message)

  assert.equal(signature.length, 3, 'signature is a 3-tuple [R8x, R8y, S]')

  const verified = eddsa.verifyEDDSA(
    message,
    {
      R8: [signature[0]!, signature[1]!],
      S: BigInt('0x' + bytesToHex(signature[2]!)),
    },
    pubKey
  )
  assert.ok(verified, 'signature verifies under the matching public key')
})

test('eddsa: verifyEDDSA does not mutate signature or pubkey arrays', async () => {
  await initCircomlib('pure')
  await initializeEddsa()

  const privateKey = new Uint8Array(randomBytes(32))
  const message = new Uint8Array(randomBytes(32))
  const pubKey = eddsa.privateKeyToPublicKey(privateKey)
  const signature = eddsa.signPoseidon(privateKey, message)

  const sigSnapshot: [Uint8Array, Uint8Array] = [
    new Uint8Array(signature[0]!),
    new Uint8Array(signature[1]!),
  ]
  const pubSnapshot: [Uint8Array, Uint8Array] = [
    new Uint8Array(pubKey[0]),
    new Uint8Array(pubKey[1]),
  ]

  const sBigInt = BigInt('0x' + bytesToHex(signature[2]!))
  eddsa.verifyEDDSA(message, { R8: [signature[0]!, signature[1]!], S: sBigInt }, pubKey)

  assert.deepEqual(signature[0], sigSnapshot[0], 'R8x not mutated')
  assert.deepEqual(signature[1], sigSnapshot[1], 'R8y not mutated')
  assert.deepEqual(pubKey[0], pubSnapshot[0], 'pubKey x not mutated')
  assert.deepEqual(pubKey[1], pubSnapshot[1], 'pubKey y not mutated')

  // Second verify call must still succeed — would fail if the first call corrupted inputs.
  const second = eddsa.verifyEDDSA(message, { R8: [signature[0]!, signature[1]!], S: sBigInt }, pubKey)
  assert.ok(second, 'second verify still succeeds')
})

test('eddsa: known public key from a fixed input', async () => {
  await initCircomlib('pure')
  await initializeEddsa()

  const input = new Uint8Array([
    207, 255, 35, 123, 225, 202, 70, 139,
    250, 120, 235, 158, 5, 168, 39, 1,
    112, 61, 67, 88, 24, 249, 103, 47,
    111, 29, 181, 35, 120, 93, 148, 41,
  ])
  const expected: [Uint8Array, Uint8Array] = [
    new Uint8Array([
      30, 223, 15, 39, 142, 51, 141, 235,
      7, 92, 200, 201, 5, 67, 246, 241,
      209, 89, 11, 252, 121, 116, 202, 28,
      218, 122, 231, 182, 229, 49, 49, 109,
    ]),
    new Uint8Array([
      1, 43, 134, 211, 238, 155, 36, 192,
      38, 46, 63, 206, 87, 145, 249, 254,
      9, 193, 223, 88, 129, 152, 98, 172,
      138, 129, 97, 26, 93, 174, 178, 235,
    ]),
  ]
  const result = eddsa.privateKeyToPublicKey(input)
  assert.deepEqual(result[0], expected[0])
  assert.deepEqual(result[1], expected[1])
})

// Canonical EdDSA-Poseidon over BabyJubJub reference vector from iden3/circomlibjs.
// Source: https://github.com/iden3/circomlibjs/blob/main/test/eddsa.js
//   "Sign (using Poseidon) a single 10 bytes from 0 to 9"
//
// Encoding note: the upstream test passes the message as a field element
// derived from `Scalar.fromRprLE(msgBuf, 0)` on the bytes 00..09,00,00.
// Our `signPoseidon` takes raw bytes, reverses them, then runs `toMontgomery`
// — so the equivalent input is the 32-byte big-endian encoding of that same
// scalar (20 leading zero bytes followed by the LE bytes reversed).
test('eddsa: signs canonical circomlibjs reference vector', async () => {
  await initCircomlib('pure')
  await initializeEddsa()

  const privateKey = hexToBytes('0001020304050607080900010203040506070809000102030405060708090001')
  const message = hexToBytes('0000000000000000000000000000000000000000000009080706050403020100')

  const expectedPubX = 13277427435165878497778222415993513565335242147425444199013288855685581939618n
  const expectedPubY = 13622229784656158136036771217484571176836296686641868549125388198837476602820n
  const expectedR8x = 11384336176656855268977457483345535180380036354188103142384839473266348197733n
  const expectedR8y = 15383486972088797283337779941324724402501462225528836549661220478783371668959n
  const expectedS = 1672775540645840396591609181675628451599263765380031905495115170613215233181n

  const pubKey = eddsa.privateKeyToPublicKey(privateKey)
  assert.equal(bytesToBig(pubKey[0]), expectedPubX, 'pubkey x matches')
  assert.equal(bytesToBig(pubKey[1]), expectedPubY, 'pubkey y matches')

  const signature = eddsa.signPoseidon(privateKey, message)
  assert.equal(bytesToBig(signature[0]), expectedR8x, 'signature R8x matches')
  assert.equal(bytesToBig(signature[1]), expectedR8y, 'signature R8y matches')
  assert.equal(bytesToBig(signature[2]), expectedS, 'signature S matches')

  const verified = eddsa.verifyEDDSA(
    message,
    { R8: [signature[0], signature[1]], S: bytesToBig(signature[2]) },
    pubKey
  )
  assert.ok(verified, 'canonical signature verifies under the matching public key')
})

// Classic EdDSA forgery attempt: submit S=0. For S=0 the verification equation
// reduces to R = -h·A, so an attacker without the private key cannot satisfy
// it for an arbitrary R (and certainly not with R = the public key, R = a
// real signature's R8, or random points). A verifier that accepts S=0 is
// catastrophically broken — anyone could forge signatures.
test('eddsa: rejects forged signature with S=0', async () => {
  await initCircomlib('pure')
  await initializeEddsa()

  const privateKey = new Uint8Array(randomBytes(32))
  const message = new Uint8Array(randomBytes(32))
  const pubKey = eddsa.privateKeyToPublicKey(privateKey)

  // R8 = the public key itself (a valid curve point) is a convenient
  // attacker-controllable choice that doesn't require crafting a point.
  assert.ok(
    !eddsa.verifyEDDSA(message, { R8: pubKey, S: 0n }, pubKey),
    'S=0 with R8=pubKey must not verify'
  )

  // Also try with the R8 from a genuine signature — same message/key, but
  // S replaced by 0. The honest R8 won't satisfy the verification equation
  // against S=0 either.
  const realSig = eddsa.signPoseidon(privateKey, message)
  assert.ok(
    !eddsa.verifyEDDSA(message, { R8: [realSig[0], realSig[1]], S: 0n }, pubKey),
    'S=0 with honest R8 must not verify'
  )
})

// A valid EdDSA signature must have S ∈ [0, L). A verifier that does
// unchecked mod-L arithmetic on S would accept S ± kL — two distinct (R, S)
// pairs verifying the same message breaks anti-replay assumptions. Also,
// circomlibjs's verifyPoseidon infinite-loops on negative S, so our wrapper
// validates the range up-front to close both the malleability gap and a DOS
// vector.
test('eddsa: rejects malleated signature with S out of range', async () => {
  await initCircomlib('pure')
  await initializeEddsa()

  const privateKey = new Uint8Array(randomBytes(32))
  const message = new Uint8Array(randomBytes(32))
  const pubKey = eddsa.privateKeyToPublicKey(privateKey)
  const sig = eddsa.signPoseidon(privateKey, message)
  const S = bytesToBig(sig[2])

  assert.ok(S < BABYJUBJUB_SUBGROUP_ORDER, 'precondition: real S is in [0, L)')
  /**
   * Verifies the honest `(R8, pubKey, message)` triple after swapping in a
   * mutated `S`. Used to assert that out-of-range `S` values are rejected.
   * @param mutatedS - candidate `S` scalar to substitute into the signature
   * @returns `true` only if the verifier accepts the malleated signature
   */
  const verifyWithS = (mutatedS: bigint) =>
    eddsa.verifyEDDSA(message, { R8: [sig[0], sig[1]], S: mutatedS }, pubKey)

  assert.ok(!verifyWithS(S + BABYJUBJUB_SUBGROUP_ORDER), 'S + L must not verify')
  assert.ok(!verifyWithS(S + 2n * BABYJUBJUB_SUBGROUP_ORDER), 'S + 2L must not verify')
  assert.ok(!verifyWithS(S - BABYJUBJUB_SUBGROUP_ORDER), 'S - L (negative) must not verify')
  assert.ok(!verifyWithS(S - 2n * BABYJUBJUB_SUBGROUP_ORDER), 'S - 2L must not verify')
  assert.ok(!verifyWithS(BABYJUBJUB_SUBGROUP_ORDER), 'S = L (boundary) must not verify')
  assert.ok(!verifyWithS(-1n), 'S = -1 must not verify')
})

test('eddsa: rejects signature verified against a different message', async () => {
  await initCircomlib('pure')
  await initializeEddsa()

  const privateKey = new Uint8Array(randomBytes(32))
  const message = new Uint8Array(randomBytes(32))
  const otherMessage = new Uint8Array(randomBytes(32))
  const pubKey = eddsa.privateKeyToPublicKey(privateKey)
  const sig = eddsa.signPoseidon(privateKey, message)

  assert.ok(
    !eddsa.verifyEDDSA(
      otherMessage,
      { R8: [sig[0], sig[1]], S: bytesToBig(sig[2]) },
      pubKey
    ),
    'verifying against a different message must not succeed'
  )
})

// Forgery attempt with R8 set to the BabyJubJub identity point (0, 1).
// With R8 = O the verification equation reduces to S·B = h·A, which a
// forger can only satisfy by knowing the private key (S = h·sk mod L).
// A verifier that skips proper point checks could still accept this with
// crafted S, so we exercise a few candidate S values an attacker might try.
test('eddsa: rejects forgery with R8 = identity point', async () => {
  await initCircomlib('pure')
  await initializeEddsa()

  const privateKey = new Uint8Array(randomBytes(32))
  const message = new Uint8Array(randomBytes(32))
  const pubKey = eddsa.privateKeyToPublicKey(privateKey)
  const realSig = eddsa.signPoseidon(privateKey, message)

  // BabyJubJub identity in our API's 32-byte big-endian encoding: x = 0, y = 1.
  const identityX = new Uint8Array(32)
  const identityY = new Uint8Array(32)
  identityY[31] = 1
  const identityR8: [Uint8Array, Uint8Array] = [identityX, identityY]

  /**
   * Verifies a candidate signature whose `R8` is the BabyJubJub identity,
   * parameterised by the scalar `S`.
   * @param S - candidate `S` scalar to pair with `R8 = O`
   * @returns `true` only if the verifier accepts the crafted signature
   */
  const verifyWithIdentityR8 = (S: bigint) =>
    eddsa.verifyEDDSA(message, { R8: identityR8, S }, pubKey)

  assert.ok(!verifyWithIdentityR8(0n), 'R8 = O, S = 0 must not verify')
  assert.ok(!verifyWithIdentityR8(1n), 'R8 = O, S = 1 must not verify')
  assert.ok(!verifyWithIdentityR8(bytesToBig(realSig[2])), 'R8 = O with honest S must not verify')
})

// Small-subgroup R8 attack. BabyJubJub has cofactor 8 — a weak verifier that
// doesn't enforce prime-order subgroup membership on R8 could be tricked
// into accepting forgeries with R8 chosen from the 8-torsion. circomlibjs
// uses cofactored verification with Base8, so these should all be rejected.
test('eddsa: rejects forgery with R8 in BabyJubJub small subgroup', async () => {
  await initCircomlib('pure')
  await initializeEddsa()

  const privateKey = new Uint8Array(randomBytes(32))
  const message = new Uint8Array(randomBytes(32))
  const pubKey = eddsa.privateKeyToPublicKey(privateKey)
  const realSig = eddsa.signPoseidon(privateKey, message)

  for (const [x, y] of BABYJUBJUB_SMALL_SUBGROUP_POINTS) {
    const R8: [Uint8Array, Uint8Array] = [bigToBytesBE(x), bigToBytesBE(y)]
    for (const S of [0n, 1n, bytesToBig(realSig[2])]) {
      assert.ok(
        !eddsa.verifyEDDSA(message, { R8, S }, pubKey),
        `R8 in small subgroup with S=${S} must not verify`
      )
    }
  }
})

// Small-subgroup pubkey attack. An attacker claiming a public key in the
// 8-torsion has only 8 possible h·A values (since A has order ≤ 8), making
// the verification equation cheap to satisfy by exhaustive search of S.
// A correct cofactored verifier rejects these regardless of the S value tried.
test('eddsa: rejects forgery with pubkey in BabyJubJub small subgroup', async () => {
  await initCircomlib('pure')
  await initializeEddsa()

  const message = new Uint8Array(randomBytes(32))

  for (const [x, y] of BABYJUBJUB_SMALL_SUBGROUP_POINTS) {
    const subgroupPub: [Uint8Array, Uint8Array] = [bigToBytesBE(x), bigToBytesBE(y)]
    // Try crafted R8 (= the same subgroup point) and varied S — an attacker
    // would try to satisfy a tiny equation system. None should verify.
    for (const S of [0n, 1n, 2n, 12345n, BABYJUBJUB_SUBGROUP_ORDER - 1n]) {
      assert.ok(
        !eddsa.verifyEDDSA(message, { R8: subgroupPub, S }, subgroupPub),
        `small-subgroup pubkey with R8=same, S=${S} must not verify`
      )
    }
  }
})

// Identity-pubkey attack. With A = O the cofactored term 8·h·A vanishes, so
// the verification equation collapses to S·Base8 = R8 — independent of the
// message or the hash. Any attacker who can supply pubkey = O can forge by
// choosing S and computing R8 = S·Base8 (trivially S = 0, R8 = O). A correct
// verifier must reject identity pubkeys; circomlibjs's inCurve check passes
// (0, 1), so this relies on additional defenses.
test('eddsa: rejects forgery with pubkey = identity point', async () => {
  await initCircomlib('pure')
  await initializeEddsa()

  const message = new Uint8Array(randomBytes(32))
  const identityX = new Uint8Array(32)
  const identityY = new Uint8Array(32)
  identityY[31] = 1
  const identityPub: [Uint8Array, Uint8Array] = [identityX, identityY]

  // Crafted attack: S = 0, R8 = O satisfies S·Base8 = R8 = O.
  assert.ok(
    !eddsa.verifyEDDSA(message, { R8: identityPub, S: 0n }, identityPub),
    'pubkey = O with R8 = O, S = 0 must not verify'
  )

  // Honest signature material with pubkey swapped to identity — hm depends
  // on pubkey so the relation breaks; this should clearly reject.
  const realPrivate = new Uint8Array(randomBytes(32))
  const realSig = eddsa.signPoseidon(realPrivate, message)
  assert.ok(
    !eddsa.verifyEDDSA(
      message,
      { R8: [realSig[0], realSig[1]], S: bytesToBig(realSig[2]) },
      identityPub
    ),
    'pubkey = O with honest sig material must not verify'
  )

  // Naive S values with R8 = O. Only S = 0 satisfies the equation; the
  // others are guarded against accidental acceptance.
  for (const S of [1n, 2n, 12345n, BABYJUBJUB_SUBGROUP_ORDER - 1n]) {
    assert.ok(
      !eddsa.verifyEDDSA(message, { R8: identityPub, S }, identityPub),
      `pubkey = O with R8 = O, S = ${S} must not verify`
    )
  }
})

// Off-curve point attacks. The all-zero encoding (0, 0) is not a BabyJubJub
// point — circomlibjs's inCurve check should reject it for both R8 and A.
// We pin that behavior so a future refactor that bypasses inCurve cannot
// silently regress.
test('eddsa: rejects verification with R8 = (0, 0) off-curve bytes', async () => {
  await initCircomlib('pure')
  await initializeEddsa()

  const privateKey = new Uint8Array(randomBytes(32))
  const message = new Uint8Array(randomBytes(32))
  const pubKey = eddsa.privateKeyToPublicKey(privateKey)
  const realSig = eddsa.signPoseidon(privateKey, message)

  const zeroR8: [Uint8Array, Uint8Array] = [new Uint8Array(32), new Uint8Array(32)]
  for (const S of [0n, 1n, bytesToBig(realSig[2]), BABYJUBJUB_SUBGROUP_ORDER - 1n]) {
    assert.ok(
      !eddsa.verifyEDDSA(message, { R8: zeroR8, S }, pubKey),
      `R8 = (0, 0) off-curve with S = ${S} must not verify`
    )
  }
})

test('eddsa: rejects verification with pubkey = (0, 0) off-curve bytes', async () => {
  await initCircomlib('pure')
  await initializeEddsa()

  const privateKey = new Uint8Array(randomBytes(32))
  const message = new Uint8Array(randomBytes(32))
  const realSig = eddsa.signPoseidon(privateKey, message)

  const zeroPub: [Uint8Array, Uint8Array] = [new Uint8Array(32), new Uint8Array(32)]
  for (const S of [0n, 1n, bytesToBig(realSig[2]), BABYJUBJUB_SUBGROUP_ORDER - 1n]) {
    assert.ok(
      !eddsa.verifyEDDSA(
        message,
        { R8: [realSig[0], realSig[1]], S },
        zeroPub
      ),
      `pubkey = (0, 0) off-curve with S = ${S} must not verify`
    )
  }
})

test('eddsa: rejects signature verified under a different public key', async () => {
  await initCircomlib('pure')
  await initializeEddsa()

  const privateKey = new Uint8Array(randomBytes(32))
  const otherPrivateKey = new Uint8Array(randomBytes(32))
  const message = new Uint8Array(randomBytes(32))
  const otherPubKey = eddsa.privateKeyToPublicKey(otherPrivateKey)
  const sig = eddsa.signPoseidon(privateKey, message)

  assert.ok(
    !eddsa.verifyEDDSA(
      message,
      { R8: [sig[0], sig[1]], S: bytesToBig(sig[2]) },
      otherPubKey
    ),
    'verifying under a different pubkey must not succeed'
  )
})
