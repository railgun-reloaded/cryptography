import assert from 'node:assert/strict'
import { test } from 'node:test'

import type { CryptographyError } from '../src/index'
import { initCircomlib, initPoseidon, poseidon, poseidonBuild, poseidonFunc, poseidonHex } from '../src/index'

const VECTOR_INPUTS_2 = [
  '0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a',
  '0x2a92a4c8d7c21d97d946951043d11954de794cd506093dbbb97ada64c14b203b',
] as const
const VECTOR_HASH_2 = '106dc6dc79863b23dc1a63c7ca40e8c22bb830e449b75a2286c7f7b0b87ae6c3'

test('initCircomlib(wasm) populates poseidonBuild.wasm', async () => {
  await initCircomlib('wasm')
  assert.ok(poseidonBuild.wasm, 'wasm build was set')
})

test('initCircomlib(pure) populates poseidonBuild.pure', async () => {
  await initCircomlib('pure')
  assert.ok(poseidonBuild.pure, 'pure build was set')
})

test('poseidonFunc matches known test vector with bigint output', async () => {
  await initCircomlib('wasm')
  const result = poseidonFunc([...VECTOR_INPUTS_2], true) as bigint
  assert.equal(result.toString(16).padStart(64, '0'), VECTOR_HASH_2)
})

test('poseidonFunc accepts bigint, number, string, and Uint8Array inputs', async () => {
  await initCircomlib('wasm')
  assert.ok(poseidonFunc([1n, 2n, 3n], true), 'bigint inputs')
  assert.ok(poseidonFunc([1, 2, 3], true), 'number inputs')
  assert.ok(poseidonFunc(['1', '2', '3'], true), 'string inputs')
  assert.ok(
    poseidonFunc([new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3])], true),
    'Uint8Array inputs'
  )
})

test('poseidonFunc returns Uint8Array by default and bigint when requested', async () => {
  await initCircomlib('wasm')
  assert.ok((poseidonFunc([1n, 2n]) as Uint8Array) instanceof Uint8Array)
  assert.equal(typeof poseidonFunc([1n, 2n], true), 'bigint')
})

test('poseidonFunc throws InvalidInputCount for length outside 1..14', async () => {
  await initCircomlib('wasm')
  assert.throws(
    () => poseidonFunc([]),
    { name: 'CryptographyError', code: 'InvalidInputCount' satisfies CryptographyError['code'] }
  )
  assert.throws(
    () => poseidonFunc(new Array(15).fill(1n)),
    { name: 'CryptographyError', code: 'InvalidInputCount' satisfies CryptographyError['code'] }
  )
})

test('poseidonFunc throws NullInput for null or undefined elements', async () => {
  await initCircomlib('wasm')
  assert.throws(
    () => poseidonFunc([1n, null as unknown as bigint]),
    { name: 'CryptographyError', code: 'NullInput' satisfies CryptographyError['code'] }
  )
  assert.throws(
    () => poseidonFunc([1n, undefined as unknown as bigint]),
    { name: 'CryptographyError', code: 'NullInput' satisfies CryptographyError['code'] }
  )
})

test('poseidonFunc throws InvalidInputType for unsupported element types', async () => {
  await initCircomlib('wasm')
  assert.throws(
    () => poseidonFunc([{} as unknown as bigint]),
    { name: 'CryptographyError', code: 'InvalidInputType' satisfies CryptographyError['code'] }
  )
})

test('poseidonFunc supports nOuts > 1 in both representations', async () => {
  await initCircomlib('wasm')
  const bigintOut = poseidonFunc([1n, 2n, 3n], true, 2)
  assert.ok(Array.isArray(bigintOut), 'bigint outputs are an array')
  assert.equal((bigintOut as bigint[]).length, 2)
  assert.ok((bigintOut as bigint[]).every((v) => typeof v === 'bigint'))

  const bytesOut = poseidonFunc([1n, 2n, 3n], false, 2)
  assert.ok(Array.isArray(bytesOut), 'bytes outputs are an array')
  assert.equal((bytesOut as Uint8Array[]).length, 2)
  assert.ok((bytesOut as Uint8Array[]).every((v) => v instanceof Uint8Array))
})

test('poseidonFunc does not mutate the input array', async () => {
  await initCircomlib('wasm')
  const inputs: (bigint | Uint8Array)[] = [new Uint8Array([1]), 2n, new Uint8Array([3])]
  const snapshot = inputs.map((v) => (v instanceof Uint8Array ? new Uint8Array(v) : v))
  poseidonFunc(inputs)
  assert.deepEqual(inputs[0], snapshot[0] as Uint8Array)
  assert.equal(inputs[1], snapshot[1])
  assert.deepEqual(inputs[2], snapshot[2] as Uint8Array)
})

test('poseidon (circomlibjs) returns 32-byte hash for valid Uint8Array inputs', async () => {
  await initCircomlib('wasm')
  const result = poseidon([new Uint8Array([1]), new Uint8Array([2])])
  assert.ok(result instanceof Uint8Array)
  assert.equal(result.length, 32)
})

test('poseidon throws PoseidonNotLoaded when neither pure nor wasm is loaded', () => {
  const previousWasm = poseidonBuild.wasm
  const previousPure = poseidonBuild.pure
  poseidonBuild.wasm = null
  poseidonBuild.pure = null
  try {
    assert.throws(
      () => poseidon([new Uint8Array([1]), new Uint8Array([2])]),
      { name: 'CryptographyError', code: 'PoseidonNotLoaded' satisfies CryptographyError['code'] }
    )
  } finally {
    poseidonBuild.wasm = previousWasm
    poseidonBuild.pure = previousPure
  }
})

test('poseidon falls back to pure when wasm is unavailable', async () => {
  await initCircomlib('pure')
  const previousWasm = poseidonBuild.wasm
  poseidonBuild.wasm = null
  try {
    const out = poseidon([new Uint8Array([1]), new Uint8Array([2])])
    assert.ok(out instanceof Uint8Array)
    assert.equal(out.length, 32)
  } finally {
    poseidonBuild.wasm = previousWasm
  }
})

const POSEIDON_HEX_0_1 = '1bd20834f5de9830c643778a2e88a3a1363c8b9ac083d36d75bf87c49953e65e'

test('poseidonHex matches engine vectors regardless of input format', async () => {
  await initCircomlib('wasm')
  assert.equal(poseidonHex(['0', '1']), POSEIDON_HEX_0_1, 'unprefixed single-digit hex')
  assert.equal(poseidonHex(['00', '01']), POSEIDON_HEX_0_1, 'unprefixed even-length hex')
  assert.equal(poseidonHex(['0x0', '0x1']), POSEIDON_HEX_0_1, '0x-prefixed odd-length hex')
  assert.equal(poseidonHex(['0x00', '0x01']), POSEIDON_HEX_0_1, '0x-prefixed even-length hex')
})

test('poseidonHex returns a 64-character lowercase hex string', async () => {
  await initCircomlib('wasm')
  const result = poseidonHex(['0x1', '0x2'])
  assert.equal(result.length, 64)
  assert.equal(result, result.toLowerCase())
})

// Canonical Poseidon (BabyJubJub) reference vectors from iden3/circomlibjs's
// own test suite. Both implementation paths used here (poseidon-lite via
// `poseidonFunc`, and circomlibjs via `poseidonHex`) must agree on these.
// Source: https://github.com/iden3/circomlibjs/blob/main/test/poseidon.js
const POSEIDON_REFERENCE_VECTORS = [
  {
    inputs: [1n, 2n],
    expected: 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189an,
  },
  {
    inputs: [1n, 2n, 3n, 4n],
    expected: 0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465n,
  },
  {
    inputs: [1n, 2n, 3n, 4n, 5n, 6n],
    expected: 20400040500897583745843009878988256314335038853985262692600694741116813247201n,
  },
] as const

for (const v of POSEIDON_REFERENCE_VECTORS) {
  test(`poseidonFunc matches circomlibjs reference (${v.inputs.length} inputs)`, async () => {
    await initCircomlib('wasm')
    const got = poseidonFunc([...v.inputs], true) as bigint
    assert.equal(got, v.expected)
  })

  test(`poseidonHex matches circomlibjs reference (${v.inputs.length} inputs)`, async () => {
    await initCircomlib('wasm')
    const got = poseidonHex(v.inputs.map((x) => '0x' + x.toString(16)))
    assert.equal(got, v.expected.toString(16).padStart(64, '0'))
  })
}

/**
 * Encodes a bigint as a 32-byte big-endian `Uint8Array` for use as a
 * Poseidon field-element input.
 * @param v - non-negative `bigint` that fits in 32 bytes
 * @returns the 32-byte big-endian encoding
 */
const bigToBytes32 = (v: bigint): Uint8Array => {
  const out = new Uint8Array(32)
  let x = v
  for (let i = 31; i >= 0 && x > 0n; i--) {
    out[i] = Number(x & 0xffn)
    x >>= 8n
  }
  return out
}

// Cross-backend equivalence: the `poseidon` byte-API dispatches to wasm if
// loaded, else pure. Both backends must produce identical output on the same
// inputs — otherwise a caller's result silently depends on which `initCircomlib`
// was called. We force each backend in turn by nulling the other slot.
for (const v of POSEIDON_REFERENCE_VECTORS) {
  test(`poseidon: pure and wasm backends agree (${v.inputs.length} inputs)`, async () => {
    await initCircomlib('pure')
    await initCircomlib('wasm')
    const padded = v.inputs.map((x) => bigToBytes32(x))
    const expectedBytes = bigToBytes32(v.expected)

    const previousPure = poseidonBuild.pure
    const previousWasm = poseidonBuild.wasm
    try {
      // wasm path: keep wasm, drop pure.
      poseidonBuild.pure = null
      const wasmOut = poseidon(padded)
      poseidonBuild.pure = previousPure

      // pure path: keep pure, drop wasm.
      poseidonBuild.wasm = null
      const pureOut = poseidon(padded)
      poseidonBuild.wasm = previousWasm

      assert.deepEqual(pureOut, wasmOut, 'pure and wasm must produce identical bytes')
      assert.deepEqual(wasmOut, expectedBytes, 'wasm matches reference')
      assert.deepEqual(pureOut, expectedBytes, 'pure matches reference')
    } finally {
      poseidonBuild.pure = previousPure
      poseidonBuild.wasm = previousWasm
    }
  })
}

test('initPoseidon leaves at least one poseidon build loaded', async () => {
  // Reset state so the test exercises the full init path.
  poseidonBuild.wasm = null
  poseidonBuild.pure = null
  await initPoseidon()
  assert.ok(
    poseidonBuild.wasm !== null || poseidonBuild.pure !== null,
    'at least one of pure/wasm is loaded after initPoseidon'
  )
})
