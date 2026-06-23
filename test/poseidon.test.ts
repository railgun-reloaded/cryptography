import assert from 'node:assert/strict'
import { test } from 'node:test'

import { bigIntToBytes } from '@railgun-reloaded/bytes'

import type { CryptographyError } from '../src/index.js'
import { poseidon, poseidonFunc, poseidonHex } from '../src/index.js'

const VECTOR_INPUTS_2 = [
  '0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a',
  '0x2a92a4c8d7c21d97d946951043d11954de794cd506093dbbb97ada64c14b203b',
] as const
const VECTOR_HASH_2 = '106dc6dc79863b23dc1a63c7ca40e8c22bb830e449b75a2286c7f7b0b87ae6c3'

test('poseidonFunc matches known test vector with bigint output', () => {
  const result = poseidonFunc([...VECTOR_INPUTS_2], true) as bigint
  assert.equal(result.toString(16).padStart(64, '0'), VECTOR_HASH_2)
})

test('poseidonFunc accepts bigint, number, string, and Uint8Array inputs', () => {
  assert.ok(poseidonFunc([1n, 2n, 3n], true), 'bigint inputs')
  assert.ok(poseidonFunc([1, 2, 3], true), 'number inputs')
  assert.ok(poseidonFunc(['1', '2', '3'], true), 'string inputs')
  assert.ok(
    poseidonFunc([new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3])], true),
    'Uint8Array inputs'
  )
})

test('poseidonFunc returns Uint8Array by default and bigint when requested', () => {
  assert.ok((poseidonFunc([1n, 2n]) as Uint8Array) instanceof Uint8Array)
  assert.equal(typeof poseidonFunc([1n, 2n], true), 'bigint')
})

test('poseidonFunc throws InvalidInputCount for length outside 1..14', () => {
  assert.throws(
    () => poseidonFunc([]),
    { name: 'CryptographyError', code: 'InvalidInputCount' satisfies CryptographyError['code'] }
  )
  assert.throws(
    () => poseidonFunc(new Array(15).fill(1n)),
    { name: 'CryptographyError', code: 'InvalidInputCount' satisfies CryptographyError['code'] }
  )
})

test('poseidonFunc throws NullInput for null or undefined elements', () => {
  assert.throws(
    () => poseidonFunc([1n, null as unknown as bigint]),
    { name: 'CryptographyError', code: 'NullInput' satisfies CryptographyError['code'] }
  )
  assert.throws(
    () => poseidonFunc([1n, undefined as unknown as bigint]),
    { name: 'CryptographyError', code: 'NullInput' satisfies CryptographyError['code'] }
  )
})

test('poseidonFunc throws InvalidInputType for unsupported element types', () => {
  assert.throws(
    () => poseidonFunc([{} as unknown as bigint]),
    { name: 'CryptographyError', code: 'InvalidInputType' satisfies CryptographyError['code'] }
  )
})

test('poseidonFunc supports nOuts > 1 in both representations', () => {
  const bigintOut = poseidonFunc([1n, 2n, 3n], true, 2)
  assert.ok(Array.isArray(bigintOut), 'bigint outputs are an array')
  assert.equal((bigintOut as bigint[]).length, 2)
  assert.ok((bigintOut as bigint[]).every((v) => typeof v === 'bigint'))

  const bytesOut = poseidonFunc([1n, 2n, 3n], false, 2)
  assert.ok(Array.isArray(bytesOut), 'bytes outputs are an array')
  assert.equal((bytesOut as Uint8Array[]).length, 2)
  assert.ok((bytesOut as Uint8Array[]).every((v) => v instanceof Uint8Array))
})

test('poseidonFunc does not mutate the input array', () => {
  const inputs: (bigint | Uint8Array)[] = [new Uint8Array([1]), 2n, new Uint8Array([3])]
  const snapshot = inputs.map((v) => (v instanceof Uint8Array ? new Uint8Array(v) : v))
  poseidonFunc(inputs)
  assert.deepEqual(inputs[0], snapshot[0] as Uint8Array)
  assert.equal(inputs[1], snapshot[1])
  assert.deepEqual(inputs[2], snapshot[2] as Uint8Array)
})

test('poseidon returns a 32-byte hash for valid Uint8Array inputs', () => {
  const result = poseidon([new Uint8Array([1]), new Uint8Array([2])])
  assert.ok(result instanceof Uint8Array)
  assert.equal(result.length, 32)
})

const POSEIDON_HEX_0_1 = '1bd20834f5de9830c643778a2e88a3a1363c8b9ac083d36d75bf87c49953e65e'

test('poseidonHex matches engine vectors regardless of input format', () => {
  assert.equal(poseidonHex(['0', '1']), POSEIDON_HEX_0_1, 'unprefixed single-digit hex')
  assert.equal(poseidonHex(['00', '01']), POSEIDON_HEX_0_1, 'unprefixed even-length hex')
  assert.equal(poseidonHex(['0x0', '0x1']), POSEIDON_HEX_0_1, '0x-prefixed odd-length hex')
  assert.equal(poseidonHex(['0x00', '0x01']), POSEIDON_HEX_0_1, '0x-prefixed even-length hex')
})

test('poseidonHex returns a 64-character lowercase hex string', () => {
  const result = poseidonHex(['0x1', '0x2'])
  assert.equal(result.length, 64)
  assert.equal(result, result.toLowerCase())
})

// Canonical Poseidon (BabyJubJub) reference vectors from iden3/circomlibjs's
// own test suite. The field-element (`poseidonFunc`), hex (`poseidonHex`) and
// byte (`poseidon`) paths must all agree with these.
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
  test(`poseidonFunc matches circomlibjs reference (${v.inputs.length} inputs)`, () => {
    const got = poseidonFunc([...v.inputs], true) as bigint
    assert.equal(got, v.expected)
  })

  test(`poseidonHex matches circomlibjs reference (${v.inputs.length} inputs)`, () => {
    const got = poseidonHex(v.inputs.map((x) => '0x' + x.toString(16)))
    assert.equal(got, v.expected.toString(16).padStart(64, '0'))
  })

  test(`poseidon (bytes) matches circomlibjs reference (${v.inputs.length} inputs)`, () => {
    const got = poseidon(v.inputs.map((x) => bigIntToBytes(x, 32)))
    assert.deepEqual(got, bigIntToBytes(v.expected, 32))
  })
}
