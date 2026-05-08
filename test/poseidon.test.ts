import assert from 'node:assert/strict'
import { test } from 'node:test'

import type { CryptographyError } from '../src/index'
import { initCircomlib, poseidon, poseidonBuild, poseidonFunc } from '../src/index'

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
