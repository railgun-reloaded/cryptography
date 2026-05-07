import { test } from 'brittle'

import { initCircomlib, poseidon, poseidonBuild, poseidonFunc } from '../src/index'

const VECTOR_INPUTS_2 = [
  '0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a',
  '0x2a92a4c8d7c21d97d946951043d11954de794cd506093dbbb97ada64c14b203b',
] as const
const VECTOR_HASH_2 = '106dc6dc79863b23dc1a63c7ca40e8c22bb830e449b75a2286c7f7b0b87ae6c3'

test('initCircomlib(wasm) populates poseidonBuild.wasm', async (t) => {
  await initCircomlib('wasm')
  t.ok(poseidonBuild.wasm, 'wasm build was set')
})

test('initCircomlib(pure) populates poseidonBuild.pure', async (t) => {
  await initCircomlib('pure')
  t.ok(poseidonBuild.pure, 'pure build was set')
})

test('poseidonFunc matches known test vector with bigint output', async (t) => {
  await initCircomlib('wasm')
  const result = poseidonFunc([...VECTOR_INPUTS_2], true) as bigint
  t.is(result.toString(16).padStart(64, '0'), VECTOR_HASH_2)
})

test('poseidonFunc accepts bigint, number, string, and Uint8Array inputs', async (t) => {
  await initCircomlib('wasm')
  t.ok(poseidonFunc([1n, 2n, 3n], true), 'bigint inputs')
  t.ok(poseidonFunc([1, 2, 3], true), 'number inputs')
  t.ok(poseidonFunc(['1', '2', '3'], true), 'string inputs')
  t.ok(
    poseidonFunc([new Uint8Array([1]), new Uint8Array([2]), new Uint8Array([3])], true),
    'Uint8Array inputs'
  )
})

test('poseidonFunc returns Uint8Array by default and bigint when requested', async (t) => {
  await initCircomlib('wasm')
  t.ok((poseidonFunc([1n, 2n]) as Uint8Array) instanceof Uint8Array)
  t.is(typeof poseidonFunc([1n, 2n], true), 'bigint')
})

test('poseidonFunc throws for length outside 1..14', async (t) => {
  await initCircomlib('wasm')
  t.exception(() => poseidonFunc([]), /between 1 and 14/)
  t.exception(() => poseidonFunc(new Array(15).fill(1n)), /between 1 and 14/)
})

test('poseidonFunc throws for null or undefined elements', async (t) => {
  await initCircomlib('wasm')
  t.exception(() => poseidonFunc([1n, null as unknown as bigint]), /undefined or null/)
  t.exception(() => poseidonFunc([1n, undefined as unknown as bigint]), /undefined or null/)
})

test('poseidonFunc throws for unsupported input types', async (t) => {
  await initCircomlib('wasm')
  t.exception(() => poseidonFunc([{} as unknown as bigint]), /Invalid input type/)
})

test('poseidonFunc supports nOuts > 1 in both representations', async (t) => {
  await initCircomlib('wasm')
  const bigintOut = poseidonFunc([1n, 2n, 3n], true, 2)
  t.ok(Array.isArray(bigintOut), 'bigint outputs are an array')
  t.is((bigintOut as bigint[]).length, 2)
  t.ok((bigintOut as bigint[]).every((v) => typeof v === 'bigint'))

  const bytesOut = poseidonFunc([1n, 2n, 3n], false, 2)
  t.ok(Array.isArray(bytesOut), 'bytes outputs are an array')
  t.is((bytesOut as Uint8Array[]).length, 2)
  t.ok((bytesOut as Uint8Array[]).every((v) => v instanceof Uint8Array))
})

test('poseidonFunc does not mutate the input array', async (t) => {
  await initCircomlib('wasm')
  const inputs: (bigint | Uint8Array)[] = [new Uint8Array([1]), 2n, new Uint8Array([3])]
  const snapshot = inputs.map((v) => (v instanceof Uint8Array ? new Uint8Array(v) : v))
  poseidonFunc(inputs)
  t.alike(inputs[0], snapshot[0] as Uint8Array)
  t.is(inputs[1], snapshot[1])
  t.alike(inputs[2], snapshot[2] as Uint8Array)
})

test('poseidon (circomlibjs) returns 32-byte hash for valid Uint8Array inputs', async (t) => {
  await initCircomlib('wasm')
  const result = poseidon([new Uint8Array([1]), new Uint8Array([2])])
  t.ok(result instanceof Uint8Array)
  t.is(result.length, 32)
})

test('poseidon throws when neither pure nor wasm is loaded', (t) => {
  const previousWasm = poseidonBuild.wasm
  const previousPure = poseidonBuild.pure
  poseidonBuild.wasm = null
  poseidonBuild.pure = null
  try {
    t.exception(
      () => poseidon([new Uint8Array([1]), new Uint8Array([2])]),
      /Poseidon has not been loaded/
    )
  } finally {
    poseidonBuild.wasm = previousWasm
    poseidonBuild.pure = previousPure
  }
})

test('poseidon falls back to pure when wasm is unavailable', async (t) => {
  await initCircomlib('pure')
  const previousWasm = poseidonBuild.wasm
  poseidonBuild.wasm = null
  try {
    const out = poseidon([new Uint8Array([1]), new Uint8Array([2])])
    t.ok(out instanceof Uint8Array)
    t.is(out.length, 32)
  } finally {
    poseidonBuild.wasm = previousWasm
  }
})
