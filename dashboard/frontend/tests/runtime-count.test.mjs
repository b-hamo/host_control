import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import ts from 'typescript'
const source = readFileSync(new URL('../src/utils.ts', import.meta.url), 'utf8')
const { outputText } = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext } })
const { freeSlots } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString('base64')}`)
test('unknown capacity is not displayed as free slots', () => {
  assert.equal(freeSlots(0, 8, 0, null), null)
  assert.equal(freeSlots(2, 8, 1), 5)
  assert.equal(freeSlots(2, 8, 1, 4), 4)
})
