import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import ts from 'typescript'

const source = readFileSync(new URL('../src/exportResult.ts', import.meta.url), 'utf8')
const { outputText } = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext } })
const { isMalwareBlocked, exportResult } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString('base64')}`)

test('confirmed detection is distinct from scan errors and ordinary blocks', () => {
  const detected = { stage: 'BLOCKED', code: 'BLOCKED', scan_code: 'MALWARE_DETECTED' }
  assert.equal(isMalwareBlocked(detected), true)
  assert.equal(exportResult(detected), '악성 파일 감지 · 반출 차단')
  for (const code of ['SCAN_ERROR', 'SCAN_TIMEOUT', 'UPLOAD_FAILED', 'BLOCKED']) {
    assert.equal(isMalwareBlocked({ ...detected, scan_code: code }), false)
  }
  assert.equal(exportResult({ stage: 'BLOCKED', scan_code: 'SCAN_TIMEOUT' }), '검사 시간 초과 · 반출 안 됨')
  assert.equal(exportResult({ stage: 'BLOCKED', scan_code: 'SCAN_ERROR' }), '검사 오류 · 반출 안 됨')
})

test('only a terminal block can count as malware; published results remain published', () => {
  assert.equal(isMalwareBlocked({ stage: 'SCANNING', scan_code: 'MALWARE_DETECTED' }), false)
  assert.equal(exportResult({ stage: 'EXPORTED', scan_code: 'MALWARE_DETECTED' }), '검사 통과 · 반출 완료')
  assert.equal(isMalwareBlocked({ stage: 'QUARANTINED', code: 'MALWARE_DETECTED' }), true)
  assert.equal(isMalwareBlocked({ stage: 'BLOCKED', code: 'QUARANTINED', scan_code: 'WINDOWS_MALWARE_BLOCKED' }), true)
})
