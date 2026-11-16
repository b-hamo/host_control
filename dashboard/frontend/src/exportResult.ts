import type { ExportEntry } from './types'

export function isMalwareBlocked(e: ExportEntry): boolean {
  return ['BLOCKED', 'QUARANTINED', 'FAILED'].includes(e.stage) &&
    (['MALWARE_DETECTED', 'WINDOWS_MALWARE_BLOCKED'].includes(e.scan_code ?? '') || e.code === 'MALWARE_DETECTED')
}

export function exportResult(e: ExportEntry): string {
  if (e.stage === 'EXPORTED') return '검사 통과 · 반출 완료'
  if (isMalwareBlocked(e)) return '악성 파일 감지 · 반출 차단'
  const code = e.scan_code ?? e.code ?? e.stage
  if (code === 'SCAN_TIMEOUT') return '검사 시간 초과 · 반출 안 됨'
  if (['SCAN_ERROR', 'SCAN_UNVERIFIABLE'].includes(code)) return '검사 오류 · 반출 안 됨'
  if (e.stage === 'FAILED') return '반출 실패'
  if (e.stage === 'QUARANTINED') return '격리 · 반출 안 됨'
  if (e.stage === 'BLOCKED') return '반출 차단'
  if (e.stage === 'HELD') return '보류'
  return '검사 중'
}
