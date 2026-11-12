import type { ExportEntry, Overview } from '../types'

// 백엔드 연동 전 더미. 백엔드 sample-overview.json 과 같은 형태.
function ago(sec: number): string {
  return new Date(Date.now() - sec * 1000).toISOString()
}

// 파일 반출 목업 (백엔드 미구현, types.ts ExportEntry 제안 계약). 최신이 위.
function exp(n: number, sid: string, label: string, name: string, sec: number, stage: string, scan?: string): ExportEntry {
  const id = `ART-${String(n).padStart(6, '0')}`
  const done = stage !== 'SCANNING'
  return {
    artifact_id: id, session_id: sid, session_label: label, name, stage,
    code: done ? stage : null, scan_code: scan ?? null,
    observed_at: ago(sec + 2), finished_at: done ? ago(sec) : null,
    export_path: stage === 'EXPORTED' ? `SandboxOutput\\${sid}\\${id}\\${name}` : null,
  }
}

function mockExports(): ExportEntry[] {
  return [
    exp(23, 'SES-6f1c', 'GUI-01', '합계_요약.xlsx', 8, 'SCANNING'),
    exp(22, 'SES-06c3', 'VM-06', 'app-build.zip', 21, 'EXPORTED'),
    exp(21, 'SES-05b2', 'VM-05', 'install.log', 33, 'EXPORTED'),
    exp(20, 'SES-07d4', 'VM-07', 'run_me.ps1', 48, 'BLOCKED', 'MALWARE_DETECTED'),
    exp(19, 'SES-07d4', 'VM-07', 'page_capture.png', 49, 'EXPORTED'),
    exp(18, 'SES-07d4', 'VM-07', 'agent_trace.txt', 50, 'EXPORTED'),
    exp(17, 'SES-09e5', 'VM-09', 'pytest_full.log', 96, 'EXPORTED'),
    exp(16, 'SES-05b2', 'VM-05', 'setup_unpacked.zip', 130, 'BLOCKED', 'MALWARE_DETECTED'),
    exp(15, 'SES-03a1', 'VM-03', 'pip_freeze.txt', 171, 'EXPORTED'),
    exp(14, 'SES-6f1c', 'GUI-01', '견적서_매크로목록.txt', 205, 'EXPORTED'),
    exp(13, 'SES-06c3', 'VM-06', 'build.ps1.out', 232, 'QUARANTINED', 'SCAN_ERROR'),
    exp(12, 'SES-09e5', 'VM-09', 'quick_check.log', 288, 'EXPORTED'),
    exp(11, 'SES-03a1', 'VM-03', 'wheelhouse.zip', 330, 'BLOCKED', 'FILE_TOO_LARGE'),
    exp(10, 'SES-09e5', 'VM-09', 'coverage.xml', 402, 'EXPORTED'),
    exp(9, 'SES-03a1', 'VM-03', 'requirements.lock', 455, 'EXPORTED'),
    exp(8, 'SES-09e5', 'VM-09', 'junit.xml', 510, 'EXPORTED'),
  ]
}

export function mockOverview(): Overview {
  const noShot = { available: false, captured_at: null }
  return {
    updated_at: new Date().toISOString(),
    runtimes: {
      windows_sandbox: { running: 1, state: 'RUNNING', window_state: 'OPEN' },
      micro_vm: { running: 6, max: 8, starting: 1, failed: 0, free_slots: 1 },
    },
    host_resources: { cpu_percent: 64, mem_percent: 72 },
    metrics: { per_session: 'hcs', reason: null },
    sessions: [
      { id: 'SES-6f1c', label: 'GUI-01', runtime: 'windows_sandbox', state: 'RUNNING', display_state: 'RUNNING', risk_type: '매크로 문서 (견적서.xlsm)', task: '메일로 받은 견적서 열어서 합계 확인해 줘', cpu_percent: 41, mem_bytes: 2576980378, started_at: ago(252), network: 'enabled', window_state: 'OPEN', host_alive: true, screenshot: noShot },
      { id: 'SES-03a1', label: 'VM-03', runtime: 'micro_vm', state: 'RUNNING', display_state: 'RUNNING', risk_type: '출처불명 패키지 설치', task: 'requirements.txt 설치해줘', cpu_percent: 28, mem_bytes: 858993459, started_at: ago(423), network: 'blocked', host_alive: true, screenshot: noShot },
      { id: 'SES-05b2', label: 'VM-05', runtime: 'micro_vm', state: 'RUNNING', display_state: 'RUNNING', risk_type: '미확인 실행파일 (setup.exe)', task: '받은 setup.exe 실행 결과 확인', cpu_percent: 19, mem_bytes: 644245094, started_at: ago(130), network: 'blocked', host_alive: true, screenshot: noShot },
      { id: 'SES-06c3', label: 'VM-06', runtime: 'micro_vm', state: 'RUNNING', display_state: 'RUNNING', risk_type: '스크립트 실행 (build.ps1)', task: '빌드 스크립트 돌려줘', cpu_percent: 24, mem_bytes: 751619276, started_at: ago(340), network: 'blocked', host_alive: true, screenshot: noShot },
      { id: 'SES-07d4', label: 'VM-07', runtime: 'micro_vm', state: 'TERMINATED', display_state: 'VIOLATION', termination_reason: 'SECURITY_VIOLATION', risk_type: '웹페이지 명령 (ClickFix)', task: '이 페이지 안내대로 해줘', cpu_percent: 0, mem_bytes: 429496729, started_at: ago(51), ended_at: ago(3), network: 'blocked', host_alive: false, screenshot: noShot },
      { id: 'SES-09e5', label: 'VM-09', runtime: 'micro_vm', state: 'RUNNING', display_state: 'RUNNING', risk_type: '빌드·테스트', task: '테스트 전체 돌려줘', cpu_percent: 33, mem_bytes: 966367641, started_at: ago(562), network: 'blocked', host_alive: true, screenshot: noShot },
      { id: 'SES-11f6', label: 'VM-11', runtime: 'micro_vm', state: 'STARTING', display_state: 'STARTING', risk_type: '스크립트 실행 (install.ps1)', task: 'install.ps1 실행해줘', cpu_percent: null, mem_bytes: null, started_at: ago(14), network: 'blocked', host_alive: true, screenshot: noShot },
    ],
    exports: mockExports(),
  }
}
