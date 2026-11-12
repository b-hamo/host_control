// 백엔드 계약 타입 — host_control dashboard/README.md (feat/124-dashboard-backend) 기준.

export type RuntimeType = 'windows_sandbox' | 'micro_vm'

// 화면 표시용 상태 (display_state)
export type DisplayState =
  | 'PREPARED' | 'STARTING' | 'STARTED' | 'RUNNING'
  | 'RESTARTING' | 'TERMINATED' | 'FAILED' | 'VIOLATION'

export type TerminationReason =
  | 'TASK_COMPLETE' | 'USER_STOP' | 'SECURITY_VIOLATION' | 'TIMEOUT' | 'RUNTIME_ERROR'

export type WindowState =
  | 'UNSEEN' | 'OPEN' | 'MISSING' | 'CLOSED' | 'UNKNOWN' | 'UNAVAILABLE'

export interface LastActivity {
  tool: string | null
  file: string | null
  ok: boolean
  at: string
}

export interface ScreenshotInfo {
  available: boolean
  captured_at: string | null
}

export interface SandboxRuntime {
  running: 0 | 1
  state: string // RUNNING | STOPPED | ...
  window_state: WindowState
}

export interface MicroVmRuntime {
  running: number
  max: number
  starting: number
  failed: number
  free_slots?: number
}

export interface HostResources {
  cpu_percent: number | null // 관리자 권한으로 안 켜면 null
  mem_percent: number | null
}

export interface Metrics {
  per_session: string // 'hcs' 등
  reason: string | null // null이 아니면 CPU/MEM이 null인 이유
}

export interface Session {
  id: string // 세션 ID (SES-…)
  label: string // 표시용 (GUI-01, VM-03)
  runtime: RuntimeType
  state: string // 원본 상태
  display_state: DisplayState // 화면 표시용
  termination_reason?: TerminationReason | null
  risk_type: string
  task?: string // 맡은 일 (AI/웹 생성 문자열 — escape 대상, React가 자동 처리)
  last_activity?: LastActivity | null
  cpu_percent: number | null
  mem_bytes: number | null
  started_at: string
  ended_at?: string | null
  network?: string // 'enabled'(Sandbox) | 'blocked'(micro VM)
  window_state?: WindowState
  host_alive?: boolean
  screenshot?: ScreenshotInfo
}

// 파일 반출 한 건. 백엔드 미구현(제안 계약) — 값은 host/artifacts.py · output_export.py 의 stage/result 기준.
// stage: 끝나기 전 CANDIDATE·AUTHORIZED·STAGED·SCANNING, 끝나면 EXPORTED·BLOCKED·QUARANTINED·FAILED·HELD·DELETED·SUPERSEDED·CANCELLED
export interface ExportEntry {
  artifact_id: string // ART-000017
  session_id: string
  session_label?: string | null // 세션이 overview에서 빠진 뒤에도 라벨을 보이려고
  name: string // 파일 이름 (Guest가 알린 경로, 표시용)
  stage: string
  code?: string | null // result.code (EXPORTED · BLOCKED · QUARANTINED · OUTPUT_FAILED …)
  scan_code?: string | null // 검사기 코드 (MALWARE_DETECTED · CONTENT_CHANGED …)
  observed_at: string // Guest가 파일을 알린 시각
  finished_at?: string | null // 반출·차단이 정해진 시각
  export_path?: string | null // EXPORTED일 때만. SandboxOutput\… 상대 경로
}

export interface Overview {
  updated_at: string
  runtimes: {
    windows_sandbox: SandboxRuntime
    micro_vm: MicroVmRuntime
  }
  host_resources: HostResources
  metrics?: Metrics
  sessions: Session[]
  exports?: ExportEntry[] // 백엔드가 아직 안 보냄 → undefined
}

// UI 상태색
export type Status = 'ok' | 'warn' | 'danger' | 'muted'

// 끝난 세션. 백엔드는 끝난 뒤 10분(KEEP_ENDED_S) 동안 계속 보내 준다.
export function isEnded(ds: DisplayState): boolean {
  return ds === 'TERMINATED' || ds === 'FAILED' || ds === 'VIOLATION'
}

// 반출 결과 → 화면 묶음. null이면 목록에 안 보인다(다른 사본으로 바뀌었거나 취소·삭제됨).
export type ExportTone = 'ok' | 'danger' | 'warn'

export function exportToneOf(stage: string): ExportTone | null {
  switch (stage) {
    case 'EXPORTED':
      return 'ok'
    case 'BLOCKED':
    case 'QUARANTINED':
    case 'FAILED':
      return 'danger'
    case 'SUPERSEDED':
    case 'CANCELLED':
    case 'DELETED':
      return null
    default:
      return 'warn' // 아직 받는 중·검사 중, HELD(보류)
  }
}

export function statusOf(ds: DisplayState): Status {
  switch (ds) {
    case 'RUNNING':
    case 'STARTED':
      return 'ok'
    case 'PREPARED':
    case 'STARTING':
    case 'RESTARTING':
      return 'warn'
    case 'VIOLATION':
    case 'FAILED':
      return 'danger'
    case 'TERMINATED':
      return 'muted'
    default:
      return 'muted'
  }
}
