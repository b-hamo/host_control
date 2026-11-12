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

export interface Overview {
  updated_at: string
  runtimes: {
    windows_sandbox: SandboxRuntime
    micro_vm: MicroVmRuntime
  }
  host_resources: HostResources
  metrics?: Metrics
  sessions: Session[]
}

// UI 상태색
export type Status = 'ok' | 'warn' | 'danger' | 'muted'

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
