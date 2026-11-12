import type { Status } from '../types'

export interface DetailFields {
  typeLabel: string
  state: string
  status: Status
  risk: string
  task?: string
  elapsed: string
  cpu: string
  mem: string
  isolation: string
  lastActivity?: string
}

function Field({ label, value, className }: { label: string; value: string; className?: string }) {
  return (
    <div>
      <div className="d-label">{label}</div>
      <div className={`d-value ${className ?? ''}`}>{value}</div>
    </div>
  )
}

export function DetailPanel({ d }: { d: DetailFields }) {
  return (
    <div className="detail">
      <div className="detail-head">( 상세정보 )</div>
      <div className="detail-grid mono">
        <Field label="런타임" value={d.typeLabel} />
        <Field label="상태" value={d.state} className={`s-${d.status}`} />
        <Field label="위험 유형" value={d.risk} />
        <Field label="경과" value={d.elapsed} />
        <Field label="CPU" value={d.cpu} />
        <Field label="메모리" value={d.mem} />
        {d.task && (
          <div style={{ gridColumn: '1 / -1' }}>
            <div className="d-label">맡은 일</div>
            <div className="d-value" style={{ fontSize: 14 }}>{d.task}</div>
          </div>
        )}
        <div style={{ gridColumn: '1 / -1' }}>
          <div className="d-label">격리</div>
          <div className="d-value">{d.isolation}</div>
        </div>
        {d.lastActivity && (
          <div style={{ gridColumn: '1 / -1' }}>
            <div className="d-label">마지막 활동</div>
            <div className="d-value muted" style={{ fontSize: 13 }}>{d.lastActivity}</div>
          </div>
        )}
      </div>
    </div>
  )
}
