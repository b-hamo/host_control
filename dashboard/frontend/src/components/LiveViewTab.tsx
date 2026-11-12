import type { Overview, Session } from '../types'
import { statusOf } from '../types'
import { formatMem, formatPct, formatElapsed } from '../utils'
import { screenshotUrl } from '../api/client'
import { ScreenCapture } from './ScreenCapture'
import { DetailPanel, type DetailFields } from './DetailPanel'

const TYPE_LABEL: Record<Session['runtime'], string> = {
  windows_sandbox: 'Windows Sandbox',
  micro_vm: 'micro VM',
}

function isolationText(s: Session): string {
  const net = s.network === 'blocked' ? '네트워크 차단' : s.network === 'enabled' ? '네트워크 허용' : `네트워크 ${s.network ?? '—'}`
  if (s.runtime === 'windows_sandbox') return `${net} · window ${s.window_state ?? '—'}`
  return net
}

function lastActivityText(s: Session): string | undefined {
  const la = s.last_activity
  if (!la) return undefined
  const when = la.at ? new Date(la.at).toLocaleTimeString('ko-KR', { hour12: false }) : ''
  const okMark = la.ok ? '' : ' · 실패'
  return `${la.tool ?? '—'}${la.file ? ` (${la.file})` : ''}${okMark} ${when}`.trim()
}

function Thumb({ s, selected, onSelect }: { s: Session; selected: boolean; onSelect: () => void }) {
  const tone = statusOf(s.display_state)
  return (
    <div className={`thumb${selected ? ' on' : ''}`} onClick={onSelect}>
      {selected && <span className="thumb-badge">보는 중</span>}
      <ScreenCapture url={screenshotUrl(s.label, s.screenshot)} name={s.label} status={tone} />
      <div className="thumb-foot">
        <span className={selected ? 'sel-id' : undefined}>{s.label}</span>
        <span className={`s-${tone}`}>{s.display_state}</span>
      </div>
    </div>
  )
}

export function LiveViewTab({
  data,
  selectedId,
  onSelect,
}: {
  data: Overview
  selectedId: string | null
  onSelect: (id: string) => void
}) {
  const sandbox = data.sessions.filter((s) => s.runtime === 'windows_sandbox')
  const vms = data.sessions.filter((s) => s.runtime === 'micro_vm')
  const selected = data.sessions.find((s) => s.id === selectedId) ?? data.sessions[0]

  if (data.sessions.length === 0) {
    return <div className="panel live-empty">격리 세션이 없어요. 작업이 시작되면 여기에 나타납니다.</div>
  }

  const detail: DetailFields | null = selected
    ? {
        typeLabel: TYPE_LABEL[selected.runtime],
        state: selected.display_state,
        status: statusOf(selected.display_state),
        risk: selected.risk_type,
        task: selected.task,
        elapsed: formatElapsed(selected.started_at, selected.ended_at),
        cpu: formatPct(selected.cpu_percent),
        mem: formatMem(selected.mem_bytes),
        isolation: isolationText(selected),
        lastActivity: lastActivityText(selected),
      }
    : null

  return (
    <div className="panel live-panel">
      <div className="live-side">
        <div className="sec sec-wide">sandbox</div>
        {sandbox.map((s) => (
          <Thumb key={s.id} s={s} selected={selected?.id === s.id} onSelect={() => onSelect(s.id)} />
        ))}

        <div className="side-divider" />

        <div className="sec">
          Micro VM <span className="muted" style={{ letterSpacing: 0, fontSize: 12 }}>{data.runtimes.micro_vm.running}/{data.runtimes.micro_vm.max}</span>
        </div>
        <div className="vm-list">
          {vms.map((s) => (
            <Thumb key={s.id} s={s} selected={selected?.id === s.id} onSelect={() => onSelect(s.id)} />
          ))}
        </div>
      </div>

      <div className="live-main">
        <div className="monitor-box">
          {selected && (
            <ScreenCapture
              url={screenshotUrl(selected.label, selected.screenshot)}
              name={selected.label}
              status={statusOf(selected.display_state)}
              big
              caption={selected.screenshot?.captured_at ? `캡처 ${new Date(selected.screenshot.captured_at).toLocaleTimeString('ko-KR', { hour12: false })}` : 'AI가 마지막으로 본 화면'}
            />
          )}
        </div>
      </div>

      <div className="detail-col">
        {detail && <DetailPanel d={detail} />}
      </div>
    </div>
  )
}
