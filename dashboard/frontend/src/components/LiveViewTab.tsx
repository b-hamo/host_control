import { useMemo, useRef } from 'react'
import type { Overview, Session } from '../types'
import { ExportLog, exportRows, countByTone, type ExportRow } from './ExportLog'
import { isEnded, statusOf } from '../types'
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
      <ScreenCapture url={screenshotUrl(s.id, s.screenshot)} name={s.label} status={tone} />
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
  // 라이브 뷰는 지금 떠 있는 세션만 보여 준다. 끝난 세션은 리소스·세션 탭의 표에만 남는다.
  const live = data.sessions.filter((s) => !isEnded(s.display_state))
  const sandbox = live.filter((s) => s.runtime === 'windows_sandbox')
  const vms = live.filter((s) => s.runtime === 'micro_vm')
  const selected =
    live.find((s) => s.id === selectedId) ?? live.find((s) => s.display_state === 'RUNNING') ?? live[0]

  const panelRef = useRef<HTMLDivElement>(null)
  // exports가 없으면(백엔드 미구현) null → 로그에 "아직 받지 않음" 표시
  const rows = useMemo(() => (data.exports ? exportRows(data.exports, data.sessions) : null), [data.exports, data.sessions])
  const allCount = rows ? countByTone(rows) : null
  const liveIds = useMemo(() => new Set(live.map((s) => s.id)), [live])
  const toExports = () => panelRef.current?.scrollTo({ top: panelRef.current.scrollHeight, behavior: 'smooth' })

  const exportLog = (
    <div className="live-bottom">
      <div className="xp-spacer" />
      <ExportLog rows={rows} selected={selected} onSelect={onSelect} liveIds={liveIds} />
    </div>
  )

  if (live.length === 0) {
    return (
      <div className="panel live-panel" ref={panelRef}>
        <div className="live-top live-empty">실행 중인 격리 세션이 없어요. 작업이 시작되면 여기에 나타납니다.</div>
        {exportLog}
      </div>
    )
  }

  const mine = rows?.filter((r) => r.session_id === selected?.id)
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
        exports: mine ? exportSummary(mine) : undefined,
      }
    : null

  return (
    <div className="panel live-panel" ref={panelRef}>
     <div className="live-top">
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
              url={screenshotUrl(selected.id, selected.screenshot)}
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
        {/* 아래로 스크롤하면 반출 목록이 있다는 안내. 누르면 내려간다. */}
        <button type="button" className="xp-cue" onClick={toExports}>
          <span>파일 반출 {rows ? `${rows.length}건` : ''}</span>
          <span className="n">
            {allCount && (
              <>
                <span className="s-ok">{allCount.ok}</span>
                <span className="s-danger">{allCount.danger}</span>
                <span className="s-warn">{allCount.warn}</span>
              </>
            )}
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M6 9l6 6 6-6" />
            </svg>
          </span>
        </button>
      </div>
     </div>

     {exportLog}
    </div>
  )
}

function exportSummary(rows: ExportRow[]): { text: string; danger: boolean } {
  const c = countByTone(rows)
  const parts = [`${c.ok}건 반출`, `${c.danger}건 차단`]
  if (c.warn) parts.push(`${c.warn}건 검사 중`)
  return { text: parts.join(' · '), danger: c.danger > 0 }
}
