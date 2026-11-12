import { forwardRef, useMemo, useState } from 'react'
import type { ExportEntry, ExportTone, Session } from '../types'
import { exportToneOf } from '../types'
import { formatClock } from '../utils'

// 라이브 뷰 아래(스크롤)에 붙는 파일 반출 로그. 높이는 고정, 본문만 스크롤.
// exports가 undefined면 백엔드가 아직 반출 목록을 보내지 않는 것(계약 미구현).

type Filter = 'all' | ExportTone
type Scope = 'all' | 'sel'

export interface ExportRow extends ExportEntry {
  tone: ExportTone
  label: string
}

/** 화면에 보일 줄만 남기고(SUPERSEDED 등 제외) 최신이 위로 오게 정렬. */
export function exportRows(exports: ExportEntry[] | undefined, sessions: Session[]): ExportRow[] {
  if (!exports) return []
  const labelOf = new Map(sessions.map((s) => [s.id, s.label]))
  const rows: ExportRow[] = []
  for (const e of exports) {
    const tone = exportToneOf(e.stage)
    if (!tone) continue
    rows.push({ ...e, tone, label: e.session_label ?? labelOf.get(e.session_id) ?? e.session_id })
  }
  const at = (e: ExportEntry) => new Date(e.finished_at ?? e.observed_at).getTime() || 0
  return rows.sort((a, b) => at(b) - at(a) || b.artifact_id.localeCompare(a.artifact_id))
}

export function countByTone(rows: ExportRow[]): Record<ExportTone, number> {
  const c: Record<ExportTone, number> = { ok: 0, danger: 0, warn: 0 }
  for (const r of rows) c[r.tone]++
  return c
}

function Result({ r }: { r: ExportRow }) {
  let text: string
  if (r.tone === 'ok') text = '반출됨 · CLEAN'
  else if (r.tone === 'danger') text = `차단 · ${r.scan_code ?? r.code ?? r.stage}`
  else text = r.stage === 'HELD' ? '보류' : '검사 중'
  return (
    <span className={`res ${r.tone}`}>
      <span className="dot" />
      {text}
    </span>
  )
}

const CHIPS: { key: Filter; label: string }[] = [
  { key: 'all', label: '전체' },
  { key: 'ok', label: '반출' },
  { key: 'danger', label: '차단' },
  { key: 'warn', label: '검사 중' },
]

export const ExportLog = forwardRef<
  HTMLElement,
  { rows: ExportRow[] | null; selected?: Session; onSelect: (id: string) => void; liveIds: Set<string> }
>(function ExportLog({ rows, selected, onSelect, liveIds }, ref) {
  const [filter, setFilter] = useState<Filter>('all')
  const [scope, setScope] = useState<Scope>('all')

  const scoped = useMemo(
    () => (rows ?? []).filter((r) => scope === 'all' || r.session_id === selected?.id),
    [rows, scope, selected?.id],
  )
  const count = countByTone(scoped)
  const shown = scoped.filter((r) => filter === 'all' || r.tone === filter)

  return (
    <section className="xp" ref={ref} aria-label="파일 반출 목록">
      <div className="xp-head">
        <div className="xp-title">( 파일 반출 )</div>
        <div className="xp-sum">
          {CHIPS.map((c) => (
            <button
              key={c.key}
              type="button"
              className={`chip ${c.key === 'all' ? '' : c.key}${filter === c.key ? ' on' : ''}`}
              onClick={() => setFilter(c.key)}
            >
              {c.label}
              <b>{c.key === 'all' ? scoped.length : count[c.key]}</b>
            </button>
          ))}
        </div>
        <div className="xp-tools">
          <div className="seg">
            <button type="button" className={scope === 'all' ? 'on' : undefined} onClick={() => setScope('all')}>
              전체 세션
            </button>
            <button type="button" className={scope === 'sel' ? 'on' : undefined} onClick={() => setScope('sel')} disabled={!selected}>
              <span className="sel">{selected?.label ?? '—'}</span> 만
            </button>
          </div>
        </div>
      </div>

      <div className="xp-body">
        <div className="xp-row xp-hrow">
          <span className="c-t">시각</span>
          <span className="c-s">세션</span>
          <span className="c-f">파일</span>
          <span className="c-r">결과</span>
          <span className="c-p">저장 위치</span>
        </div>
        {rows === null ? (
          <div className="xp-empty">반출 기록을 아직 받지 않아요. (백엔드 연결 전)</div>
        ) : shown.length === 0 ? (
          <div className="xp-empty">조건에 맞는 반출 기록이 없어요.</div>
        ) : (
          shown.map((r) => {
            const clickable = liveIds.has(r.session_id)
            return (
              <div
                key={r.artifact_id}
                className={`xp-row xp-line st-${r.tone}${clickable ? ' link' : ''}`}
                title={r.name}
                onClick={clickable ? () => onSelect(r.session_id) : undefined}
              >
                <span className="c-t">{formatClock(r.finished_at ?? r.observed_at)}</span>
                <span className={`c-s${r.session_id === selected?.id ? ' cur' : ''}`}>{r.label}</span>
                <span className="c-f">{r.name}</span>
                <span className="c-r">
                  <Result r={r} />
                </span>
                {r.tone === 'ok' && r.export_path ? (
                  <span className="c-p" title={r.export_path}>{r.export_path}</span>
                ) : (
                  <span className="c-p none">—</span>
                )}
              </div>
            )
          })
        )}
      </div>
    </section>
  )
})
