import { useEffect, useState } from 'react'
import type { Session } from '../types'
import { statusOf } from '../types'
import { formatMem, formatPct } from '../utils'

const RUNTIME_LABEL: Record<Session['runtime'], string> = {
  windows_sandbox: 'Win Sandbox',
  micro_vm: 'micro VM',
}

export function SessionsTable({ sessions }: { sessions: Session[] }) {
  const [, setTick] = useState(0)
  useEffect(() => {
    const id = window.setInterval(() => setTick((t) => t + 1), 1000)
    return () => window.clearInterval(id)
  }, [])

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      <div className="sec">진행중 세션</div>
      <div className="tile sess-wrap">
        {sessions.length === 0 ? (
          <div className="empty">진행중인 세션이 없어요</div>
        ) : (
          <table className="mono sess-table">
            <thead>
              <tr>
                <th>session</th><th>런타임</th><th>위험 유형</th><th>상태</th>
                <th className="r">CPU</th><th className="r pr">MEM</th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => {
                const tone = statusOf(s.display_state)
                return (
                  <tr key={s.id}>
                    <td className="pl">{s.label}</td>
                    <td className={s.runtime === 'windows_sandbox' ? 'c-blue' : 'sub'}>{RUNTIME_LABEL[s.runtime]}</td>
                    <td className={tone === 'danger' ? 's-danger' : 'sub'}>{s.risk_type}</td>
                    <td className={`s-${tone}`}>{s.display_state}</td>
                    <td className={`r ${s.cpu_percent != null && s.cpu_percent >= 70 ? 's-warn' : ''}`}>{formatPct(s.cpu_percent)}</td>
                    <td className="r pr">{formatMem(s.mem_bytes)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
