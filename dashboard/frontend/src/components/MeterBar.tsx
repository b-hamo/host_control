import type { Status } from '../types'
import { clampPct } from '../utils'

export function MeterBar({ label, pct, tone }: { label: string; pct: number | null; tone: Status }) {
  const has = pct != null
  const v = has ? clampPct(pct) : 0
  return (
    <div className="tile">
      <div className="meter-head">
        <span className="sub">{label}</span>
        <span className={`mono s-${has ? tone : 'muted'}`} style={{ fontSize: 18 }}>{has ? `${v}%` : '—'}</span>
      </div>
      <div className="track">
        <div className={`fill b-${tone}`} style={{ width: `${v}%` }} />
      </div>
    </div>
  )
}
