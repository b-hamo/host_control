import type { Overview } from '../types'
import { MeterBar } from './MeterBar'
import { freeSlots, toneForPct } from '../utils'

export function ResourcePanel({
  host,
  vm,
  reason,
}: {
  host: Overview['host_resources']
  vm: Overview['runtimes']['micro_vm']
  reason?: string | null
}) {
  const slots = freeSlots(vm.running, vm.max, vm.starting, vm.free_slots)
  const noMetrics = host.cpu_percent == null && host.mem_percent == null
  return (
    <div>
      <div className="sec">리소스 (Host){noMetrics && reason && <span className="muted" style={{ letterSpacing: 0, fontSize: 11, marginLeft: 8, textTransform: 'none' }}>· {reason}</span>}</div>
      <div className="grid-res">
        <MeterBar label="CPU" pct={host.cpu_percent} tone={toneForPct(host.cpu_percent)} />
        <MeterBar label="메모리" pct={host.mem_percent} tone={toneForPct(host.mem_percent)} />
        <div className="tile tile-center">
          <div className="sub" style={{ marginBottom: 4 }}>VM 남은 슬롯</div>
          <div className="mono slot-num">{slots}</div>
          <div className="mono muted" style={{ fontSize: 11, marginTop: 3 }}>{vm.running} / {vm.max} 가동</div>
        </div>
      </div>
    </div>
  )
}
