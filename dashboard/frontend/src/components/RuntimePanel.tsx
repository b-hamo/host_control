import type { Overview } from '../types'

export function RuntimePanel({ runtimes }: { runtimes: Overview['runtimes'] }) {
  const sb = runtimes.windows_sandbox
  const vm = runtimes.micro_vm
  const sbOn = sb.running === 1
  return (
    <div>
      <div className="sec">격리 런타임</div>
      <div className="grid-2">
        <div className="tile">
          <div className="sub" style={{ marginBottom: 8 }}>Windows Sandbox</div>
          <div className="mono big-num" style={!sbOn ? { color: 'var(--muted)' } : undefined}>
            {sb.running}
            <span className="num-sub"> / 1</span>
          </div>
          <div className="mono sub" style={{ marginTop: 10, fontSize: 12 }}>{sb.state}</div>
        </div>
        <div className="tile">
          <div className="sub" style={{ marginBottom: 8 }}>micro VM</div>
          <div className="mono big-num">
            {vm.running}
            <span className="num-sub"> / {vm.max}</span>
          </div>
          <div className="mono sub" style={{ marginTop: 10, fontSize: 12 }}>
            running <span className="s-ok">{vm.running}</span> · starting <span className="s-warn">{vm.starting}</span>
            {vm.failed > 0 && <> · failed <span className="s-danger">{vm.failed}</span></>}
          </div>
        </div>
      </div>
    </div>
  )
}
