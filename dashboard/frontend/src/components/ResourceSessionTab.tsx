import type { Overview } from '../types'
import { RuntimePanel } from './RuntimePanel'
import { ResourcePanel } from './ResourcePanel'
import { SessionsTable } from './SessionsTable'

export function ResourceSessionTab({ data }: { data: Overview }) {
  return (
    <div className="panel res-panel">
      <RuntimePanel runtimes={data.runtimes} />
      <ResourcePanel host={data.host_resources} vm={data.runtimes.micro_vm} reason={data.metrics?.reason} />
      <SessionsTable sessions={data.sessions} />
    </div>
  )
}
