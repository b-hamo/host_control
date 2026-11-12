import { useState } from 'react'
import { useTheme } from './theme'
import { useDashboardData } from './hooks/useDashboardData'
import { Header } from './components/Header'
import { Tabs, type TabKey } from './components/Tabs'
import { ResourceSessionTab } from './components/ResourceSessionTab'
import { LiveViewTab } from './components/LiveViewTab'

export default function App() {
  const { theme } = useTheme()
  const { data, error, loading } = useDashboardData(3000)
  const [tab, setTab] = useState<TabKey>('res')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  return (
    <div className={`app ${theme}`}>
      <div className="shell">
        <Header updatedAt={data?.updated_at} />
        <Tabs active={tab} onChange={setTab} />

        {error && <div className="banner">데이터를 불러오지 못했어요: {error}</div>}

        {!data && loading && <div className="loading">불러오는 중…</div>}

        {data && (tab === 'res'
          ? <ResourceSessionTab data={data} />
          : <LiveViewTab data={data} selectedId={selectedId} onSelect={setSelectedId} />)}
      </div>
    </div>
  )
}
