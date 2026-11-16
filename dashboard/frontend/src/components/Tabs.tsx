export type TabKey = 'res' | 'live'

const TABS: { key: TabKey; label: string }[] = [
  { key: 'res', label: '리소스 · 세션' },
  { key: 'live', label: '라이브 뷰' },
]

export function Tabs({ active, onChange }: { active: TabKey; onChange: (k: TabKey) => void }) {
  return (
    <div className="tabs">
      {TABS.map((t) => (
        <button key={t.key} className={`tab${active === t.key ? ' on' : ''}`} onClick={() => onChange(t.key)}>
          {t.label}
        </button>
      ))}
    </div>
  )
}
