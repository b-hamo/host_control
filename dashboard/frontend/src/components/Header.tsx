import { BullIcon } from './BullIcon'
import { useTheme } from '../theme'

function SunIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
      <circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" strokeLinecap="round" />
    </svg>
  )
}
function MoonIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
      <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" strokeLinejoin="round" />
    </svg>
  )
}

export function Header({ updatedAt }: { updatedAt?: string }) {
  const { theme, toggle } = useTheme()
  return (
    <div className="hdr">
      <div className="hdr-left">
        <BullIcon size={28} />
        <span className="hdr-title">MINOBOX</span>
      </div>
      <div className="hdr-right">
        <span className="mono muted hdr-refresh">{updatedAt ? 'live · 3s' : 'connecting…'}</span>
        <button className="themebtn" onClick={toggle} aria-label="테마 전환">
          {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
          <span>{theme === 'dark' ? '라이트' : '다크'}</span>
        </button>
      </div>
    </div>
  )
}
