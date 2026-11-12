// MINOBOX 심볼 — 상자 속 황소(실루엣). 색은 CSS로 제어(.bull-box/.bull-body/.bull-eye).
export function BullIcon({ size = 28 }: { size?: number }) {
  return (
    <svg viewBox="0 0 48 48" width={size} height={size} role="img" aria-label="MINOBOX" style={{ flex: 'none' }}>
      <rect className="bull-box" x="3.5" y="3.5" width="41" height="41" rx="10" fill="none" strokeWidth="2.4" />
      <g transform="translate(24,25) scale(0.72) translate(-24,-24)">
        <path
          className="bull-body"
          d="M5 7 C 7 14, 13 16, 17.5 16.5 C 20 15, 28 15, 30.5 16.5 C 35 16, 41 14, 43 7 C 40 11, 34 12.5, 31 13.5 C 34 16, 35.5 20, 35.5 24 C 35.5 31, 30 36, 24 36 C 18 36, 12.5 31, 12.5 24 C 12.5 20, 14 16, 17 13.5 C 14 12.5, 8 11, 5 7 Z"
        />
        <circle className="bull-eye" cx="20" cy="24" r="1.7" />
        <circle className="bull-eye" cx="28" cy="24" r="1.7" />
        <ellipse className="bull-eye" cx="24" cy="30.5" rx="4" ry="2.6" />
      </g>
    </svg>
  )
}
