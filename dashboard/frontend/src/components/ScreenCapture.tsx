import { useState, type CSSProperties } from 'react'
import type { Status } from '../types'

// 화면 캡처 영역. url이 있으면 실제 이미지, 없으면(MOCK) 목업 데스크톱을 그림.
// 캡처는 Sandbox=Runner PNG / micro VM=minoBox screenshot 에서 받아옴.
// 큰 모니터는 실제 캡처의 가로세로 비율을 따른다(Sandbox 화면은 16:9가 아닐 수 있어 잘리면 안 됨).
export function ScreenCapture({
  url,
  name,
  status,
  big = false,
  caption,
}: {
  url: string | null
  name: string
  status: Status
  big?: boolean
  caption?: string
}) {
  const [ratio, setRatio] = useState<number | null>(null)
  const style = big && url && ratio ? ({ '--ar': ratio } as CSSProperties) : undefined
  return (
    <div className={`scr${big ? ' monitor' : ''}`} style={style}>
      {url ? (
        <img
          src={url}
          alt={`${name} 화면`}
          className="scr-img"
          onLoad={(e) => {
            const { naturalWidth: w, naturalHeight: h } = e.currentTarget
            if (w > 0 && h > 0) setRatio(w / h)
          }}
        />
      ) : (
        <>
          <div className="scr-win" style={status === 'danger' ? { borderColor: '#6a3a3a' } : undefined} />
          <div className="scr-task" />
        </>
      )}
      <span className="scr-ov">
        <span className={`dot b-${status}`} />
        {name}
      </span>
      {caption && <span className="scr-cap">{caption}</span>}
    </div>
  )
}
