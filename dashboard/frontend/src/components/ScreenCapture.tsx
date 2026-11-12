import type { Status } from '../types'

// 화면 캡처 영역. url이 있으면 실제 이미지, 없으면(MOCK) 목업 데스크톱을 그림.
// 캡처는 Sandbox=Runner PNG / micro VM=minoBox screenshot 에서 받아옴.
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
  return (
    <div className={`scr${big ? ' monitor' : ''}`}>
      {url ? (
        <img src={url} alt={`${name} 화면`} className="scr-img" />
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
