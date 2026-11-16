import type { Overview, ScreenshotInfo } from '../types'
import { mockOverview } from './mock'

// 대시보드 서버가 페이지를 열 때 URL에 ?token=... 을 붙여줍니다.
// 토큰이 있으면 실제 API, 없으면(=npm run dev 등) 목업으로 동작합니다.
// 강제로 실 API를 쓰려면 .env 에 VITE_USE_MOCK=false.
function readToken(): string | null {
  try {
    return new URLSearchParams(window.location.search).get('token')
  } catch {
    return null
  }
}

const TOKEN = readToken()
const USE_MOCK = TOKEN ? false : import.meta.env.VITE_USE_MOCK !== 'false'

function authHeaders(): HeadersInit {
  return TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}
}

/** 대시보드 집계. 백엔드: GET /api/dashboard/overview (2~5초 폴링) */
export async function getOverview(signal?: AbortSignal): Promise<Overview> {
  if (USE_MOCK) {
    await new Promise((r) => setTimeout(r, 120))
    return mockOverview()
  }
  const res = await fetch('/api/dashboard/overview', { signal, headers: authHeaders() })
  if (!res.ok) throw new Error(`overview ${res.status}`)
  return (await res.json()) as Overview
}

/** 런타임 화면 캡처 URL. 백엔드: GET /api/runtimes/{id}/screenshot (PNG)
 *  - available=false면 null (요청하지 않음)
 *  - captured_at을 v로 붙여, 화면이 바뀔 때만 새로 받게 함(캐시)
 *  - <img>는 헤더를 못 붙이므로 ?token= 으로 전달 */
export function screenshotUrl(labelOrId: string, shot?: ScreenshotInfo | null): string | null {
  if (USE_MOCK) return null
  if (shot && !shot.available) return null
  const params = new URLSearchParams()
  if (TOKEN) params.set('token', TOKEN)
  if (shot?.captured_at) params.set('v', shot.captured_at)
  const qs = params.toString()
  return `/api/runtimes/${encodeURIComponent(labelOrId)}/screenshot${qs ? `?${qs}` : ''}`
}
