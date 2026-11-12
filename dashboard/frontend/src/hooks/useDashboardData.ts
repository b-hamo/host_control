import { useEffect, useRef, useState } from 'react'
import type { Overview } from '../types'
import { getOverview } from '../api/client'

interface State {
  data: Overview | null
  error: string | null
  loading: boolean
}

/** overview를 intervalMs 간격으로 폴링. */
export function useDashboardData(intervalMs = 3000): State {
  const [state, setState] = useState<State>({ data: null, error: null, loading: true })
  const timer = useRef<number | null>(null)

  useEffect(() => {
    let alive = true
    const ac = new AbortController()

    async function tick() {
      try {
        const data = await getOverview(ac.signal)
        if (alive) setState({ data, error: null, loading: false })
      } catch (e) {
        if (alive && (e as Error).name !== 'AbortError') {
          setState((s) => ({ ...s, error: (e as Error).message, loading: false }))
        }
      }
    }

    tick()
    timer.current = window.setInterval(tick, intervalMs)
    return () => {
      alive = false
      ac.abort()
      if (timer.current) window.clearInterval(timer.current)
    }
  }, [intervalMs])

  return state
}
