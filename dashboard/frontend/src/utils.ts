import type { Status } from './types'

const DASH = '—'

export function formatMem(bytes: number | null | undefined): string {
  if (bytes == null) return DASH
  if (bytes < 0) return '0'
  const gb = bytes / 1024 ** 3
  if (gb >= 1) return `${gb.toFixed(1)}G`
  const mb = bytes / 1024 ** 2
  return `${Math.round(mb)}M`
}

export function formatPct(n: number | null | undefined): string {
  if (n == null) return DASH
  return `${Math.round(n)}%`
}

export function formatElapsed(startedAt: string, endedAt?: string | null, now: number = Date.now()): string {
  const start = new Date(startedAt).getTime()
  if (Number.isNaN(start)) return DASH
  const end = endedAt ? new Date(endedAt).getTime() : now
  let s = Math.max(0, Math.floor((end - start) / 1000))
  const h = Math.floor(s / 3600)
  s -= h * 3600
  const m = Math.floor(s / 60)
  s -= m * 60
  if (h > 0) return `${h}h ${m}m`
  return `${m}m ${String(s).padStart(2, '0')}s`
}

export function clampPct(n: number): number {
  return Math.max(0, Math.min(100, Math.round(n)))
}

export function freeSlots(running: number, max: number, starting = 0, explicit?: number): number {
  if (typeof explicit === 'number') return explicit
  return Math.max(0, max - running - starting)
}

export function toneForPct(n: number | null | undefined): Status {
  if (n == null) return 'muted'
  if (n >= 85) return 'danger'
  if (n >= 70) return 'warn'
  return 'ok'
}
