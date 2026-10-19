import { api, APIError, errorKey } from './client'

export type Query = { loading: boolean; data?: unknown; error: string }
type Entry = { snapshot: Query; controller: AbortController }

// An in-memory, per-identity cache. No tokens, storage, timers, or polling.
// Invalidation cancels old reads so late responses cannot restore stale data.
export class QueryCache {
  private entries = new Map<string, Entry>()
  private listeners = new Set<() => void>()
  private onUnauthorized: () => void
  constructor(onUnauthorized: () => void) { this.onUnauthorized = onUnauthorized }
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener) } }
  snapshot = (path: string) => this.entries.get(path)?.snapshot
  private emit() { this.listeners.forEach((listener) => listener()) }

  load(path: string) {
    if (this.entries.has(path)) return
    const entry: Entry = { snapshot: { loading: true, error: '' }, controller: new AbortController() }
    this.entries.set(path, entry)
    this.emit()
    void api(path, 'GET', undefined, entry.controller.signal).then((data) => {
      if (entry.controller.signal.aborted) return
      entry.snapshot = { loading: false, data, error: '' }
      this.emit()
    }).catch((error) => {
      if (entry.controller.signal.aborted) return
      entry.snapshot = { loading: false, error: errorKey(error) }
      this.emit()
      if (error instanceof APIError && error.status === 401) this.onUnauthorized()
    })
  }

  invalidate = () => {
    this.entries.forEach((entry) => entry.controller.abort())
    this.entries.clear()
    this.emit()
  }

  async mutate(path: string, method: string, body: unknown) {
    try {
      await api(path, method, body)
      this.invalidate()
    } catch (error) {
      if (error instanceof APIError && error.status === 401) this.onUnauthorized()
      throw error
    }
  }
}
