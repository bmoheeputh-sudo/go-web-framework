import { api, APIError, errorKey } from './client'

export type Query = { loading: boolean; data?: unknown; error: string }
type Entry = { snapshot: Query; controller: AbortController; stale: boolean }

// Writes refresh only related reads. The audit trail changes with every
// administrative write; unknown module writes conservatively refresh all data.
function affectedReads(path: string): readonly string[] | undefined {
  if (path.startsWith('/api/admin/auth/')) return ['/api/admin/auth', '/api/admin/users', '/api/admin/audit']
  if (path.startsWith('/api/admin/users')) return ['/api/admin/users', '/api/accounts', '/api/admin/audit']
  if (path.startsWith('/api/admin/accounts')) return ['/api/admin/accounts', '/api/accounts', '/api/admin/users', '/api/admin/audit']
  if (path.startsWith('/api/admin/permissions') || path.startsWith('/api/admin/role-permissions'))
    return ['/api/admin/permissions', '/api/admin/roles', '/api/admin/users', '/api/admin/audit']
  return undefined
}

function matches(path: string, prefix: string) {
  return path === prefix || path.startsWith(`${prefix}/`) || path.startsWith(`${prefix}?`)
}

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
    const previous = this.entries.get(path)
    if (previous && !previous.stale) return
    const entry: Entry = { snapshot: previous?.snapshot || { loading: true, error: '' }, controller: new AbortController(), stale: false }
    this.entries.set(path, entry)
    this.emit()
    void api(path, 'GET', undefined, entry.controller.signal).then((data) => {
      if (entry.controller.signal.aborted) return
      entry.snapshot = { loading: false, data, error: '' }
      this.emit()
    }).catch((error) => {
      if (entry.controller.signal.aborted) return
      const denied = error instanceof APIError && (error.status === 401 || error.status === 403)
      entry.snapshot = { loading: false, data: denied ? undefined : entry.snapshot.data, error: errorKey(error) }
      this.emit()
      if (error instanceof APIError && error.status === 401) this.onUnauthorized()
    })
  }

  invalidate = (prefixes?: readonly string[]) => {
    this.entries.forEach((entry, path) => {
      if (prefixes && !prefixes.some((prefix) => matches(path, prefix))) return
      entry.controller.abort()
      entry.stale = true
      // Keep settled rows visible while the next request refreshes them.
      entry.snapshot = { ...entry.snapshot, loading: true, error: '' }
    })
    this.emit()
  }

  dispose = () => {
    this.entries.forEach((entry) => entry.controller.abort())
    this.entries.clear()
    this.listeners.clear()
  }

  async mutate(path: string, method: string, body: unknown) {
    try {
      await api(path, method, body)
      this.invalidate(affectedReads(path))
    } catch (error) {
      if (error instanceof APIError && error.status === 401) this.onUnauthorized()
      throw error
    }
  }
}
