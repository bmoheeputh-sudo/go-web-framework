import { createContext, useContext, useEffect, useState, useSyncExternalStore } from 'react'
import { QueryCache } from './cache'
import { errorKey } from './client'
import { useNotifications } from '../notifications/notifications'

export const QueryContext = createContext<QueryCache | null>(null)
export function useQueryCache() {
  const cache = useContext(QueryContext)
  if (!cache) throw new Error('QueryProvider is required')
  return cache
}
export function useQuery<T>(path: string | null) {
  const cache = useQueryCache()
  const snapshot = useSyncExternalStore(cache.subscribe, () => path ? cache.snapshot(path) : undefined)
  useEffect(() => { if (path) cache.load(path) }, [cache, path, snapshot])
  return { data: snapshot?.data as T | undefined, loading: Boolean(path) && (!snapshot || snapshot.loading), error: snapshot?.error || '' }
}
export function useMutation() {
  const cache = useQueryCache()
  const notify = useNotifications()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function mutate(path: string, method: string, body: unknown) {
    setBusy(true); setError('')
    try {
      await cache.mutate(path, method, body)
      notify({ severity: 'success', messageKey: 'admin:changesSaved' })
      return true
    } catch (error) {
      const key = errorKey(error)
      setError(key)
      notify({ severity: 'error', messageKey: `admin:${key}` })
      return false
    }
    finally { setBusy(false) }
  }
  return { mutate, busy, error, clearError: () => setError('') }
}
