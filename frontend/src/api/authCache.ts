import { useCallback } from 'react'
import { authSettingsPath, authStatusPath } from './authConfiguration'
import { useQueryCache } from './queries'

const authenticationViews = [authStatusPath, authSettingsPath] as const
const authenticationMutationViews = [...authenticationViews, '/api/admin/audit'] as const

// Activation status and preparation are deliberately absent: those security
// decisions are always read directly from the server with cache: 'no-store'.
export function useAuthenticationCacheSync() {
  const cache = useQueryCache()
  const refreshViews = useCallback(() => cache.invalidate(authenticationViews), [cache])
  const refreshAfterChange = useCallback(() => cache.invalidate(authenticationMutationViews), [cache])
  return { refreshViews, refreshAfterChange }
}
