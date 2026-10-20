import { useCallback, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { api, APIError, errorKey } from '../api/client'
import type { Identity, User } from '../api/client'
import { SessionContext } from './session'
import type { Access, Authentication } from './session'

function isIdentity(value: unknown): value is Identity {
  if (typeof value !== 'object' || value === null) return false
  const identity = value as Record<string, unknown>
  return (
    typeof identity.issuer === 'string' && identity.issuer.length > 0 &&
    typeof identity.subject === 'string' && identity.subject.length > 0 &&
    typeof identity.email === 'string' &&
    typeof identity.email_verified === 'boolean' &&
    typeof identity.display_name === 'string' &&
    ['oidc', 'local_dev'].includes(String(identity.provider))
  )
}

export default function SessionProvider({ children }: { children: ReactNode }) {
  const [health, setStatus] = useState('checking')
  const [authentication, setAuthentication] = useState<Authentication>({ status: 'loading' })
  const [oidcEnabled, setOidcEnabled] = useState(false)
  const [loggingOut, setLoggingOut] = useState(false)
  const [logoutFailed, setLogoutFailed] = useState(false)
  const [loginFailed] = useState(() => new URLSearchParams(window.location.search).get('auth_error') === 'login_failed')
  const [access, setAccess] = useState<Access>({ loading: true, user: null, error: '' })
  const [revision, setRevision] = useState(0)
  const identity = authentication.status === 'authenticated' ? authentication.identity : null
  const expire = useCallback(() => {
    setAuthentication({ status: 'unauthenticated' })
    setAccess({ loading: false, user: null, error: '' })
  }, [])


  useEffect(() => {
    const controller = new AbortController()
    const options = { signal: controller.signal, cache: 'no-store' as const }

    // Callback failures contain only a fixed error marker, never provider details.
    if (new URLSearchParams(window.location.search).has('auth_error')) {
      const location = new URL(window.location.href)
      location.searchParams.delete('auth_error')
      window.history.replaceState(window.history.state, '', location.pathname + location.search + location.hash)
    }

    fetch('/api/auth/config', options)
      .then((response) => {
        if (!response.ok) throw new Error('Authentication configuration unavailable')
        return response.json()
      })
      .then((config) => {
        if (!controller.signal.aborted) setOidcEnabled(config.provider === 'oidc')
      })
      .catch(() => {
        if (!controller.signal.aborted) setOidcEnabled(false)
      })

    fetch('/api/health', options)
      .then((response) => {
        if (!response.ok) throw new Error('API unavailable')
        return response.json()
      })
      .then((data) => {
        if (!controller.signal.aborted) setStatus(data.status === 'ok' ? 'connected' : 'connectionError')
      })
      .catch(() => {
        if (!controller.signal.aborted) setStatus('disconnected')
      })

    // Health and authentication are independent: HTTP 401 does not mean the
    // backend is disconnected. No tokens or development identity are sent.
    async function loadIdentity() {
      try {
        const response = await fetch('/api/auth/me', options)
        if (controller.signal.aborted) return
        if (response.status === 401) {
          setAuthentication({ status: 'unauthenticated' })
          return
        }
        if (!response.ok) throw new Error('Authentication unavailable')
        const identity: unknown = await response.json()
        if (!isIdentity(identity)) throw new Error('Invalid identity response')
        if (!controller.signal.aborted) setAuthentication({ status: 'authenticated', identity })
      } catch {
        if (!controller.signal.aborted) setAuthentication({ status: 'error' })
      }
    }

    void loadIdentity()
    return () => controller.abort()
  }, [])

  async function logout() {
    setLoggingOut(true)
    setLogoutFailed(false)
    try {
      const response = await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
      if (!response.ok) throw new Error('Logout failed')
      expire()
    } catch {
      setLogoutFailed(true)
    } finally {
      setLoggingOut(false)
    }
  }


  function refreshAccess() {
    setAccess({ loading: true, user: null, error: '' })
    setRevision((value) => value + 1)
  }
  useEffect(() => {
    if (!identity) return
    const controller = new AbortController()
    api<User>('/api/access/me', 'GET', undefined, controller.signal).then((user) => {
      if (!controller.signal.aborted) setAccess({ loading: false, user, error: '' })
    }).catch((error) => {
      if (controller.signal.aborted) return
      if (error instanceof APIError && error.status === 401) expire()
      else setAccess({ loading: false, user: null, error: errorKey(error) })
    })
    return () => controller.abort()
  }, [identity, revision, expire])

  return <SessionContext.Provider value={{ authentication, access, health, oidcEnabled, loggingOut, logoutFailed, loginFailed, logout, expire, refreshAccess }}>{children}</SessionContext.Provider>
}
