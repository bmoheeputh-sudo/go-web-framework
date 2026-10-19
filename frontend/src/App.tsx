import { useEffect, useState } from 'react'
import AccessPortal from './AccessPortal'
import {
  AppBar,
  Toolbar,
  Typography,
  Container,
  Paper,
  Box,
  Chip,
  CircularProgress,
  Alert,
  Button,
} from '@mui/material'

type Identity = {
  issuer: string
  subject: string
  email: string
  email_verified: boolean
  display_name: string
  provider: 'oidc' | 'google_iap' | 'local_dev'
}

type Authentication =
  | { status: 'loading' | 'unauthenticated' | 'error' }
  | { status: 'authenticated'; identity: Identity }

const providerNames: Record<Identity['provider'], string> = {
  oidc: 'OIDC',
  google_iap: 'Google IAP',
  local_dev: 'Local DEV',
}

function isIdentity(value: unknown): value is Identity {
  if (typeof value !== 'object' || value === null) return false
  const identity = value as Record<string, unknown>
  return (
    typeof identity.issuer === 'string' && identity.issuer.length > 0 &&
    typeof identity.subject === 'string' && identity.subject.length > 0 &&
    typeof identity.email === 'string' &&
    typeof identity.email_verified === 'boolean' &&
    typeof identity.display_name === 'string' &&
    ['oidc', 'google_iap', 'local_dev'].includes(String(identity.provider))
  )
}

function App() {
  const [status, setStatus] = useState('Checking...')
  const [authentication, setAuthentication] = useState<Authentication>({ status: 'loading' })
  const [oidcEnabled, setOidcEnabled] = useState(false)
  const [loggingOut, setLoggingOut] = useState(false)
  const [logoutFailed, setLogoutFailed] = useState(false)
  const [loginFailed] = useState(() => new URLSearchParams(window.location.search).get('auth_error') === 'login_failed')

  useEffect(() => {
    const controller = new AbortController()
    const options = { signal: controller.signal, cache: 'no-store' as const }

    // Callback failures contain only a fixed error marker, never provider details.
    if (new URLSearchParams(window.location.search).has('auth_error')) {
      const location = new URL(window.location.href)
      location.searchParams.delete('auth_error')
      window.history.replaceState(null, '', location.pathname + location.search + location.hash)
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
        if (!controller.signal.aborted) setStatus(data.status === 'ok' ? 'Connected' : 'Error')
      })
      .catch(() => {
        if (!controller.signal.aborted) setStatus('Disconnected')
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
      setAuthentication({ status: 'unauthenticated' })
    } catch {
      setLogoutFailed(true)
    } finally {
      setLoggingOut(false)
    }
  }

  return (
    <>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6">Go Web Framework</Typography>
        </Toolbar>
      </AppBar>

      <Container maxWidth="lg" sx={{ mt: 4 }}>
        <Typography variant="h4" gutterBottom>
          Dashboard
        </Typography>

        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            Backend Status
          </Typography>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            {status === 'Checking...' ? (
              <CircularProgress size={24} aria-label="Checking backend connection" />
            ) : (
              <Chip
                label={status}
                color={status === 'Connected' ? 'success' : 'error'}
              />
            )}
          </Box>
        </Paper>

        <Paper sx={{ p: 3, mt: 3 }}>
          <Typography variant="h6" gutterBottom>
            Authentication
          </Typography>

          <Box aria-live="polite">
            {loginFailed && authentication.status !== 'authenticated' && (
              <Alert severity="error" sx={{ mb: 2 }}>Sign-in could not be completed. Please try again.</Alert>
            )}
            {logoutFailed && (
              <Alert severity="error" sx={{ mb: 2 }}>Sign-out failed. Please try again.</Alert>
            )}
            {authentication.status === 'loading' && (
              <CircularProgress size={24} aria-label="Checking authentication" />
            )}
            {authentication.status === 'unauthenticated' && (
              <Alert severity="info">You are not authenticated. No user identity is available.</Alert>
            )}
            {authentication.status === 'error' && (
              <Alert severity="error">Unable to load your identity. Please try refreshing the page.</Alert>
            )}
            {authentication.status === 'authenticated' && (
              <Box component="dl" sx={{ m: 0, textAlign: 'left' }}>
                <Typography component="dt" color="text.secondary">Provider</Typography>
                <Typography component="dd" sx={{ m: 0, mb: 2 }}>
                  {providerNames[authentication.identity.provider]}
                </Typography>
                <Typography component="dt" color="text.secondary">Display name</Typography>
                <Typography component="dd" sx={{ m: 0, mb: 2 }}>
                  {authentication.identity.display_name || 'Not provided'}
                </Typography>
                <Typography component="dt" color="text.secondary">Email address</Typography>
                <Typography component="dd" sx={{ m: 0, overflowWrap: 'anywhere' }}>
                  {authentication.identity.email || 'Not provided'}
                </Typography>
              </Box>
            )}
            {oidcEnabled && authentication.status === 'unauthenticated' && (
              <Button variant="contained" href="/api/auth/login" sx={{ mt: 2 }}>Sign in</Button>
            )}
            {authentication.status === 'authenticated' && authentication.identity.provider === 'oidc' && (
              <Button variant="outlined" onClick={() => void logout()} disabled={loggingOut} sx={{ mt: 2 }}>
                {loggingOut ? 'Signing out…' : 'Sign out'}
              </Button>
            )}
          </Box>
        </Paper>
        {authentication.status === 'authenticated' && (
          <AccessPortal key={JSON.stringify([authentication.identity.issuer, authentication.identity.subject])} />
        )}
      </Container>
    </>
  )
}

export default App
