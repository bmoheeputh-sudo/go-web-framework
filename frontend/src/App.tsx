import { useEffect, useState } from 'react'
import AccessPortal from './AccessPortal'
import { useTranslation } from 'react-i18next'
import LanguageSelector from './LanguageSelector'
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
  oidc: 'providerOidc',
  google_iap: 'providerIap',
  local_dev: 'providerLocal',
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
  const { t } = useTranslation(['common', 'auth'])
  const [status, setStatus] = useState('checking')
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
        <Toolbar sx={{ gap: 2, flexWrap: 'wrap', py: 1 }}>
          <Typography variant="h6" sx={{ flexGrow: 1, textAlign: 'start' }}>{t('appName')}</Typography>
          <LanguageSelector />
        </Toolbar>
      </AppBar>

      <Container maxWidth="lg" sx={{ mt: 4 }}>
        <Typography variant="h4" gutterBottom>
          {t('dashboard')}
        </Typography>

        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            {t('backendStatus')}
          </Typography>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            {status === 'checking' ? (
              <CircularProgress size={24} aria-label={t('checkingConnection')} />
            ) : (
              <Chip
                label={t(status)}
                color={status === 'connected' ? 'success' : 'error'}
              />
            )}
          </Box>
        </Paper>

        <Paper sx={{ p: 3, mt: 3 }}>
          <Typography variant="h6" gutterBottom>
            {t('auth:title')}
          </Typography>

          <Box aria-live="polite">
            {loginFailed && authentication.status !== 'authenticated' && (
              <Alert severity="error" sx={{ mb: 2 }}>{t('auth:loginFailed')}</Alert>
            )}
            {logoutFailed && (
              <Alert severity="error" sx={{ mb: 2 }}>{t('auth:logoutFailed')}</Alert>
            )}
            {authentication.status === 'loading' && (
              <CircularProgress size={24} aria-label={t('auth:checking')} />
            )}
            {authentication.status === 'unauthenticated' && (
              <Alert severity="info">{t('auth:unauthenticated')}</Alert>
            )}
            {authentication.status === 'error' && (
              <Alert severity="error">{t('auth:identityError')}</Alert>
            )}
            {authentication.status === 'authenticated' && (
              <Box component="dl" sx={{ m: 0, textAlign: 'start' }}>
                <Typography component="dt" color="text.secondary">{t('auth:provider')}</Typography>
                <Typography component="dd" sx={{ m: 0, mb: 2 }}>
                  {t(`auth:${providerNames[authentication.identity.provider]}`)}
                </Typography>
                <Typography component="dt" color="text.secondary">{t('auth:displayName')}</Typography>
                <Typography component="dd" sx={{ m: 0, mb: 2 }}>
                  <bdi>{authentication.identity.display_name || t('notProvided')}</bdi>
                </Typography>
                <Typography component="dt" color="text.secondary">{t('auth:email')}</Typography>
                <Typography component="dd" sx={{ m: 0, overflowWrap: 'anywhere' }}>
                  <bdi>{authentication.identity.email || t('notProvided')}</bdi>
                </Typography>
              </Box>
            )}
            {oidcEnabled && authentication.status === 'unauthenticated' && (
              <Button variant="contained" href="/api/auth/login" sx={{ mt: 2 }}>{t('auth:signIn')}</Button>
            )}
            {authentication.status === 'authenticated' && authentication.identity.provider === 'oidc' && (
              <Button variant="outlined" onClick={() => void logout()} disabled={loggingOut} sx={{ mt: 2 }}>
                {t(loggingOut ? 'auth:signingOut' : 'auth:signOut')}
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
