import { useRef, useState } from 'react'
import { Alert, Box, Checkbox, FormControlLabel, IconButton, InputAdornment, MenuItem, Stack, TextField } from '@mui/material'
import Visibility from '@mui/icons-material/Visibility'
import VisibilityOff from '@mui/icons-material/VisibilityOff'
import { useTranslation } from 'react-i18next'
import type { AuthProvider, NewAuthDraft } from '../api/authConfiguration'

function validOIDC(issuer: string, redirect: string, allowHTTP: boolean) {
  try {
    const i = new URL(issuer), r = new URL(redirect)
    return i.protocol === 'https:' && !i.username && !i.password && !i.search && !i.hash &&
      !r.username && !r.password && !r.search && !r.hash && r.pathname === '/api/auth/callback' &&
      (r.protocol === 'https:' || (allowHTTP && r.protocol === 'http:' &&
        (r.hostname === 'localhost' || r.hostname === '[::1]' || /^127(?:\.\d{1,3}){3}$/.test(r.hostname))))
  } catch { return false }
}
const audiencePattern = /^\/projects\/[0-9]+\/(apps\/[a-z][a-z0-9-]*|global\/backendServices\/[0-9]+|locations\/[a-z][a-z0-9-]*\/services\/[a-z][a-z0-9-]*)$/
export const authDraftFormID = 'auth-draft-form'

export default function AuthDraftForm({ development, latestVersion, busy, trustedRedirectURI, onCreate }: {
  development: boolean; latestVersion: number; busy: boolean; trustedRedirectURI?: string; onCreate: (body: NewAuthDraft) => Promise<boolean>
}) {
  const { t } = useTranslation(['auth', 'common', 'admin'])
  const [provider, setProvider] = useState<AuthProvider>('oidc')
  const [issuer, setIssuer] = useState(''), [clientID, setClientID] = useState('')
  const [secret, setSecret] = useState(''), [showSecret, setShowSecret] = useState(false)
  const [enteredRedirect, setEnteredRedirect] = useState(''), [audience, setAudience] = useState('')
  const [allowHTTP, setAllowHTTP] = useState(false), [invalid, setInvalid] = useState(false)
  const submitting = useRef(false)
  const redirect = trustedRedirectURI || enteredRedirect
  async function submit(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || submitting.current) return
    const valid = provider === 'oidc' ? Boolean(clientID.trim() && secret.trim() && validOIDC(issuer.trim(), redirect.trim(), development && allowHTTP))
      : provider === 'google_iap' ? audiencePattern.test(audience.trim()) : development
    if (!valid) { setInvalid(true); return }
    const body: NewAuthDraft = provider === 'oidc'
      ? { provider, expected_latest_version: latestVersion, issuer_url: issuer.trim(), client_id: clientID.trim(), client_secret: secret, redirect_uri: redirect.trim(), allow_http_development: development && allowHTTP }
      : provider === 'google_iap' ? { provider, expected_latest_version: latestVersion, iap_audience: audience.trim() }
        : { provider, expected_latest_version: latestVersion }
    submitting.current = true
    setSecret(''); setShowSecret(false); setInvalid(false)
    try { await onCreate(body) } // Only the request owns the submitted secret; never persisted or cached.
    finally { submitting.current = false }
  }
  return <Box component="form" id={authDraftFormID} onSubmit={(event) => void submit(event)}
    onKeyDown={(event) => {
      // The submit button lives in DialogActions outside the form; preserve Enter on text inputs.
      if (event.key === 'Enter' && event.target instanceof HTMLInputElement && event.target.type !== 'hidden') {
        event.preventDefault()
        event.currentTarget.requestSubmit()
      }
    }}
    noValidate autoComplete="off" sx={{ pt: 1, minWidth: 0 }} aria-label={t('newDraft')}>
    <Stack spacing={2}>
      {invalid && <Alert severity="error">{t('admin:errorInvalid')}</Alert>}
      <TextField select fullWidth label={t('provider')} value={provider} disabled={busy} onChange={(event) => {
        setProvider(event.target.value as AuthProvider); setSecret(''); setShowSecret(false); setInvalid(false)
      }}>
        <MenuItem value="oidc">{t('providerOidc')}</MenuItem>
        <MenuItem value="google_iap">{t('providerIap')}</MenuItem>
        <MenuItem value="local_dev" disabled={!development}>{t('providerLocal')}</MenuItem>
      </TextField>
      {!development && <Alert severity="info">{t('developmentUnavailable')}</Alert>}
      {provider === 'oidc' && <>
        <TextField required fullWidth label={t('issuerURL')} value={issuer} disabled={busy} onChange={(e) => setIssuer(e.target.value)} slotProps={{ htmlInput: { maxLength: 2048, dir: 'ltr' } }} />
        <TextField required fullWidth label={t('clientID')} value={clientID} disabled={busy} onChange={(e) => setClientID(e.target.value)} slotProps={{ htmlInput: { maxLength: 512, dir: 'ltr' } }} />
        <TextField required fullWidth label={t('clientSecret')} type={showSecret ? 'text' : 'password'} value={secret} disabled={busy}
          autoComplete="new-password" onChange={(e) => setSecret(e.target.value)} helperText={t('secretRequired')}
          slotProps={{ htmlInput: { maxLength: 4096, dir: 'ltr', spellCheck: false }, input: { endAdornment: <InputAdornment position="end"><IconButton disabled={busy} aria-label={t(showSecret ? 'hideSecret' : 'showSecret')} aria-pressed={showSecret} onClick={() => setShowSecret(!showSecret)}>{showSecret ? <VisibilityOff /> : <Visibility />}</IconButton></InputAdornment> } }} />
        <TextField required fullWidth label={t('redirectURI')} value={redirect} disabled={busy} onChange={(e) => setEnteredRedirect(e.target.value)}
          helperText={trustedRedirectURI ? t('setupTrustedRedirect') : undefined}
          slotProps={{ htmlInput: { maxLength: 2048, dir: 'ltr', readOnly: Boolean(trustedRedirectURI) } }} />
        {development && <FormControlLabel label={t('allowHTTP')} control={<Checkbox disabled={busy} checked={allowHTTP} onChange={(_, value) => setAllowHTTP(value)} />} />}
      </>}
      {provider === 'google_iap' && <>
        <Alert severity="info">{t('iapHelp')}</Alert>
        <TextField fullWidth required label={t('iapAudience')} disabled={busy} value={audience} onChange={(e) => setAudience(e.target.value)} slotProps={{ htmlInput: { maxLength: 512, dir: 'ltr' } }} />
      </>}
      {provider === 'local_dev' && <Alert severity="warning">{t('localHelp')}</Alert>}
    </Stack>
  </Box>
}
