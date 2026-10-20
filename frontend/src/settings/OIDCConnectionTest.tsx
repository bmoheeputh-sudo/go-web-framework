import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react'
import { Accordion, AccordionDetails, AccordionSummary, Alert, Button, Stack, Typography } from '@mui/material'
import ExpandMore from '@mui/icons-material/ExpandMore'
import { useTranslation } from 'react-i18next'
import { api, APIError } from '../api/client'
import type { AuthRevision, ConnectionTest, StartedConnectionTest } from '../api/authConfiguration'
import type { User } from '../api/client'
import { authSettingsPath } from '../api/authConfiguration'
import { useQueryCache } from '../api/queries'
import { useSession } from '../auth/session'
import { useNotifications } from '../notifications/notifications'
import { formatNumber } from '../i18n'
import IdentityEnrollment from './IdentityEnrollment'

type Run = { popup: Window; id?: string; stopped: boolean; timer?: ReturnType<typeof setTimeout>; deadlineTimer?: ReturnType<typeof setTimeout>; controller: AbortController }
const testPath = (id: string) => `/api/admin/auth/tests/${encodeURIComponent(id)}`
const pending = (test: ConnectionTest) => ['checking', 'pending', 'processing'].includes(test.status)
function stop(run: Run) {
  run.stopped = true
  clearTimeout(run.timer)
  clearTimeout(run.deadlineTimer)
  run.controller.abort()
  try { run.popup.close() } catch { /* COOP may sever the window reference. */ }
}

function releasePopup(run: Run) {
  run.stopped = true
  clearTimeout(run.timer)
  clearTimeout(run.deadlineTimer)
  run.controller.abort()
}

export type OIDCConnectionTestHandle = { start: (popup?: Window) => void }

const OIDCConnectionTest = forwardRef<OIDCConnectionTestHandle, {
  revision: AuthRevision; disabled: boolean
  externalTrigger?: boolean
  showEnrollment?: boolean
  inlineEnrollment?: boolean
  guided?: boolean
  onBusyChange?: (busy: boolean) => void
  onResult?: (result: ConnectionTest | null) => void
  onEnrolled?: (user: User) => void
  onVerifiedPopup?: (popup: Window, result: ConnectionTest) => void
}>(function OIDCConnectionTest({ revision, disabled, externalTrigger = false, showEnrollment = true, inlineEnrollment = false, guided = false, onBusyChange, onResult, onEnrolled, onVerifiedPopup }, ref) {
  const { t, i18n } = useTranslation('auth')
  const notify = useNotifications(), cache = useQueryCache(), { expire } = useSession()
  const active = useRef<Run | null>(null)
  const [busy, setBusy] = useState(false), [result, setResult] = useState<ConnectionTest | null>(null)
  const [error, setError] = useState(false)
  useEffect(() => () => {
    onBusyChange?.(false)
    const run = active.current
    if (run && !run.stopped) {
      stop(run)
      if (run.id) void api(testPath(run.id) + '/cancel', 'POST', {}).catch(() => { /* Server expiry still applies. */ })
    }
  }, [onBusyChange])
  function fail(run: Run, error: unknown) {
    if (run.stopped) return
    stop(run); setBusy(false); onBusyChange?.(false); setError(true)
    if (error instanceof APIError && error.status === 401) expire()
    if (error instanceof APIError && error.status === 409) {
      notify({ severity: 'warning', messageKey: 'auth:revisionConflict' }); cache.invalidate()
    } else notify({ severity: 'error', messageKey: 'auth:testUnavailable' })
  }
  function accept(run: Run, value: ConnectionTest) {
    setResult(value); onResult?.(value)
    if (pending(value)) return false
    if (value.status === 'succeeded' && onVerifiedPopup) {
      releasePopup(run)
      active.current = null
      onVerifiedPopup(run.popup, value)
    } else stop(run)
    setBusy(false); onBusyChange?.(false)
    notify({ severity: value.status === 'succeeded' ? 'success' : value.status === 'failed' ? 'error' : 'warning', messageKey: `auth:test_${value.status}` })
    return true
  }
  async function cancel(run: Run) {
    if (run.stopped || !run.id) return
    clearTimeout(run.timer)
    try {
      const value = await api<ConnectionTest>(testPath(run.id) + '/cancel', 'POST', {}, run.controller.signal)
      if (!run.stopped) accept(run, value)
    } catch (error) { fail(run, error) }
  }
  async function poll(run: Run, deadline: number) {
    if (run.stopped || !run.id) return
    try {
      const value = await api<ConnectionTest>(testPath(run.id), 'GET', undefined, run.controller.signal)
      if (run.stopped || accept(run, value)) return
      // A server response remains authoritative; a client deadline only bounds
      // polling when the network cannot report expiry. Cross-origin window
      // properties are never inspected while the identity provider is open.
      if (Date.now() > deadline + 15_000) { fail(run, new Error('test deadline')); return }
      run.timer = setTimeout(() => void poll(run, deadline), 2000)
    } catch (error) { fail(run, error) }
  }
  async function start(existingPopup?: Window) {
    if (active.current && !active.current.stopped) return
    const popup = existingPopup ?? window.open('about:blank', '_blank', 'popup,width=520,height=720')
    if (!popup) { notify({ severity: 'warning', messageKey: 'auth:testPopupBlocked' }); return }
    popup.opener = null // Provider pages cannot navigate the administrator's window.
    const run: Run = { popup, stopped: false, controller: new AbortController() }
    active.current = run; setBusy(true); onBusyChange?.(true); setError(false); setResult(null); onResult?.(null)
    run.timer = setTimeout(() => fail(run, new Error('start deadline')), 25_000)
    try {
      const started = await api<StartedConnectionTest>(`${authSettingsPath}/${encodeURIComponent(revision.id)}/test`, 'POST', { expected_generation: revision.generation }, run.controller.signal)
      if (run.stopped) return
      clearTimeout(run.timer); run.id = started.id
      const { authorization_url: authorizationURL, ...value } = started
      if (accept(run, value)) return
      const location = new URL(authorizationURL || '')
      if (location.protocol !== 'https:' || location.origin !== new URL(revision.issuer_url).origin || location.username || location.password) throw new Error('invalid test URL')
      popup.location.replace(location.href)
      run.deadlineTimer = setTimeout(() => fail(run, new Error('test deadline')), Math.max(0, Math.min(315_000, Date.parse(value.expires_at) - Date.now() + 15_000)))
      run.timer = setTimeout(() => void poll(run, Date.parse(value.expires_at)), 2000)
    } catch (error) { fail(run, error) }
  }
  useImperativeHandle(ref, () => ({ start: (popup?: Window) => { if (!disabled) void start(popup) } }))
  return <Stack spacing={2} sx={{ mt: 2, minWidth: 0 }}>
    {!guided && <Alert severity="info">{t('testHelp')}</Alert>}
    <Stack direction="row" sx={{ gap: 1, flexWrap: 'wrap' }}>
      {!externalTrigger && <Button variant="outlined" disabled={disabled || busy} onClick={() => void start()}>{t('testConnection')}</Button>}
      {busy && <Button onClick={() => { if (active.current?.id) void cancel(active.current); else if (active.current) { stop(active.current); setBusy(false); onBusyChange?.(false); notify({ severity: 'warning', messageKey: 'auth:test_cancelled' }) } }}>{t('testCancel')}</Button>}
    </Stack>
    {busy && <Typography role="status">{t('testInProgress')}</Typography>}
    {error && <Alert severity="error">{t('testUnavailable')}</Alert>}
    {result && <Stack spacing={1} sx={{ overflowWrap: 'anywhere' }}>
      <Typography>{t(`test_${result.status}`)}</Typography>
      {result.status === 'succeeded' && result.tested_identity && <Typography variant="body2" color="text.secondary">{t('testIdentity')}</Typography>}
      <Accordion disableGutters variant="outlined" sx={{ '&::before': { display: 'none' } }}>
        <AccordionSummary expandIcon={<ExpandMore />}>{t('technicalDetails')}</AccordionSummary>
        <AccordionDetails><Stack spacing={1}>
          <Typography>{t('revisionLabel', { version: formatNumber(result.configuration_version, i18n.resolvedLanguage || 'en') })}</Typography>
          <Typography>{t('testCallback')}: <bdi>{result.callback_uri}</bdi></Typography>
          {result.tested_identity && <Typography><bdi>{result.tested_identity.issuer}</bdi> · <bdi>{result.tested_identity.subject}</bdi></Typography>}
        </Stack></AccordionDetails>
      </Accordion>
      {showEnrollment && result.evidence_id && <IdentityEnrollment key={result.evidence_id} revision={revision} result={result} disabled={disabled || busy} inlineConfirmation={inlineEnrollment} onEnrolled={onEnrolled} />}
    </Stack>}
  </Stack>
})

export default OIDCConnectionTest
