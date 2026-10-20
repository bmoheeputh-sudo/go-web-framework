import { useEffect, useState } from 'react'
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, MenuItem, Stack, TextField, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { api, APIError } from '../api/client'
import type { AuthRevision, ConnectionTest } from '../api/authConfiguration'
import { authSettingsPath } from '../api/authConfiguration'
import { useSession } from '../auth/session'
import { useQueryCache } from '../api/queries'
import { useNotifications } from '../notifications/notifications'
import { formatDate, roleKeys } from '../i18n'
import type { User } from '../api/client'

const roles = ['Admin', 'User', 'Viewer'] as const

export default function IdentityEnrollment({ revision, result, disabled, onEnrolled, inlineConfirmation = false }: {
  revision: AuthRevision; result: ConnectionTest; disabled: boolean; onEnrolled?: (user: User) => void; inlineConfirmation?: boolean
}) {
  const { t, i18n } = useTranslation(['auth', 'admin', 'common'])
  const { authentication, access, expire } = useSession()
  const notify = useNotifications(), cache = useQueryCache()
  const [role, setRole] = useState(''), [confirm, setConfirm] = useState(false), [busy, setBusy] = useState(false), [done, setDone] = useState(false)
  const deadline = Date.parse(result.evidence_expires_at || '')
  const [expired, setExpired] = useState(() => !Number.isFinite(deadline) || deadline <= Date.now())
  useEffect(() => {
    if (expired) return
    const timer = setTimeout(() => setExpired(true), Math.max(0, Math.min(deadline - Date.now(), 300_000)))
    return () => clearTimeout(timer)
  }, [deadline, expired])
  const authorized = authentication.status === 'authenticated' && !access.loading && !access.error && access.user?.active && access.user.permissions.includes('admin.manage')
  if (!authorized || result.status !== 'succeeded' || !result.evidence_id || !result.tested_identity || revision.status !== 'approved' || revision.provider !== 'oidc' || result.revision_id !== revision.id || result.generation !== revision.generation) return null
  const blocked = disabled || busy || expired || done
  async function enroll() {
    if (blocked || !roles.some((r) => r === role) || Date.now() >= deadline) return
    setBusy(true)
    try {
      // The server resolves identity from evidence. No issuer, subject, email,
      // actor or deployment fields may be submitted by this form.
      const user = await api<User>(`${authSettingsPath}/${encodeURIComponent(revision.id)}/enroll`, 'POST', {
        evidence_id: result.evidence_id, expected_generation: revision.generation, role, confirm: true,
      })
      onEnrolled?.(user)
      setDone(true); setConfirm(false); cache.invalidate()
      notify({ severity: 'success', messageKey: 'auth:enrollmentSuccess' })
    } catch (error) {
      setConfirm(false)
      if (error instanceof APIError && error.status === 401) expire()
      const conflict = error instanceof APIError && error.status === 409
      if (conflict) setExpired(true)
      notify({ severity: conflict ? 'warning' : 'error', messageKey: conflict ? 'auth:enrollmentConflict' : 'auth:enrollmentFailed' })
    } finally { setBusy(false) }
  }
  const identity = <Stack spacing={1} sx={{ overflowWrap: 'anywhere' }}>
    <Typography>{t('issuerURL')}: <bdi>{result.tested_identity.issuer}</bdi></Typography>
    <Typography>{t('enrollmentSubject')}: <bdi>{result.tested_identity.subject}</bdi></Typography>
    <Typography>{t('enrollmentRevision')}: <bdi>{revision.id}</bdi> ({revision.configuration_version})</Typography>
    <Typography>{t('enrollmentFreshUntil', { date: formatDate(result.evidence_expires_at!, i18n.resolvedLanguage || 'en') })}</Typography>
  </Stack>
  return <Stack spacing={2}>
    <Alert severity="warning">{t('enrollmentHelp')}</Alert>
    {identity}
    {expired && <Alert severity="warning">{t('enrollmentConflict')}</Alert>}
    <TextField select label={t('enrollmentRole')} value={role} onChange={(event) => setRole(event.target.value)} disabled={blocked} fullWidth>
      {roles.map((value) => <MenuItem key={value} value={value}>{t(`admin:${roleKeys[value]}`)}</MenuItem>)}
    </TextField>
    <Button variant="outlined" disabled={blocked || !role} onClick={() => setConfirm(true)}>{t('enrollIdentity')}</Button>
    {inlineConfirmation && confirm && <Stack spacing={1} role="region" aria-label={t('enrollmentConfirm')}>
      <Alert severity="warning">{t('enrollmentGrant', { role: role ? t(`admin:${roleKeys[role]}`) : '' })}</Alert>
      <Stack direction="row" sx={{ gap: 1 }}>
        <Button disabled={busy} onClick={() => setConfirm(false)}>{t('common:cancel')}</Button>
        <Button variant="contained" disabled={blocked} onClick={() => void enroll()}>{t('enrollIdentity')}</Button>
      </Stack>
    </Stack>}
    {!inlineConfirmation && <Dialog open={confirm} onClose={() => { if (!busy) setConfirm(false) }} fullWidth maxWidth="sm" aria-labelledby="enrollment-confirm-title">
      <DialogTitle id="enrollment-confirm-title">{t('enrollmentConfirm')}</DialogTitle>
      <DialogContent><Stack spacing={2}>{identity}<Alert severity="warning">{t('enrollmentGrant', { role: role ? t(`admin:${roleKeys[role]}`) : '' })}</Alert></Stack></DialogContent>
      <DialogActions>
        <Button disabled={busy} onClick={() => setConfirm(false)}>{t('common:cancel')}</Button>
        <Button disabled={blocked} onClick={() => void enroll()}>{t('enrollIdentity')}</Button>
      </DialogActions>
    </Dialog>}
  </Stack>
}
