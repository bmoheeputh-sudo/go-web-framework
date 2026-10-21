import { useEffect, useRef, useState } from 'react'
import { Alert, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, Stack, TextField, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { AuthConfigurationError } from '../api/authConfiguration'
import { readNotificationSuppression, setNotificationSuppression } from '../api/notificationManagement'
import type { Suppression } from '../api/notificationManagement'
import TechnicalValue from '../components/common/TechnicalValue'
import { formatNumber } from '../i18n'
import { useSession } from '../auth/session'
import { useNotifications } from '../notifications/notifications'
import { notificationErrorKey, validNotificationReason } from './notificationManagementState'
import { useBeforeUnload } from 'react-router-dom'
import { useQueryCache } from '../api/queries'
import type { QueryCache } from '../api/cache'

const suppressionDrafts = new WeakMap<QueryCache, Map<string, { reason: string; active: boolean; blocked: boolean }>>()

export function NotificationPager({ offset, total, busy, onChange }: { offset: number; total: number; busy: boolean; onChange: (offset: number) => void }) {
  const { t, i18n } = useTranslation('common')
  return <Stack direction="row" sx={{ gap: 1, alignItems: 'center', flexWrap: 'wrap', mt: 2 }}>
    <Button disabled={busy || offset === 0} onClick={() => onChange(Math.max(0, offset - 20))}>{t('previousPage')}</Button>
    <Typography variant="body2">{t('page', { page: formatNumber(offset / 20 + 1, i18n.resolvedLanguage || 'en') })}</Typography>
    <Button disabled={busy || offset + 20 >= total || offset >= 100000} onClick={() => onChange(offset + 20)}>{t('nextPage')}</Button>
  </Stack>
}
export function SuppressionDialog({ target, onClose, onChanged }: { target: { ref: string; email: string }; onClose: () => void; onChanged: () => void }) {
  const { t } = useTranslation(['admin', 'common'])
  const session = useSession(), notify = useNotifications(), cache = useQueryCache()
  const saved = suppressionDrafts.get(cache)?.get(target.ref)
  const [record, setRecord] = useState<Suppression | null>(null), [active, setActive] = useState(saved?.active ?? true), [reason, setReason] = useState(saved?.reason || '')
  const [busy, setBusy] = useState(false), [error, setError] = useState(''), [blocked, setBlocked] = useState(saved?.blocked || false), [discard, setDiscard] = useState(false)
  const inFlight = useRef(false)
  useBeforeUnload((event) => { if (reason || busy) { event.preventDefault(); event.returnValue = '' } })
  useEffect(() => { const values = suppressionDrafts.get(cache) || new Map(); values.set(target.ref, { reason, active, blocked: blocked || busy }); suppressionDrafts.set(cache, values) }, [cache, target.ref, reason, active, blocked, busy])
  function clear() { suppressionDrafts.get(cache)?.delete(target.ref); onClose() }
  async function inspect() {
    if (inFlight.current) return
    inFlight.current = true
    setBusy(true)
    try { const value = await readNotificationSuppression(target.ref); setRecord(value); if (!reason) setActive(value.active); setBlocked(false); setError('') }
    catch (failure) { setError(notificationErrorKey(failure, false)) }
    finally { inFlight.current = false; setBusy(false) }
  }
  async function save() {
    if (inFlight.current || busy || blocked || !record || !validNotificationReason(reason)) return
    inFlight.current = true
    setBusy(true)
    try { const value = await setNotificationSuppression(target.ref, record.generation, active, reason); setRecord(value); notify({ severity: 'success', messageKey: 'admin:changesSaved' }); onChanged(); clear() }
    catch (failure) { setError(notificationErrorKey(failure, true)); setBlocked(true); if (failure instanceof AuthConfigurationError && failure.status === 401) session.expire() }
    finally { inFlight.current = false; setBusy(false) }
  }
  return <Dialog open fullWidth maxWidth="sm" aria-labelledby="notification-suppression-title" onClose={() => { if (!busy) setDiscard(true) }}>
    <DialogTitle id="notification-suppression-title">{t('nmSuppression')}</DialogTitle>
    <DialogContent dividers><Stack component="form" id="notification-suppression-form" spacing={2} onSubmit={(event) => { event.preventDefault(); void save() }}>
      <Typography><bdi>{target.email}</bdi></Typography>
      <TechnicalValue label={t('nmTargetReference')} value={target.ref} />
      <Alert severity="info">{t('nmSuppressionHelp')}</Alert>
      {!record && <Button disabled={busy} onClick={() => void inspect()}>{t('nmInspectSuppression')}</Button>}
      {record && <><FormControlLabel control={<Checkbox checked={active} onChange={(_, value) => setActive(value)} />} label={t('nmSuppressed')} /><TextField required multiline minRows={2} label={t('nmReason')} value={reason} onChange={(event) => setReason(event.target.value)} /></>}
      {error && <Alert severity="error">{t(error)}</Alert>}
      {blocked && <Button disabled={busy} onClick={() => void inspect()}>{t('nmInspectSuppression')}</Button>}
      {discard && <Alert severity="warning" action={<Button disabled={busy} onClick={clear}>{t('nmDiscard')}</Button>}>{t('nmUnsaved')}</Alert>}
    </Stack></DialogContent>
    <DialogActions><Button disabled={busy} onClick={() => { if (reason) setDiscard(true); else clear() }}>{t('common:close')}</Button><Button variant="contained" type="submit" form="notification-suppression-form" disabled={busy || blocked || !record || !validNotificationReason(reason)}>{t('nmSaveSuppression')}</Button></DialogActions>
  </Dialog>
}
