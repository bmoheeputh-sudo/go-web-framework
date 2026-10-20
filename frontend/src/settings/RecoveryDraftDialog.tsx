import { useRef, useState } from 'react'
import { Alert, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TextField, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { APIError } from '../api/client'
import { createRecoveryDraft } from '../api/authConfiguration'
import type { AuthRevision } from '../api/authConfiguration'
import { useSession } from '../auth/session'
import { useAuthenticationCacheSync } from '../api/authCache'
import { useNotifications } from '../notifications/notifications'

const validReason = (value: string) => {
  const reason = value.trim()
  return reason.length >= 8 && reason.length <= 512 && ![...reason].some((character) => {
    const code = character.charCodeAt(0)
    return code < 32 || code === 127
  })
}

export default function RecoveryDraftDialog({ revision, latestVersion, open, onClose, onCreated }: {
  revision: AuthRevision
  latestVersion: number
  open: boolean
  onClose: () => void
  onCreated: (revision: AuthRevision) => void
}) {
  const { t } = useTranslation(['auth', 'common'])
  const notify = useNotifications()
  const { refreshAfterChange } = useAuthenticationCacheSync()
  const { expire } = useSession()
  const [reason, setReason] = useState(''), [busy, setBusy] = useState(false), [failed, setFailed] = useState(false)
  const submitting = useRef(false)
  async function create() {
    if (submitting.current || !validReason(reason)) return
    submitting.current = true; setBusy(true); setFailed(false)
    try {
      const result = await createRecoveryDraft(revision.id, latestVersion, reason.trim())
      refreshAfterChange()
      notify({ severity: 'success', messageKey: 'auth:recoveryDraftCreated' })
      onCreated(result.revision)
    } catch (error) {
      if (error instanceof APIError && error.status === 401) expire()
      setFailed(true)
      notify({ severity: 'error', messageKey: 'auth:recoveryDraftFailed' })
    } finally { submitting.current = false; setBusy(false) }
  }
  return <Dialog open={open} onClose={() => { if (!busy) onClose() }} fullWidth maxWidth="sm" aria-labelledby="recovery-draft-title">
    <DialogTitle id="recovery-draft-title">{t('recoveryDraftTitle')}</DialogTitle>
    <DialogContent>
      <Stack spacing={2} sx={{ pt: 1 }}>
        <Alert severity="info">{t('recoveryDraftExplanation')}</Alert>
        <Typography>{t('recoveryHistoricalRevision')}: <bdi>{revision.id}</bdi></Typography>
        <Alert severity="warning">{t('recoveryFreshEvidenceRequired')}</Alert>
        {failed && <Alert severity="error">{t('recoveryDraftFailed')}</Alert>}
        <TextField required multiline minRows={2} label={t('activationReason')} value={reason} disabled={busy}
          error={reason.length > 0 && !validReason(reason)} helperText={t('activationReasonHelp')}
          onChange={(event) => setReason(event.target.value)} slotProps={{ htmlInput: { maxLength: 512 } }} />
      </Stack>
    </DialogContent>
    <DialogActions>
      <Button disabled={busy} onClick={onClose}>{t('common:cancel')}</Button>
      <Button variant="contained" disabled={busy || !validReason(reason)} onClick={() => void create()}>{t('recoveryCreateAction')}</Button>
    </DialogActions>
  </Dialog>
}
