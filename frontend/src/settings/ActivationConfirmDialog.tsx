import { useState } from 'react'
import {
  Alert, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle,
  FormControlLabel, Stack, TextField, Typography,
} from '@mui/material'
import { useTranslation } from 'react-i18next'
import type { Identity } from '../api/client'
import type { ActivationPreparation, AuthRevision } from '../api/authConfiguration'

export type ActivationConfirmation = {
  reason: string
  transitionSeconds: number
  acknowledgeReauthentication: boolean
  acknowledgeEmergencyRecovery: boolean
}

const validReason = (value: string) => {
  const reason = value.trim()
  return reason.length >= 8 && reason.length <= 512 && ![...reason].some((character) => {
    const code = character.charCodeAt(0)
    return code < 32 || code === 127
  })
}

export default function ActivationConfirmDialog({ open, revision, preparation, identity, enrolledUserID, expired, busy, onClose, onConfirm }: {
  open: boolean
  revision: AuthRevision
  preparation: ActivationPreparation
  identity: Identity
  enrolledUserID: string
  expired: boolean
  busy: boolean
  onClose: () => void
  onConfirm: (confirmation: ActivationConfirmation) => void
}) {
  const { t } = useTranslation(['auth', 'common'])
  const firstCutover = preparation.requires_reauthentication
  const [reason, setReason] = useState('')
  const [transition, setTransition] = useState(0)
  const [reauthentication, setReauthentication] = useState(false)
  const [recovery, setRecovery] = useState(false)
  const allowed = !busy && !expired && validReason(reason) && transition >= 0 && transition <= preparation.maximum_transition_seconds &&
    (!firstCutover || (transition === 0 && reauthentication && recovery))
  return <Dialog open={open} onClose={() => { if (!busy) onClose() }} fullWidth maxWidth="sm" aria-labelledby="activation-confirm-title">
    <DialogTitle id="activation-confirm-title">{t('activationConfirmTitle')}</DialogTitle>
    <DialogContent>
      <Stack spacing={2} sx={{ pt: 1, overflowWrap: 'anywhere' }}>
        <Alert severity="warning">{t(firstCutover ? 'activationFirstCutoverWarning' : 'activationTransitionWarning')}</Alert>
        <Typography><strong>{t('provider')}:</strong> OIDC</Typography>
        <Typography><strong>{t('activationTargetRevision')}:</strong> <bdi>{revision.id}</bdi></Typography>
        <Typography><strong>{t('activationGenerations')}:</strong> {preparation.expected_activation_generation} → {preparation.target_activation_generation}</Typography>
        <Typography><strong>{t('issuerURL')}:</strong> <bdi>{identity.issuer}</bdi></Typography>
        <Typography><strong>{t('activationVerifiedSubject')}:</strong> <bdi>{identity.subject}</bdi></Typography>
        <Typography><strong>{t('activationEnrolledUser')}:</strong> <bdi>{enrolledUserID}</bdi></Typography>
        <Typography><strong>{t('activationEvidenceStatus')}:</strong> {t('activationEvidenceReady')}</Typography>
        <Typography><strong>{t('activationRecoveryProcedure')}:</strong> {t('activationRecoveryProcedureName')}</Typography>
        <Typography variant="body2" color="text.secondary">{t('activationRecoveryRunbook')}</Typography>
        <TextField required multiline minRows={2} label={t('activationReason')} value={reason} disabled={busy || expired}
          error={reason.length > 0 && !validReason(reason)} helperText={t('activationReasonHelp')}
          onChange={(event) => setReason(event.target.value)} slotProps={{ htmlInput: { maxLength: 512 } }} />
        {!firstCutover && <TextField type="number" label={t('activationTransitionSeconds')} value={transition} disabled={busy || expired}
          helperText={t('activationTransitionHelp', { maximum: preparation.maximum_transition_seconds })}
          onChange={(event) => setTransition(Math.max(0, Math.min(preparation.maximum_transition_seconds, Number(event.target.value) || 0)))}
          slotProps={{ htmlInput: { min: 0, max: preparation.maximum_transition_seconds, step: 1 } }} />}
        {firstCutover && <>
          <FormControlLabel control={<Checkbox checked={reauthentication} disabled={busy || expired} onChange={(_, checked) => setReauthentication(checked)} />}
            label={t('activationAcknowledgeReauthentication')} />
          <FormControlLabel control={<Checkbox checked={recovery} disabled={busy || expired} onChange={(_, checked) => setRecovery(checked)} />}
            label={t('activationAcknowledgeRecovery')} />
        </>}
        {expired && <Alert severity="error">{t('activationPreparationExpired')}</Alert>}
      </Stack>
    </DialogContent>
    <DialogActions>
      <Button disabled={busy} onClick={onClose}>{t('common:cancel')}</Button>
      <Button variant="contained" disabled={!allowed} onClick={() => onConfirm({
        reason: reason.trim(), transitionSeconds: firstCutover ? 0 : transition,
        acknowledgeReauthentication: firstCutover && reauthentication,
        acknowledgeEmergencyRecovery: firstCutover && recovery,
      })}>{t('activationConfirmAction')}</Button>
    </DialogActions>
  </Dialog>
}
