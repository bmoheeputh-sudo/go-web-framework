import {
  Alert, Checkbox,
  FormControlLabel, Stack, TextField, Typography,
} from '@mui/material'
import { useTranslation } from 'react-i18next'
import type { Identity } from '../api/client'
import type { ActivationPreparation, AuthRevision } from '../api/authConfiguration'
import { validReason } from './activationConfirmation'
import type { ActivationConfirmation } from './activationConfirmation'

export default function ActivationConfirmationStep({ revision, preparation, identity, enrolledUserID, expired, busy, value, onChange }: {
  revision: AuthRevision
  preparation: ActivationPreparation
  identity: Identity
  enrolledUserID: string
  expired: boolean
  busy: boolean
  value: ActivationConfirmation
  onChange: (value: ActivationConfirmation) => void
}) {
  const { t } = useTranslation(['auth', 'common'])
  const firstCutover = preparation.requires_reauthentication
  return <Stack spacing={2} component="section" aria-label={t('activationConfirmTitle')} sx={{ overflowWrap: 'anywhere' }}>
        <Typography component="h3" variant="h6">{t('activationConfirmTitle')}</Typography>
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
        <TextField required multiline minRows={2} label={t('activationReason')} value={value.reason} disabled={busy || expired}
          error={value.reason.length > 0 && !validReason(value.reason)} helperText={t('activationReasonHelp')}
          onChange={(event) => onChange({ ...value, reason: event.target.value })} slotProps={{ htmlInput: { maxLength: 512 } }} />
        {!firstCutover && <TextField type="number" label={t('activationTransitionSeconds')} value={value.transitionSeconds} disabled={busy || expired}
          helperText={t('activationTransitionHelp', { maximum: preparation.maximum_transition_seconds })}
          onChange={(event) => onChange({ ...value, transitionSeconds: Math.max(0, Math.min(preparation.maximum_transition_seconds, Number(event.target.value) || 0)) })}
          slotProps={{ htmlInput: { min: 0, max: preparation.maximum_transition_seconds, step: 1 } }} />}
        {firstCutover && <>
          <FormControlLabel control={<Checkbox checked={value.acknowledgeReauthentication} disabled={busy || expired} onChange={(_, checked) => onChange({ ...value, acknowledgeReauthentication: checked })} />}
            label={t('activationAcknowledgeReauthentication')} />
          <FormControlLabel control={<Checkbox checked={value.acknowledgeEmergencyRecovery} disabled={busy || expired} onChange={(_, checked) => onChange({ ...value, acknowledgeEmergencyRecovery: checked })} />}
            label={t('activationAcknowledgeRecovery')} />
        </>}
        {expired && <Alert severity="error">{t('activationPreparationExpired')}</Alert>}
  </Stack>
}
