import { Alert, Box, Button, Stack, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import type { ActivationResult, ActivationStatus } from '../api/authConfiguration'
import SectionCard from '../components/common/SectionCard'

export type DisplayedOutcome = ActivationResult | { outcome: 'outcome_unknown'; desired_generation: number; revision_id: string }

export default function ActivationOutcomePanel({ outcome, status, busy, onInspect, onReconcile, onReset }: {
  outcome: DisplayedOutcome
  status?: ActivationStatus
  busy: boolean
  onInspect: () => void
  onReconcile: () => void
  onReset: () => void
}) {
  const { t } = useTranslation('auth')
  const uncertain = outcome.outcome === 'commit_uncertain' || outcome.outcome === 'outcome_unknown'
  const committedNotApplied = outcome.outcome === 'committed_not_applied'
  const notCommitted = outcome.outcome === 'not_committed'
  const severity = outcome.outcome === 'committed_applied' ? 'success' : uncertain || committedNotApplied ? 'warning' : 'error'
  const key = `activationOutcome_${outcome.outcome}`
  return <Box aria-live="assertive">
    <SectionCard title={t('activationOutcomeTitle')}>
    <Stack spacing={2}>
      <Alert severity={severity}>{t(key)}</Alert>
      {'commit_persisted' in outcome && <>
        <Typography>{t('activationCommitPersisted')}: {outcome.commit_persisted === null ? t('activationUnknown') : t(outcome.commit_persisted ? 'yes' : 'no')}</Typography>
        <Typography>{t('activationDesiredGeneration')}: {outcome.desired_generation}</Typography>
        <Typography>{t('activationAppliedGeneration')}: {outcome.applied_generation}</Typography>
      </>}
      {status && <Typography>{t('activationAuthoritativeComparison', {
        authoritative: status.authoritative_generation, local: status.local_applied_generation,
      })}</Typography>}
      {(uncertain || committedNotApplied) && <Alert severity="info">{t('activationNoRetry')}</Alert>}
      {uncertain && <Button disabled={busy} onClick={onInspect}>{t('activationInspectStatus')}</Button>}
      {committedNotApplied && <Stack direction="row" sx={{ gap: 1, flexWrap: 'wrap' }}>
        <Button disabled={busy} onClick={onInspect}>{t('activationRefreshStatus')}</Button>
        <Button variant="contained" disabled={busy || !status || !status.reconciliation_required} onClick={onReconcile}>{t('activationReconcile')}</Button>
      </Stack>}
      {notCommitted && <Button disabled={busy} onClick={onReset}>{t('activationStartOver')}</Button>}
      {outcome.outcome === 'committed_applied' && <Alert severity="info">{t('activationReauthenticateGuidance')}</Alert>}
    </Stack>
    </SectionCard>
  </Box>
}
