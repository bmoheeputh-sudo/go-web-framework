import { Alert, Button, CircularProgress, Stack, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import type { AuthRevision, ConnectionTest } from '../api/authConfiguration'
import type { User } from '../api/client'
import DetailDrawer from '../components/common/DetailDrawer'
import TwoColumnKeyValue from '../components/common/TwoColumnKeyValue'
import StatusBadge from '../components/common/StatusBadge'
import type { DetailItem } from '../components/common/TwoColumnKeyValue'
import { formatDate, formatNumber } from '../i18n'
import OIDCConnectionTest from './OIDCConnectionTest'

export default function RevisionDetailDrawer({ open, revision, loading, disabled, onClose, onValidate, onApprove, onPrepare, onRecovery, onTestResult, onEnrolled }: {
  open: boolean
  revision?: AuthRevision
  loading: boolean
  disabled: boolean
  onClose: () => void
  onValidate: (revision: AuthRevision) => void
  onApprove: (revision: AuthRevision) => void
  onPrepare: (revision: AuthRevision) => void
  onRecovery: (revision: AuthRevision) => void
  onTestResult: (result: ConnectionTest | null) => void
  onEnrolled: (user: User) => void
}) {
  const { t, i18n } = useTranslation(['auth', 'common'])
  const language = i18n.resolvedLanguage || 'en'
  const date = (value?: string) => value ? formatDate(value, language) : t('common:none')
  const value = (text: string) => <bdi>{text || t('common:none')}</bdi>
  const items: DetailItem[] = revision ? [
    { label: t('provider'), value: value(revision.provider) },
    { label: t('common:status'), value: <StatusBadge label={t(`revisionStatus_${revision.status}`)} tone={revision.status === 'active' ? 'success' : revision.status === 'approved' ? 'info' : 'neutral'} /> },
    { label: t('revisionID'), value: value(revision.id) },
    { label: t('activationAuthoritativeGeneration'), value: formatNumber(revision.generation, language) },
    { label: t('deployment'), value: value(revision.deployment_id) },
    { label: t('environment'), value: value(revision.environment) },
    { label: t('creator'), value: value(revision.created_by) },
    { label: t('createdAt'), value: date(revision.created_at) },
    { label: t('validatedAt'), value: date(revision.validated_at) },
    { label: t('approvedAt'), value: date(revision.approved_at) },
    { label: t('secretIndicator'), value: t(revision.has_secret ? 'secretPresent' : 'secretAbsent') },
    ...(revision.provider === 'oidc' ? [
      { label: t('issuerURL'), value: value(revision.issuer_url) },
      { label: t('clientID'), value: value(revision.client_id) },
      { label: t('redirectURI'), value: value(revision.redirect_uri) },
      { label: t('allowHTTP'), value: t(revision.allow_http_development ? 'yes' : 'no') },
    ] : []),
    ...(revision.provider === 'google_iap' ? [{ label: t('iapAudience'), value: value(revision.iap_audience) }] : []),
  ] : []
  const actions = revision && <>
    {revision.status === 'draft' && <Button variant="contained" disabled={disabled} onClick={() => onValidate(revision)}>{t('validateSettings')}</Button>}
    {revision.status === 'validated' && <Button variant="contained" disabled={disabled} onClick={() => onApprove(revision)}>{t('approveRevision')}</Button>}
    {revision.status === 'approved' && revision.provider === 'oidc' && <Button variant="contained" disabled={disabled} onClick={() => onPrepare(revision)}>{t('activationPrepare')}</Button>}
    {revision.status === 'superseded' && revision.provider === 'oidc' && <Button variant="outlined" disabled={disabled} onClick={() => onRecovery(revision)}>{t('recoveryCreateAction')}</Button>}
  </>
  return <DetailDrawer open={open} onClose={onClose} title={t('revisionMetadata')} actions={actions}>
    <Stack spacing={2} role="region" aria-label={t('revisionMetadata')}>
      {loading && <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}><CircularProgress size={20} /><Typography>{t('common:loading')}</Typography></Stack>}
      {!loading && !revision && <Alert severity="warning">{t('settingsUnavailable')}</Alert>}
      {revision && <>
        <Typography variant="subtitle1">{t('revisionLabel', { version: formatNumber(revision.configuration_version, language) })}</Typography>
        <TwoColumnKeyValue items={items} />
        {revision.status === 'approved' && revision.provider === 'oidc' && <OIDCConnectionTest key={revision.id} revision={revision} disabled={disabled}
          onResult={onTestResult} onEnrolled={onEnrolled} />}
      </>}
    </Stack>
  </DetailDrawer>
}
