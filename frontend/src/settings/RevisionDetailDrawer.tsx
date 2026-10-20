import ContentCopy from '@mui/icons-material/ContentCopy'
import { useRef, useState } from 'react'
import { Alert, Button, CircularProgress, Divider, IconButton, Stack, Tooltip, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import type { AuthRevision, ConnectionTest } from '../api/authConfiguration'
import type { User } from '../api/client'
import DetailDrawer from '../components/common/DetailDrawer'
import TwoColumnKeyValue from '../components/common/TwoColumnKeyValue'
import StatusBadge from '../components/common/StatusBadge'
import type { DetailItem } from '../components/common/TwoColumnKeyValue'
import { formatDate, formatNumber } from '../i18n'
import { useNotifications } from '../notifications/notifications'
import OIDCConnectionTest from './OIDCConnectionTest'
import type { OIDCConnectionTestHandle } from './OIDCConnectionTest'

function TechnicalValue({ label, value }: { label: string; value: string }) {
  const { t } = useTranslation(['auth', 'common'])
  const notify = useNotifications()
  async function copy() {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('clipboard unavailable')
      await navigator.clipboard.writeText(value)
      notify({ severity: 'success', messageKey: 'auth:setupCopied', values: { field: label } })
    } catch { notify({ severity: 'error', messageKey: 'auth:setupCopyFailed', values: { field: label } }) }
  }
  return <Stack direction="row" sx={{ minWidth: 0, alignItems: 'flex-start', gap: 0.5 }}>
    <Typography component="span" variant="body2" sx={{ minWidth: 0, flex: 1, fontFamily: 'monospace', overflowWrap: 'anywhere' }}><bdi>{value}</bdi></Typography>
    <Tooltip title={t('copySetupValue', { field: label })}><IconButton size="small" aria-label={t('copySetupValue', { field: label })} onClick={() => void copy()}><ContentCopy fontSize="small" /></IconButton></Tooltip>
  </Stack>
}

function DetailSection({ title, items }: { title: string; items: DetailItem[] }) {
  return <Stack component="section" spacing={1.5} aria-label={title}>
    <Typography component="h3" variant="subtitle1" sx={{ fontWeight: 600 }}>{title}</Typography>
    <TwoColumnKeyValue items={items} />
  </Stack>
}

export default function RevisionDetailDrawer({ open, revision, loading, disabled, prepareDisabled = false, onClose, onValidate, onApprove, onPrepare, onRecovery, onTestResult, onEnrolled }: {
  open: boolean
  revision?: AuthRevision
  loading: boolean
  disabled: boolean
  prepareDisabled?: boolean
  onClose: () => void
  onValidate: (revision: AuthRevision) => void
  onApprove: (revision: AuthRevision) => void
  onPrepare: (revision: AuthRevision) => void
  onRecovery: (revision: AuthRevision) => void
  onTestResult: (result: ConnectionTest | null) => void
  onEnrolled: (user: User) => void
}) {
  const { t, i18n } = useTranslation(['auth', 'common'])
  const testRef = useRef<OIDCConnectionTestHandle>(null)
  const [testBusy, setTestBusy] = useState(false)
  const language = i18n.resolvedLanguage || 'en'
  const date = (value?: string) => value ? formatDate(value, language) : t('common:none')
  const technical = (label: string, value?: string) => value ? <TechnicalValue label={label} value={value} /> : t('common:none')
  const configuration: DetailItem[] = revision ? [
    { label: t('provider'), value: t(revision.provider === 'oidc' ? 'providerOidc' : revision.provider === 'google_iap' ? 'providerIap' : 'providerLocal') },
    { label: t('revisionID'), value: technical(t('revisionID'), revision.id) },
    { label: t('revisionGeneration'), value: formatNumber(revision.generation, language) },
    { label: t('deployment'), value: technical(t('deployment'), revision.deployment_id) },
    { label: t('environment'), value: <bdi>{revision.environment}</bdi> },
    { label: t('secretIndicator'), value: t(revision.has_secret ? 'secretPresent' : 'secretAbsent') },
  ] : []
  const identity: DetailItem[] = revision?.provider === 'oidc' ? [
    { label: t('issuerURL'), value: technical(t('issuerURL'), revision.issuer_url) },
    { label: t('clientID'), value: technical(t('clientID'), revision.client_id) },
    { label: t('redirectURI'), value: technical(t('redirectURI'), revision.redirect_uri) },
    { label: t('allowHTTP'), value: t(revision.allow_http_development ? 'yes' : 'no') },
  ] : revision?.provider === 'google_iap' ? [{ label: t('iapAudience'), value: technical(t('iapAudience'), revision.iap_audience) }] : []
  const audit: DetailItem[] = revision ? [
    { label: t('creator'), value: technical(t('creator'), revision.created_by) },
    { label: t('createdAt'), value: date(revision.created_at) },
    { label: t('validatedAt'), value: date(revision.validated_at) },
    { label: t('approvedAt'), value: date(revision.approved_at) },
  ] : []
  const actions = revision && <>
    {revision.status === 'draft' && <Button variant="contained" disabled={disabled} onClick={() => onValidate(revision)}>{t('validateSettings')}</Button>}
    {revision.status === 'validated' && <Button variant="contained" disabled={disabled} onClick={() => onApprove(revision)}>{t('approveRevision')}</Button>}
    {revision.status === 'approved' && revision.provider === 'oidc' && <>
      <Button variant="outlined" disabled={disabled || testBusy} onClick={() => testRef.current?.start()}>{t('testConnection')}</Button>
      <Button variant="contained" disabled={disabled || prepareDisabled || testBusy} onClick={() => onPrepare(revision)}>{t('activationPrepare')}</Button>
    </>}
    {revision.status === 'superseded' && revision.provider === 'oidc' && <Button variant="outlined" disabled={disabled} onClick={() => onRecovery(revision)}>{t('recoveryCreateAction')}</Button>}
  </>
  return <DetailDrawer open={open} onClose={onClose} title={revision ? t('revisionLabel', { version: formatNumber(revision.configuration_version, language) }) : t('revisionMetadata')}
    titleAdornment={revision && <StatusBadge label={t(`revisionStatus_${revision.status}`)} tone={revision.status === 'active' ? 'success' : revision.status === 'approved' ? 'info' : 'neutral'} />} actions={actions}>
    <Stack spacing={2.5} role="region" aria-label={t('revisionMetadata')}>
      {loading && <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}><CircularProgress size={20} /><Typography>{t('common:loading')}</Typography></Stack>}
      {!loading && !revision && <Alert severity="warning">{t('settingsUnavailable')}</Alert>}
      {revision && <>
        <DetailSection title={t('detailConfiguration')} items={configuration} />
        <Divider />
        <DetailSection title={t('detailIdentityProvider')} items={identity} />
        <Divider />
        <DetailSection title={t('detailAuditHistory')} items={audit} />
        {revision.status === 'approved' && revision.provider === 'oidc' && <>
          <Divider />
          <OIDCConnectionTest key={revision.id} ref={testRef} revision={revision} disabled={disabled} externalTrigger onBusyChange={setTestBusy}
            onResult={onTestResult} onEnrolled={onEnrolled} />
        </>}
      </>}
    </Stack>
  </DetailDrawer>
}
