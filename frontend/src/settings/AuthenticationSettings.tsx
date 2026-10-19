import { useEffect, useRef, useState } from 'react'
import { Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, Paper, Stack, TableCell, TableRow, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { APIError, errorKey } from '../api/client'
import { authSettingsPath, authStatusPath } from '../api/authConfiguration'
import type { AuthHistory, AuthRevision, AuthStatus } from '../api/authConfiguration'
import { useQuery, useQueryCache } from '../api/queries'
import CompactTable from '../components/CompactTable'
import { PageTools } from '../components/PageTools'
import { formatDate, formatNumber } from '../i18n'
import { useNotifications } from '../notifications/notifications'
import type { Notification } from '../notifications/notifications'
import AuthDraftForm from './AuthDraftForm'

export default function AuthenticationSettings() {
  const { t, i18n } = useTranslation(['auth', 'common', 'admin'])
  const cache = useQueryCache(), notify = useNotifications()
  const status = useQuery<AuthStatus>(authStatusPath)
  const [cursors, setCursors] = useState([0])
  const history = useQuery<AuthHistory>(`${authSettingsPath}?limit=20&before_version=${cursors.at(-1)}`)
  const [selected, setSelected] = useState<string | null>(null)
  const detail = useQuery<AuthRevision>(selected ? `${authSettingsPath}/${encodeURIComponent(selected)}` : null)
  const [approval, setApproval] = useState<AuthRevision | null>(null)
  const [busy, setBusy] = useState(false), [mutationError, setMutationError] = useState('')
  const mutating = useRef(false), reportedError = useRef('')
  const queryError = status.error || history.error || detail.error
  const queryMessage = queryError ? (queryError === 'errorUnavailable' || queryError === 'errorRequest' ? 'auth:settingsUnavailable' : `admin:${queryError}`) : ''
  useEffect(() => {
    if (queryMessage && reportedError.current !== queryMessage) notify({ severity: 'error', messageKey: queryMessage as Notification['messageKey'] })
    reportedError.current = queryMessage
  }, [queryMessage, notify])
  const loading = status.loading || history.loading || detail.loading
  const locked = busy || loading
  const language = i18n.resolvedLanguage || 'en'
  const date = (value?: string) => value ? formatDate(value, language) : t('common:none')
  const version = (revision: AuthRevision) => t('revisionLabel', { version: formatNumber(revision.configuration_version, language) })
  const summary = (revision: AuthRevision | null) => revision ? `${version(revision)} · ${revision.provider} · ${t(`revisionStatus_${revision.status}`)}` : t('common:none')
  const metadata = detail.data
  const environment = status.data?.latest_revision?.environment || status.data?.database_active_revision?.environment
  // The runtime local_dev provider is allowed only in development by the backend.
  // An empty history under OIDC/IAP does not establish a development environment.
  const development = environment ? environment === 'development' : status.data?.runtime_provider === 'local_dev'
  async function mutate(path: string, body: unknown, messageKey: Notification['messageKey']) {
    if (mutating.current) return false
    mutating.current = true; setBusy(true); setMutationError('')
    try {
      await cache.mutate(path, 'POST', body)
      notify({ severity: 'success', messageKey })
      return true
    } catch (error) {
      const conflict = error instanceof APIError && error.status === 409
      const key = errorKey(error)
      const messageKey: Notification['messageKey'] = conflict ? 'auth:revisionConflict'
        : key === 'errorUnavailable' || key === 'errorRequest' ? 'auth:settingsUnavailable' : `admin:${key}`
      setMutationError(messageKey)
      notify({ severity: conflict ? 'warning' : 'error', messageKey })
      if (conflict) cache.invalidate() // Refresh metadata/generations; never retry a write automatically.
      return false
    } finally { mutating.current = false; setBusy(false) }
  }
  return <Stack spacing={3} sx={{ minWidth: 0 }}>
    <PageTools busy={locked} error={queryMessage} onRefresh={() => setMutationError('')} />
    {mutationError && <Alert severity={mutationError === 'auth:revisionConflict' ? 'warning' : 'error'}>{t(mutationError)}</Alert>}
    {status.data && <Paper component="section" aria-label={t('runtimeTitle')} sx={{ p: { xs: 2, sm: 3 }, overflowWrap: 'anywhere' }}>
      <Typography component="h2" variant="h6" sx={{ mb: 2 }}>{t('runtimeTitle')}</Typography>
      <Stack spacing={1}>
        <Typography><strong>{t('runtimeProvider')}: </strong><bdi>{status.data.runtime_provider}</bdi></Typography>
        <Typography><strong>{t('configurationSource')}: </strong>{t('sourceEnvironment')}</Typography>
        <Alert severity="info">{t('managementOnly')}</Alert>
        <Typography><strong>{t('validationMode')}: </strong>{t('offlineValidation')}</Typography>
        <Typography><strong>{t('latestRevision')}: </strong>{summary(status.data.latest_revision)}</Typography>
        <Typography><strong>{t('databaseActiveRevision')}: </strong>{summary(status.data.database_active_revision)}</Typography>
      </Stack>
    </Paper>}
    <Alert severity="info">{t('offlineHelp')} {t('futureCapabilities')}</Alert>
    {status.data && <AuthDraftForm development={development} latestVersion={status.data.latest_revision?.configuration_version || 0} busy={locked || Boolean(queryError)} onCreate={async (body) => {
      const success = await mutate(authSettingsPath, body, 'auth:draftCreated')
      if (success) setCursors([0])
      return success
    }} />}
    <Paper component="section" sx={{ p: { xs: 2, sm: 3 }, minWidth: 0 }}>
      <Typography component="h2" variant="h6" sx={{ mb: 2 }}>{t('history')}</Typography>
      <CompactTable label={t('history')} headers={[t('revision'), t('provider'), t('common:status'), t('creator'), t('createdAt'), t('validatedAt'), t('approvedAt'), t('secretIndicator'), t('actions')]}
        empty={Boolean(history.data) && !history.data?.revisions?.length} emptyMessage={t('emptyHistory')} minWidth={950}>
        {history.data?.revisions?.map((revision) => <TableRow key={revision.id}>
          <TableCell>{formatNumber(revision.configuration_version, language)}</TableCell><TableCell><bdi>{revision.provider}</bdi></TableCell>
          <TableCell>{t(`revisionStatus_${revision.status}`)}</TableCell><TableCell><bdi>{revision.created_by}</bdi></TableCell>
          <TableCell>{date(revision.created_at)}</TableCell><TableCell>{date(revision.validated_at)}</TableCell><TableCell>{date(revision.approved_at)}</TableCell>
          <TableCell>{t(revision.has_secret ? 'secretPresent' : 'secretAbsent')}</TableCell>
          <TableCell><Button disabled={locked} onClick={() => { setSelected(revision.id); setMutationError('') }} aria-label={t('viewRevision', { version: formatNumber(revision.configuration_version, language) })}>{t('view')}</Button></TableCell>
        </TableRow>)}
      </CompactTable>
      <Stack direction="row" sx={{ mt: 2, flexWrap: 'wrap', gap: 1 }}>
        <Button disabled={locked || cursors.length === 1} onClick={() => setCursors(cursors.slice(0, -1))}>{t('common:previousPage')}</Button>
        <Button disabled={locked || !history.data?.next_before_version} onClick={() => setCursors([...cursors, history.data!.next_before_version])}>{t('common:nextPage')}</Button>
      </Stack>
    </Paper>
    {metadata && <Paper component="section" aria-label={t('revisionMetadata')} sx={{ p: { xs: 2, sm: 3 }, overflowWrap: 'anywhere' }}>
      <Typography component="h2" variant="h6">{t('revisionMetadata')} — {version(metadata)}</Typography>
      <Box component="dl" sx={{ '& dt': { fontWeight: 600, mt: 1 }, '& dd': { m: 0 } }}>
        {[
          [t('provider'), metadata.provider], [t('common:status'), t(`revisionStatus_${metadata.status}`)],
          [t('revisionID'), metadata.id], [t('deployment'), metadata.deployment_id], [t('environment'), metadata.environment],
          [t('creator'), metadata.created_by], [t('createdAt'), date(metadata.created_at)],
          [t('validatedAt'), date(metadata.validated_at)], [t('approvedAt'), date(metadata.approved_at)],
          [t('secretIndicator'), t(metadata.has_secret ? 'secretPresent' : 'secretAbsent')],
          ...(metadata.provider === 'oidc' ? [[t('issuerURL'), metadata.issuer_url], [t('clientID'), metadata.client_id], [t('redirectURI'), metadata.redirect_uri], [t('allowHTTP'), t(metadata.allow_http_development ? 'yes' : 'no')]] : []),
          ...(metadata.provider === 'google_iap' ? [[t('iapAudience'), metadata.iap_audience]] : []),
        ].map(([label, value]) => <Box key={label}><dt>{label}</dt><dd><bdi>{value}</bdi></dd></Box>)}
      </Box>
      <Stack direction="row" sx={{ gap: 1, flexWrap: 'wrap' }}>
        {metadata.status === 'draft' && <Button disabled={locked || Boolean(queryError)} variant="contained" onClick={() => void mutate(`${authSettingsPath}/${metadata.id}/validate`, { expected_generation: metadata.generation }, 'auth:validationSaved')}>{t('validateSettings')}</Button>}
        {metadata.status === 'validated' && <Button disabled={locked || Boolean(queryError)} variant="contained" onClick={() => setApproval(metadata)}>{t('approveRevision')}</Button>}
      </Stack>
    </Paper>}
    <Dialog open={Boolean(approval)} onClose={() => { if (!busy) setApproval(null) }} fullWidth maxWidth="sm" aria-labelledby="auth-approve-title">
      <DialogTitle id="auth-approve-title">{t('approveTitle')}</DialogTitle>
      <DialogContent>{approval && <Typography sx={{ mb: 2 }}>{summary(approval)}</Typography>}<Typography>{t('approveHelp')}</Typography></DialogContent>
      <DialogActions>
        <Button disabled={busy} onClick={() => setApproval(null)}>{t('common:cancel')}</Button>
        <Button disabled={busy} onClick={async () => {
          if (!approval) return
          await mutate(`${authSettingsPath}/${approval.id}/approve`, { expected_generation: approval.generation }, 'auth:approvalSaved')
          setApproval(null)
        }}>{t('admin:confirmPermissions')}</Button>
      </DialogActions>
    </Dialog>
  </Stack>
}
