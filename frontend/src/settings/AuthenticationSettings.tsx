import { useEffect, useRef, useState } from 'react'
import { Accordion, AccordionDetails, AccordionSummary, Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, TableCell, TableRow, Typography } from '@mui/material'
import ExpandMore from '@mui/icons-material/ExpandMore'
import { useTranslation } from 'react-i18next'
import { APIError, errorKey } from '../api/client'
import type { User } from '../api/client'
import { authProviderSetupPath, authSettingsPath, authStatusPath } from '../api/authConfiguration'
import type { AuthHistory, AuthRevision, AuthStatus, ConnectionTest, OIDCProviderSetupMetadata } from '../api/authConfiguration'
import { useQuery, useQueryCache } from '../api/queries'
import { useAuthenticationCacheSync } from '../api/authCache'
import CompactTable from '../components/CompactTable'
import { PageTools } from '../components/PageTools'
import DetailDrawer from '../components/common/DetailDrawer'
import SectionCard from '../components/common/SectionCard'
import StatusBadge from '../components/common/StatusBadge'
import TwoColumnKeyValue from '../components/common/TwoColumnKeyValue'
import { formatDate, formatNumber } from '../i18n'
import { useNotifications } from '../notifications/notifications'
import type { Notification } from '../notifications/notifications'
import AuthDraftForm, { authDraftFormID } from './AuthDraftForm'
import ActivationWorkflow from './ActivationWorkflow'
import type { DisplayedOutcome } from './ActivationOutcomePanel'
import OIDCProviderSetup from './OIDCProviderSetup'
import RecoveryDraftDialog from './RecoveryDraftDialog'
import RevisionDetailDrawer from './RevisionDetailDrawer'

export default function AuthenticationSettings() {
  const { t, i18n } = useTranslation(['auth', 'common', 'admin'])
  const cache = useQueryCache(), notify = useNotifications()
  const { refreshViews } = useAuthenticationCacheSync()
  const status = useQuery<AuthStatus>(authStatusPath)
  const setup = useQuery<OIDCProviderSetupMetadata>(authProviderSetupPath)
  const [cursors, setCursors] = useState([0])
  const history = useQuery<AuthHistory>(`${authSettingsPath}?limit=20&before_version=${cursors.at(-1)}`)
  const [selected, setSelected] = useState<string | null>(null)
  const detail = useQuery<AuthRevision>(selected ? `${authSettingsPath}/${encodeURIComponent(selected)}` : null)
  const [draftOpen, setDraftOpen] = useState(false), [guideOpen, setGuideOpen] = useState(false)
  const [approval, setApproval] = useState<AuthRevision | null>(null)
  const [isolatedTest, setIsolatedTest] = useState<ConnectionTest | null>(null)
  const [enrolledUser, setEnrolledUser] = useState<User | null>(null)
  const [recoverySource, setRecoverySource] = useState<AuthRevision | null>(null)
  const [activationRevision, setActivationRevision] = useState<AuthRevision | null>(null)
  const [activationOutcome, setActivationOutcome] = useState<DisplayedOutcome | null>(null)
  const [busy, setBusy] = useState(false), [mutationError, setMutationError] = useState('')
  const mutating = useRef(false), reportedError = useRef('')
  const queryError = status.error || history.error || detail.error
  const queryMessage = queryError ? (queryError === 'errorUnavailable' || queryError === 'errorRequest' ? 'auth:settingsUnavailable' : `admin:${queryError}`) : ''
  useEffect(() => {
    if (queryMessage && reportedError.current !== queryMessage) notify({ severity: 'error', messageKey: queryMessage as Notification['messageKey'] })
    reportedError.current = queryMessage
  }, [queryMessage, notify])
  const locked = busy || status.loading || history.loading
  const language = i18n.resolvedLanguage || 'en'
  const date = (value?: string) => value ? formatDate(value, language) : t('common:none')
  const version = (revision: AuthRevision) => t('revisionLabel', { version: formatNumber(revision.configuration_version, language) })
  const providerLabel = (provider: string) => t(provider === 'oidc' ? 'providerOidc' : provider === 'google_iap' ? 'providerIap' : provider === 'local_dev' ? 'providerLocal' : 'common:none')
  const summary = (revision: AuthRevision | null) => revision ? `${version(revision)} · ${providerLabel(revision.provider)} · ${t(`revisionStatus_${revision.status}`)}` : t('common:none')
  const metadata = detail.data?.id === selected ? detail.data : undefined
  const environment = status.data?.latest_revision?.environment || status.data?.database_active_revision?.environment
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
      if (conflict) refreshViews()
      return false
    } finally { mutating.current = false; setBusy(false) }
  }

  return <Stack spacing={2} sx={{ minWidth: 0 }}>
    <PageTools busy={locked} error={queryMessage} onRefresh={() => setMutationError('')} />
    {mutationError && !draftOpen && <Alert severity={mutationError === 'auth:revisionConflict' ? 'warning' : 'error'}>{t(mutationError)}</Alert>}
    <Box sx={{ display: 'grid', gridTemplateColumns: { xs: 'minmax(0, 1fr)', lg: 'repeat(2, minmax(0, 1fr))' }, gap: 2, alignItems: 'start' }}>
      {status.data && <SectionCard title={t('runtimeTitle')}>
        <Stack spacing={1.5}>
          <TwoColumnKeyValue items={[
            { label: t('runtimeProvider'), value: providerLabel(status.data.runtime_provider) },
            { label: t('configurationSource'), value: t(status.data.runtime_source === 'database' ? 'sourceDatabase' : 'sourceEnvironment') },
          ]} />
          {status.data.management_only && <Alert severity="info">{t('managementOnly')}</Alert>}
          <Accordion disableGutters variant="outlined" sx={{ '&::before': { display: 'none' } }}>
            <AccordionSummary expandIcon={<ExpandMore />}>{t('technicalDetails')}</AccordionSummary>
            <AccordionDetails><TwoColumnKeyValue items={[
            { label: t('validationMode'), value: t('offlineValidation') },
            { label: t('latestRevision'), value: summary(status.data.latest_revision) },
            { label: t('databaseActiveRevision'), value: summary(status.data.database_active_revision) },
          ]} /></AccordionDetails>
          </Accordion>
        </Stack>
      </SectionCard>}
      <ActivationWorkflow revision={activationRevision} open={Boolean(activationRevision)} onClose={() => setActivationRevision(null)}
        isolatedTest={isolatedTest} enrolledUser={enrolledUser} disabled={locked || Boolean(queryError)} onResolvedUser={setEnrolledUser} onOutcomeChange={setActivationOutcome} />
    </Box>

    <SectionCard title={t('history')} actions={<Stack direction="row" sx={{ gap: 1, flexWrap: 'wrap' }}>
      <Button variant="contained" disabled={locked || !status.data} onClick={() => { setMutationError(''); setDraftOpen(true) }}>{t('newDraft')}</Button>
      <Button variant="outlined" onClick={() => setGuideOpen(true)}>{t('setupTitle')}</Button>
    </Stack>}>
      <CompactTable label={t('revision')} headers={[t('revision'), t('provider'), t('common:status'), t('createdAt'), t('actions')]}
        empty={Boolean(history.data) && !history.data?.revisions?.length} emptyMessage={t('emptyHistory')} minWidth={480}>
        {history.data?.revisions?.map((revision) => <TableRow key={revision.id} hover>
          <TableCell>{formatNumber(revision.configuration_version, language)}</TableCell>
          <TableCell>{providerLabel(revision.provider)}</TableCell>
          <TableCell><StatusBadge label={t(`revisionStatus_${revision.status}`)} tone={revision.status === 'active' ? 'success' : revision.status === 'approved' ? 'info' : 'neutral'} /></TableCell>
          <TableCell>{date(revision.created_at)}</TableCell>
          <TableCell sx={{ whiteSpace: 'nowrap' }}><Button size="small" disabled={locked} onClick={() => { setSelected(revision.id); setMutationError('') }} aria-label={t('viewRevision', { version: formatNumber(revision.configuration_version, language) })}>{t('view')}</Button></TableCell>
        </TableRow>)}
      </CompactTable>
      <Stack direction="row" sx={{ mt: 2, flexWrap: 'wrap', gap: 1 }}>
        <Button disabled={locked || cursors.length === 1} onClick={() => setCursors(cursors.slice(0, -1))}>{t('common:previousPage')}</Button>
        <Button disabled={locked || !history.data?.next_before_version} onClick={() => setCursors([...cursors, history.data!.next_before_version])}>{t('common:nextPage')}</Button>
      </Stack>
    </SectionCard>

    <RevisionDetailDrawer open={Boolean(selected)} revision={metadata} loading={detail.loading} disabled={locked || detail.loading || Boolean(queryError)}
      prepareDisabled={Boolean(activationOutcome)}
      onClose={() => setSelected(null)} onValidate={(revision) => void mutate(`${authSettingsPath}/${revision.id}/validate`, { expected_generation: revision.generation }, 'auth:validationSaved')}
      onApprove={setApproval} onPrepare={(revision) => { if (activationOutcome) return; setActivationRevision(revision); setSelected(null) }} onRecovery={setRecoverySource}
      onTestResult={(result) => { setIsolatedTest(result); setEnrolledUser(null) }} onEnrolled={setEnrolledUser} />

    <Dialog open={draftOpen && Boolean(status.data)} onClose={() => { if (!busy) setDraftOpen(false) }} fullWidth maxWidth="sm" aria-labelledby="auth-draft-title">
      <DialogTitle id="auth-draft-title">{t('newDraft')}</DialogTitle>
      <DialogContent dividers>{mutationError && <Alert severity={mutationError === 'auth:revisionConflict' ? 'warning' : 'error'} sx={{ mb: 2 }}>{t(mutationError)}</Alert>}
        {draftOpen && status.data && <AuthDraftForm development={development} latestVersion={status.data.latest_revision?.configuration_version || 0}
        busy={locked || Boolean(queryError)} trustedRedirectURI={setup.data?.normal_callback_url} onCreate={async (body) => {
          const success = await mutate(authSettingsPath, body, 'auth:draftCreated')
          if (success) { setCursors([0]); setDraftOpen(false) }
          return success
        }} />}</DialogContent>
      <DialogActions><Button disabled={busy} onClick={() => setDraftOpen(false)}>{t('common:cancel')}</Button>
        <Button variant="contained" type="submit" form={authDraftFormID} disabled={locked || Boolean(queryError)}>{t('createDraft')}</Button></DialogActions>
    </Dialog>

    <DetailDrawer open={guideOpen} onClose={() => setGuideOpen(false)} title={t('setupTitle')}>
      <OIDCProviderSetup metadata={setup.data} loading={setup.loading} error={setup.error} />
    </DetailDrawer>

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
    {recoverySource && <RecoveryDraftDialog revision={recoverySource} latestVersion={status.data?.latest_revision?.configuration_version || 0}
      open onClose={() => setRecoverySource(null)} onCreated={(revision) => {
        setRecoverySource(null); setSelected(revision.id); setCursors([0])
      }} />}
  </Stack>
}
