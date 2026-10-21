import { useEffect, useRef, useState } from 'react'
import { Alert, Box, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, Stack, TableCell, TableRow, TextField, Typography } from '@mui/material'
import { useBeforeUnload, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { AuthConfigurationError } from '../api/authConfiguration'
import { authorizeGmail, configureEmailConnector, createEmailConnector, emailConnectorsPath, listEmailConnectors, readEmailConnector, testEmailConnector } from '../api/emailConnectors'
import type { ConnectorPage, ConnectorStatus, EmailConnector } from '../api/emailConnectors'
import type { QueryCache } from '../api/cache'
import { useQueryCache } from '../api/queries'
import { useSession } from '../auth/session'
import { useNotifications } from '../notifications/notifications'
import CompactTable from '../components/CompactTable'
import { PageTools } from '../components/PageTools'
import SectionCard from '../components/common/SectionCard'
import StatusBadge from '../components/common/StatusBadge'
import TechnicalValue from '../components/common/TechnicalValue'
import TwoColumnKeyValue from '../components/common/TwoColumnKeyValue'
import { typographyRoles } from '../design/theme'
import { formatDate, formatNumber } from '../i18n'

type Workflow = { kind: 'add' | 'configure' | 'test' | 'authorize'; id: string; provider: 'gmail' | 'ses'; current?: EmailConnector }
type Draft = { workflow: Workflow | null; sender: string; region: string; perMinute: string; perDay: string; enabled: boolean; defaultConnector: boolean; reason: string; mailbox: string; consent: boolean; uncertain: boolean; conflict: boolean }
const drafts = new WeakMap<QueryCache, Draft>()
const fresh = (): Draft => ({ workflow: null, sender: '', region: 'eu-west-1', perMinute: '30', perDay: '1500', enabled: false, defaultConnector: false, reason: '', mailbox: '', consent: false, uncertain: false, conflict: false })
const statusKeys: Record<ConnectorStatus, string> = { configured: 'emailConfigured', ready: 'emailReady', authentication_failed: 'emailAuthenticationFailed', sender_not_verified: 'emailSenderNotVerified', permission_denied: 'emailPermissionDenied', quota_unavailable: 'emailQuotaUnavailable', provider_unavailable: 'emailProviderUnavailable' }
function lastErrorKey(connector?: EmailConnector) {
  const code = connector?.last_error || ''
  if (!code) return 'emailNoError'
  if (code === 'ses_sandbox') return 'emailSandbox'
  if (code === 'gmail_scope_required') return 'emailScopeWarning'
  if (code.includes('authentication') || code === 'gmail_not_authorized') return 'emailAuthenticationFailed'
  if (code.includes('sender')) return 'emailSenderNotVerified'
  if (code.includes('permission') || code === 'ses_sending_disabled') return 'emailPermissionDenied'
  if (code.includes('quota')) return 'emailQuotaUnavailable'
  return 'emailProviderUnavailable'
}
const tones = { configured: 'neutral', ready: 'success', authentication_failed: 'error', sender_not_verified: 'warning', permission_denied: 'error', quota_unavailable: 'warning', provider_unavailable: 'error' } as const
const email = (value: string) => /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/u.test(value)
const noControls = (value: string) => [...value].every((char) => { const code = char.codePointAt(0)!; return code >= 32 && (code < 127 || code > 159) })
const reasonValid = (value: string) => value.trim().length >= 8 && new TextEncoder().encode(value).length <= 512 && noControls(value)

export default function EmailConnectors() {
  const { t, i18n } = useTranslation(['admin', 'common'])
  const session = useSession(), cache = useQueryCache(), notify = useNotifications()
  const authorized = session.authentication.status === 'authenticated' && session.access.user?.active && session.access.user.permissions.includes('admin.manage')
  const [params] = useSearchParams()
  const [form, setForm] = useState<Draft>(() => drafts.get(cache) || fresh())
  const [page, setPage] = useState<ConnectorPage | null>(null), [offset, setOffset] = useState(0), [revision, setRevision] = useState(0)
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false), [error, setError] = useState(''), [discard, setDiscard] = useState(false)
  const [authorizationURL, setAuthorizationURL] = useState('')
  const mounted = useRef(false), inFlight = useRef(false)
  const language = i18n.resolvedLanguage || 'en'
  useEffect(() => { mounted.current = true; return () => { mounted.current = false } }, [])
  useEffect(() => { drafts.set(cache, { ...form, uncertain: form.uncertain || busy }) }, [cache, form, busy])
  useBeforeUnload((event) => { if (form.workflow) { event.preventDefault(); event.returnValue = '' } })
  useEffect(() => {
    if (!authorized) return
    const controller = new AbortController()
    listEmailConnectors(offset, controller.signal).then((data) => { if (!controller.signal.aborted) { setPage(data); setLoading(false) } }).catch((failure) => { if (!controller.signal.aborted) { handleError(failure, false); setLoading(false) } })
    return () => controller.abort()
    // The explicit refresh counter scopes reads; write retries are never automatic.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authorized, offset, revision])
  function update(change: Partial<Draft>) { setForm((old) => ({ ...old, ...change })) }
  function refresh() { setLoading(true); setRevision((value) => value + 1); cache.invalidate([emailConnectorsPath]) }
  function handleError(failure: unknown, mutation: boolean) {
    const status = failure instanceof AuthConfigurationError ? failure.status : 0
    if (status === 401) session.expire()
    if (status === 403) void session.refreshAccess()
    const key = status === 409 ? 'emailConflict' : status === 400 ? 'emailInvalid' : status === 403 ? 'emailDenied' : mutation && (status === 0 || status >= 500) ? 'emailUncertain' : 'emailUnavailable'
    setError(key); notify({ severity: 'error', messageKey: `admin:${key}` })
    if (mutation) update({ conflict: status === 409, uncertain: status === 0 || status >= 500 })
  }
  function begin(kind: Workflow['kind'], provider: 'gmail' | 'ses', current?: EmailConnector) {
    setForm({ ...fresh(), workflow: { kind, provider, id: current?.id || crypto.randomUUID(), current }, sender: current?.sender || '', mailbox: current?.sender || '', region: current?.region || 'eu-west-1', perMinute: String(current?.per_minute || 30), perDay: String(current?.per_day || 1500), enabled: current?.enabled || false, defaultConnector: current?.default || false })
    setError(''); setDiscard(false); setAuthorizationURL('')
  }
  function close() { if (busy) return; setDiscard(true) }
  function clear() { setForm(fresh()); setDiscard(false); setError(''); setAuthorizationURL('') }
  async function inspect() {
    if (!form.workflow || busy) return
    setBusy(true)
    try { const current = await readEmailConnector(form.workflow.id); update({ workflow: { ...form.workflow, kind: form.workflow.kind === 'add' ? 'configure' : form.workflow.kind, current }, conflict: false, uncertain: false }); setError(''); refresh() }
    catch (failure) { handleError(failure, false) }
    finally { setBusy(false) }
  }
  async function submit() {
    const workflow = form.workflow
    if (!workflow || inFlight.current || form.uncertain || form.conflict || !valid) return
    inFlight.current = true; setBusy(true); setError('')
    try {
      if (workflow.kind === 'add') await createEmailConnector({ id: workflow.id, provider: workflow.provider, sender: form.sender, region: workflow.provider === 'ses' ? form.region : '', per_minute: Number(form.perMinute), per_day: Number(form.perDay), reason: form.reason })
      else if (workflow.kind === 'configure') await configureEmailConnector(workflow.id, { expected_generation: workflow.current!.generation, enabled: form.enabled, default: form.defaultConnector, per_minute: Number(form.perMinute), per_day: Number(form.perDay), reason: form.reason })
      else if (workflow.kind === 'test') await testEmailConnector(workflow.id, workflow.current!.generation, form.reason)
      else { const url = await authorizeGmail(workflow.id, workflow.current!.generation, form.mailbox, form.reason); if (mounted.current) setAuthorizationURL(url) }
      if (mounted.current) { notify({ severity: 'success', messageKey: workflow.kind === 'test' ? 'admin:emailTestCompleted' : workflow.kind === 'authorize' ? 'admin:emailAuthorizationStarted' : 'admin:changesSaved' }); refresh(); if (workflow.kind !== 'authorize') clear() }
      else drafts.set(cache, fresh())
    } catch (failure) { if (mounted.current) handleError(failure, true) }
    finally { inFlight.current = false; if (mounted.current) setBusy(false) }
  }
  const workflow = form.workflow
  const numeric = Number.isInteger(Number(form.perMinute)) && Number(form.perMinute) >= 1 && Number(form.perMinute) <= 60 && Number.isInteger(Number(form.perDay)) && Number(form.perDay) >= 1 && Number(form.perDay) <= 100000
  const valid = reasonValid(form.reason) && (workflow?.kind === 'add' ? email(form.sender) && numeric && (workflow.provider !== 'ses' || /^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$/u.test(form.region)) : workflow?.kind === 'configure' ? numeric && (!form.defaultConnector || form.enabled) : workflow?.kind === 'authorize' ? email(form.mailbox) && form.consent : true)
  const title = t(workflow?.kind === 'add' ? workflow.provider === 'gmail' ? 'emailAddGmail' : 'emailAddSES' : workflow?.kind === 'configure' ? 'emailConfigure' : workflow?.kind === 'authorize' ? 'emailAuthorize' : 'emailTest')
  if (!authorized) return <Alert severity="error">{t('common:accessDenied')}</Alert>
  return <Stack spacing={2}>
    <PageTools busy={loading || busy} error={error} onRefresh={refresh} />
    {params.has('gmail_result') && <Alert severity={params.get('gmail_result') === 'completed' ? 'info' : 'warning'}>{t('emailOAuthReturn')}</Alert>}
    <SectionCard title={t('emailConnectorsTitle')} description={t('emailNoDelivery')} busy={loading || busy} actions={<Stack direction="row" sx={{ gap: 1, flexWrap: 'wrap' }}><Button variant="contained" disabled={busy || Boolean(workflow)} onClick={() => begin('add', 'gmail')}>{t('emailAddGmail')}</Button><Button variant="outlined" disabled={busy || Boolean(workflow)} onClick={() => begin('add', 'ses')}>{t('emailAddSES')}</Button></Stack>}>
      {!page?.gmail_authorization_available && <Alert severity="info" sx={{ mb: 2 }}>{t('emailGmailSetup')}</Alert>}
      <CompactTable label={t('emailConnectorsTitle')} headers={[t('emailProvider'), t('emailSender'), t('emailReadiness'), t('emailConfiguration'), t('emailLimits'), t('actions')]} empty={!page?.items.length} emptyMessage={t('emailEmpty')} stickyActions minWidth={640}>
        {page?.items.map((row) => <TableRow key={row.id}>
          <TableCell>{row.provider === 'gmail' ? 'Google Workspace Gmail API' : 'Amazon SES'}{row.region && <Typography variant={typographyRoles.supportingText}>{row.region}</Typography>}</TableCell>
          <TableCell><bdi>{row.sender}</bdi></TableCell>
          <TableCell><StatusBadge label={t(statusKeys[row.readiness.status])} tone={tones[row.readiness.status]} />{row.tested_at && <Typography variant={typographyRoles.supportingText}>{formatDate(row.tested_at, language)}</Typography>}</TableCell>
          <TableCell>{t(row.enabled ? 'emailEnabled' : 'emailDisabled')}{row.default && <Typography variant={typographyRoles.supportingText}>{t('emailDefault')}</Typography>}</TableCell>
          <TableCell>{t('emailLimitSummary', { minute: formatNumber(row.per_minute, language), day: formatNumber(row.per_day, language) })}</TableCell>
          <TableCell><Stack direction="row" sx={{ gap: 0.5, flexWrap: 'wrap' }}><Button disabled={busy || Boolean(workflow)} onClick={() => begin('configure', row.provider, row)}>{t('emailConfigure')}</Button><Button disabled={busy || Boolean(workflow)} onClick={() => begin('test', row.provider, row)}>{t('emailTest')}</Button>{row.provider === 'gmail' && <Button disabled={busy || Boolean(workflow) || !page.gmail_authorization_available} onClick={() => begin('authorize', row.provider, row)}>{t('emailAuthorize')}</Button>}</Stack></TableCell>
        </TableRow>)}
      </CompactTable>
      <Stack direction="row" sx={{ mt: 2, gap: 1, alignItems: 'center', flexWrap: 'wrap' }}><Button disabled={loading || offset === 0} onClick={() => { setOffset(offset - 20); setLoading(true) }}>{t('common:previousPage')}</Button><Typography variant="body2">{t('common:page', { page: formatNumber(offset / 20 + 1, language) })}</Typography><Button disabled={loading || !page || offset + 20 >= page.total || offset >= 100000} onClick={() => { setOffset(offset + 20); setLoading(true) }}>{t('common:nextPage')}</Button></Stack>
    </SectionCard>
    <Dialog open={Boolean(workflow)} onClose={close} fullWidth maxWidth="sm" aria-labelledby="email-connector-title">
      <DialogTitle id="email-connector-title">{title}</DialogTitle>
      <DialogContent dividers><Box component="form" id="email-connector-form" onSubmit={(event) => { event.preventDefault(); void submit() }}><Stack spacing={2}>
        <Alert severity="info">{t(workflow?.kind === 'test' ? 'emailTestExplanation' : 'emailNoDelivery')}</Alert>
        {workflow?.kind === 'add' ? <>
          <TextField label={t('emailSender')} type="email" value={form.sender} required autoFocus onChange={(event) => update({ sender: event.target.value })} />
          {workflow.provider === 'ses' && <><TextField label={t('emailRegion')} value={form.region} required onChange={(event) => update({ region: event.target.value })} /><Alert severity="info">{t('emailSESIdentity')}</Alert></>}
        </> : <>
          <TwoColumnKeyValue items={[{ label: t('emailSender'), value: <bdi>{form.sender}</bdi> }, { label: t('emailConnectorID'), value: <TechnicalValue label={t('emailConnectorID')} value={workflow?.id || ''} /> }, { label: t('emailReadiness'), value: workflow?.current ? t(statusKeys[workflow.current.readiness.status]) : '' }, { label: t('emailLastError'), value: t(lastErrorKey(workflow?.current)) }]} />
          {workflow?.kind === 'configure' && <><Alert severity="info">{t('emailImmutableSender')}</Alert><FormControlLabel control={<Checkbox checked={form.enabled} disabled={!form.enabled && workflow.current?.readiness.status !== 'ready'} onChange={(_, enabled) => update({ enabled, defaultConnector: enabled && form.defaultConnector })} />} label={t('emailEnabled')} /><FormControlLabel control={<Checkbox checked={form.defaultConnector} disabled={!form.enabled} onChange={(_, value) => update({ defaultConnector: value })} />} label={t('emailDefault')} /></>}
        </>}
        {(workflow?.kind === 'add' || workflow?.kind === 'configure') && <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}><TextField label={t('emailPerMinute')} type="number" value={form.perMinute} required slotProps={{ htmlInput: { min: 1, max: 60 } }} onChange={(event) => update({ perMinute: event.target.value })} /><TextField label={t('emailPerDay')} type="number" value={form.perDay} required slotProps={{ htmlInput: { min: 1, max: 100000 } }} onChange={(event) => update({ perDay: event.target.value })} /></Stack>}
        {workflow?.kind === 'authorize' && <><TextField label={t('emailMailbox')} type="email" value={form.mailbox} required onChange={(event) => update({ mailbox: event.target.value })} /><Alert severity="warning">{t('emailScopeWarning')}</Alert>{page?.gmail_scopes.map((scope) => <TechnicalValue key={scope} label={t('emailOAuthScope')} value={scope} />)}<FormControlLabel control={<Checkbox checked={form.consent} onChange={(_, consent) => update({ consent })} />} label={t('emailScopeConsent')} /></>}
        <TextField label={t('emailReason')} value={form.reason} required multiline minRows={2} onChange={(event) => update({ reason: event.target.value })} />
        {authorizationURL && <Button component="a" href={authorizationURL} target="_blank" rel="noopener noreferrer" variant="contained">{t('emailContinueGoogle')}</Button>}
        {error && <Alert severity="error">{t(error)}</Alert>}
        {(form.uncertain || form.conflict) && <Alert severity="warning" action={<Button disabled={busy} onClick={() => void inspect()}>{t('emailInspect')}</Button>}>{t(form.uncertain ? 'emailUncertain' : 'emailConflict')}</Alert>}
        {discard && <Alert severity="warning" action={<Button disabled={busy} onClick={clear}>{t('emailDiscard')}</Button>}>{t('emailUnsaved')}</Alert>}
      </Stack></Box></DialogContent>
      <DialogActions><Button disabled={busy} onClick={close}>{t('common:cancel')}</Button><Button variant="contained" type="submit" form="email-connector-form" disabled={busy || !valid || form.uncertain || form.conflict || Boolean(authorizationURL)}>{t(workflow?.kind === 'add' ? 'emailCreate' : workflow?.kind === 'test' ? 'emailTest' : workflow?.kind === 'authorize' ? 'emailAuthorize' : 'emailSave')}</Button></DialogActions>
    </Dialog>
  </Stack>
}
