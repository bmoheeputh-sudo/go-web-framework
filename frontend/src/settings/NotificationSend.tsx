import { useEffect, useRef, useState } from 'react'
import { Alert, Box, Button, Checkbox, FormControlLabel, MenuItem, Stack, Step, StepLabel, Stepper, TableCell, TableRow, TextField, Typography } from '@mui/material'
import { useBeforeUnload, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { AuthConfigurationError } from '../api/authConfiguration'
import { listEmailConnectors } from '../api/emailConnectors'
import type { ConnectorPage } from '../api/emailConnectors'
import { enqueueNotifications, listOnboarding, notificationUUID, notificationsPath, previewNotifications, readNotificationReceipt } from '../api/notificationManagement'
import type { NotificationKind, NotificationPreview, NotificationReceipt, OnboardingPage } from '../api/notificationManagement'
import type { QueryCache } from '../api/cache'
import { useQueryCache } from '../api/queries'
import { useSession } from '../auth/session'
import { useNotifications } from '../notifications/notifications'
import { PageTools } from '../components/PageTools'
import CompactTable from '../components/CompactTable'
import SectionCard from '../components/common/SectionCard'
import TechnicalValue from '../components/common/TechnicalValue'
import TwoColumnKeyValue from '../components/common/TwoColumnKeyValue'
import { formatDate, formatNumber } from '../i18n'
import { typographyRoles } from '../design/theme'
import { notificationDiagnostic, notificationErrorKey, validNotificationReason } from './notificationManagementState'
import { NotificationPager } from './NotificationControls'

type Draft = { selected: string[]; connector: string; preview: NotificationPreview | null; reason: string; confirmed: boolean; step: number; attempt: string; key: string; uncertain: boolean; queued: number; category: 'pending' | 'unobserved'; search: string; importID: string }
const fresh = (): Draft => ({ selected: [], connector: '', preview: null, reason: '', confirmed: false, step: 0, attempt: '', key: '', uncertain: false, queued: 0, category: 'pending', search: '', importID: '' })
const drafts = new WeakMap<QueryCache, Partial<Record<NotificationKind, Draft>>>()
export default function NotificationSend({ kind }: { kind: NotificationKind }) {
  const { t, i18n } = useTranslation(['admin', 'common'])
  const session = useSession(), cache = useQueryCache(), notify = useNotifications()
  const [params, setParams] = useSearchParams()
  const receiptParameter = params.get('notification_request') || ''
  const [draft, setDraft] = useState<Draft>(() => { const old = drafts.get(cache)?.[kind]; return old || (notificationUUID.test(receiptParameter) ? { ...fresh(), attempt: receiptParameter, step: 3, uncertain: true } : fresh()) })
  const [page, setPage] = useState<OnboardingPage | null>(null), [connectors, setConnectors] = useState<ConnectorPage | null>(null)
  const [offset, setOffset] = useState(0), [connectorOffset, setConnectorOffset] = useState(0), [revision, setRevision] = useState(0)
  const [search, setSearch] = useState(draft.search), [importID, setImportID] = useState(draft.importID)
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false), [error, setError] = useState(''), [discard, setDiscard] = useState(false)
  const [sample, setSample] = useState(''), [now, setNow] = useState(Date.now()), [receipt, setReceipt] = useState<NotificationReceipt | null>(null)
  const mounted = useRef(false), inFlight = useRef(false), attempted = useRef('')
  const language = i18n.resolvedLanguage || 'en'
  function patch(value: Partial<Draft>) { setDraft((old) => ({ ...old, ...value })) }
  useEffect(() => { mounted.current = true; return () => { mounted.current = false } }, [])
  useEffect(() => { drafts.set(cache, { ...drafts.get(cache), [kind]: { ...draft, uncertain: draft.uncertain || (busy && Boolean(attempted.current)) } }) }, [cache, draft, kind, busy])
  useBeforeUnload((event) => { if ((draft.selected.length || draft.reason) && !draft.queued || busy && attempted.current) { event.preventDefault(); event.returnValue = '' } })
  useEffect(() => {
    const controller = new AbortController()
    Promise.all([listOnboarding(draft.category, draft.search, draft.category === 'pending' ? draft.importID : '', offset, controller.signal), listEmailConnectors(connectorOffset, controller.signal)]).then(([targets, providerPage]) => {
      if (controller.signal.aborted) return
      setPage(targets); setConnectors(providerPage)
      setDraft((old) => ({ ...old, connector: old.connector || providerPage.items.find((c) => c.enabled && c.default && c.readiness.status === 'ready')?.id || '' }))
    }).catch((failure) => { if (!controller.signal.aborted) { setPage(null); setConnectors(null); report(failure, false) } }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
    // Selection and edited audit text do not trigger data reads or write retries.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft.category, draft.search, draft.importID, offset, connectorOffset, revision])
  useEffect(() => {
    const deadlines = [draft.preview?.preview_expires_at, ...connectors?.items.map((c) => c.expires_at) || []].filter((value): value is string => Boolean(value)).map(Date.parse).filter((time) => time > Date.now())
    if (!deadlines.length) return
    const timer = window.setTimeout(() => setNow(Date.now()), Math.max(1, Math.min(...deadlines) - Date.now() + 1))
    return () => window.clearTimeout(timer)
  }, [draft.preview, connectors, now])
  function refresh() { setLoading(true); setError(''); cache.invalidate([notificationsPath]); setRevision((value) => value + 1) }
  function report(failure: unknown, mutation: boolean) {
    const key = notificationErrorKey(failure, mutation); setError(key)
    if (failure instanceof AuthConfigurationError && failure.status === 401) session.expire()
    if (failure instanceof AuthConfigurationError && failure.status === 403) void session.refreshAccess()
    notify({ severity: 'error', messageKey: `admin:${key}` })
    if (mutation && key === 'nmUncertain') patch({ uncertain: true, step: 3 })
    else if (mutation) { patch({ preview: null, confirmed: false, attempt: '', key: '', step: 0 }); attempted.current = '' }
  }
  function select(ref: string, checked: boolean) { patch({ selected: checked ? [...draft.selected, ref] : draft.selected.filter((value) => value !== ref), preview: null, confirmed: false }) }
  async function preview() {
    if (inFlight.current || !draft.selected.length || !draft.connector || draft.uncertain || !page?.communication_configured) return
    inFlight.current = true; setBusy(true); setError('')
    try {
      const value = await previewNotifications({ request_id: crypto.randomUUID(), connector_id: draft.connector, targets: draft.selected, type: kind, locale: 'en' })
      if (mounted.current) { patch({ preview: value, step: 1, confirmed: false }); setSample(value.selected_targets[0] || '') }
    } catch (failure) { if (mounted.current) report(failure, false) }
    finally { inFlight.current = false; if (mounted.current) setBusy(false) }
  }
  async function enqueue() {
    const p = draft.preview
    if (!p || inFlight.current || draft.uncertain || !draft.confirmed || !validNotificationReason(draft.reason) || Date.parse(p.preview_expires_at) <= Date.now() || !p.ready_count) return
    inFlight.current = true; attempted.current = p.input.request_id; setBusy(true); setError('')
    const key = crypto.randomUUID()
    patch({ attempt: p.input.request_id, key })
    setParams((old) => { const next = new URLSearchParams(old); next.set('notification_request', p.input.request_id); return next }, { replace: true, preventScrollReset: true })
    try {
      const result = await enqueueNotifications({ input: p.input, expected: p.expected, connector_generation: p.connector_generation, selected_targets: p.selected_targets, preview_digest: p.preview_digest, preview_expires_at: p.preview_expires_at, idempotency_key: key, reason: draft.reason, confirm: true })
      if (mounted.current) { patch({ queued: result.job_count, uncertain: false, selected: [], step: 3 }); refresh(); notify({ severity: 'success', messageKey: 'admin:nmQueuedSuccess' }) }
      else drafts.set(cache, { ...drafts.get(cache), [kind]: { ...draft, attempt: result.request_id, key, queued: result.job_count, uncertain: false, selected: [], step: 3 } })
    } catch (failure) { if (mounted.current) report(failure, true) }
    finally { inFlight.current = false; if (mounted.current) setBusy(false) }
  }
  async function inspect() {
    if (busy || !draft.attempt) return
    setBusy(true); setError('')
    try { const value = await readNotificationReceipt(draft.attempt); setReceipt(value); patch({ queued: value.job_count, uncertain: false, selected: [], step: 3 }); refresh() }
    catch (failure) { report(failure, false) }
    finally { setBusy(false) }
  }
  function reset() { setDraft(fresh()); setReceipt(null); setError(''); setDiscard(false); attempted.current = ''; setParams((old) => { const p = new URLSearchParams(old); p.delete('notification_request'); return p }, { replace: true, preventScrollReset: true }) }
  const p = draft.preview, expired = Boolean(p && Date.parse(p.preview_expires_at) <= now)
  const currentSample = p?.rows.find((row) => row.target === sample)
  const readyConnectors = connectors?.items.filter((c) => c.enabled && c.readiness.status === 'ready' && (!c.expires_at || Date.parse(c.expires_at) > now)) || []
  return <Stack spacing={2}>
    <PageTools busy={loading || busy} error={error} onRefresh={refresh} />
    <SectionCard title={t(kind === 'invitation' ? 'nmInvitations' : 'nmReminders')} description={t('nmIndependentInvitations')}>
      <Stepper activeStep={draft.step} alternativeLabel sx={{ mb: 3 }}>{['nmSelect', 'nmPreview', 'nmConfirm', 'nmResult'].map((key) => <Step key={key}><StepLabel>{t(key)}</StepLabel></Step>)}</Stepper>
      <Stack spacing={2}>
        {page && <Alert severity="info">{t(page.access_mode === 'allow_all' ? 'nmAllowAll' : 'nmApprovedOnly')}</Alert>}
        {page && !page.communication_configured && <Alert severity="warning">{t('nmCommunicationSetup')}</Alert>}
        {draft.step === 0 && <>
          <Stack component="form" direction={{ xs: 'column', md: 'row' }} spacing={2} onSubmit={(event) => { event.preventDefault(); if (importID && !notificationUUID.test(importID)) { setError('nmInvalidReceipt'); return } setLoading(true); patch({ search, importID, preview: null }); setOffset(0); setRevision((n) => n + 1) }}>
            {kind === 'reminder' && <TextField select label={t('nmTargetGroup')} value={draft.category} onChange={(event) => { setLoading(true); patch({ category: event.target.value as Draft['category'] }); setOffset(0) }}><MenuItem value="pending">{t('nmCategory_pending')}</MenuItem><MenuItem value="unobserved">{t('nmCategory_unobserved')}</MenuItem></TextField>}
            <TextField label={t('nmSearch')} value={search} onChange={(event) => setSearch(event.target.value)} />
            {draft.category === 'pending' && <TextField label={t('nmImportReceipt')} value={importID} onChange={(event) => setImportID(event.target.value)} />}
            <Button type="submit" disabled={busy || loading}>{t('nmApplyFilters')}</Button>
          </Stack>
          <Typography variant={typographyRoles.supportingText}>{t('nmSelectionCount', { count: draft.selected.length, max: 100 })}</Typography>
          <CompactTable label={t('nmRecipients')} headers={[t('nmSelect'), t('nmEmployee'), t('nmEligibility')]} empty={!page?.items.length} emptyMessage={t('nmEmpty')} minWidth={480}>
            {page?.items.map((row) => <TableRow key={row.target}><TableCell><Checkbox checked={draft.selected.includes(row.target)} disabled={busy || draft.selected.length >= 100 && !draft.selected.includes(row.target)} onChange={(_, value) => select(row.target, value)} slotProps={{ input: { 'aria-label': t('nmSelectRecipient', { email: row.email }) } }} /></TableCell><TableCell><Typography variant={typographyRoles.primaryValue}>{row.display_name}</Typography><bdi>{row.email}</bdi></TableCell><TableCell>{t(notificationDiagnostic(row.code))}</TableCell></TableRow>)}
          </CompactTable>
          <NotificationPager offset={offset} total={page?.total || 0} busy={loading || busy} onChange={(value) => { setLoading(true); setOffset(value) }} />
          <Stack direction="row" sx={{ gap: 1, flexWrap: 'wrap' }}><Button disabled={busy || !page?.items.length || draft.selected.length >= 100} onClick={() => patch({ selected: [...new Set([...draft.selected, ...page!.items.filter((row) => !row.code).map((row) => row.target)])].slice(0, 100), preview: null })}>{t('nmSelectPage')}</Button><Button disabled={busy || !draft.selected.length} onClick={() => patch({ selected: [], preview: null })}>{t('nmClearSelection')}</Button></Stack>
          <TextField select required label={t('nmConnector')} value={readyConnectors.some((c) => c.id === draft.connector) ? draft.connector : ''} onChange={(event) => patch({ connector: event.target.value, preview: null })}>{readyConnectors.map((c) => <MenuItem key={c.id} value={c.id}>{c.provider === 'gmail' ? 'Gmail' : 'Amazon SES'} · {c.sender}</MenuItem>)}</TextField>
          {!readyConnectors.length && <Alert severity="warning">{t('nmReadyConnectorRequired')}</Alert>}
          <NotificationPager offset={connectorOffset} total={connectors?.total || 0} busy={busy || loading} onChange={(value) => { setLoading(true); setConnectorOffset(value) }} />
        </>}
        {(draft.step === 1 || draft.step === 2) && p && <>
          <Alert severity={p.ready_count ? 'info' : 'warning'}>{t('nmPreviewSummary', { ready: p.ready_count, skipped: p.skipped_count })}</Alert>
          <Typography variant={typographyRoles.supportingText}>{t('nmTemplateLanguage')}</Typography>
          <Typography variant={typographyRoles.supportingText}>{t('nmPreviewExpires', { date: formatDate(p.preview_expires_at, language) })}</Typography>
          {expired && <Alert severity="warning" action={<Button disabled={busy} onClick={() => void preview()}>{t('nmRefreshPreview')}</Button>}>{t('nmPreviewExpired')}</Alert>}
          <Box sx={{ maxHeight: 320, overflowY: 'auto' }}><CompactTable label={t('nmPreviewRecipients')} headers={[t('nmEmployee'), t('nmEligibility'), t('nmPreview')]} empty={!p.rows.length} emptyMessage={t('nmEmpty')} stickyActions>
            {p.rows.map((row) => <TableRow key={row.target}><TableCell><Typography>{row.display_name}</Typography><bdi>{row.email}</bdi></TableCell><TableCell>{t(notificationDiagnostic(row.code))}</TableCell><TableCell><Button disabled={Boolean(row.code)} onClick={() => setSample(row.target)} aria-label={t('nmPreviewRecipient', { email: row.email })}>{t('nmPreview')}</Button></TableCell></TableRow>)}
          </CompactTable></Box>
          {currentSample && !currentSample.code && <SectionCard title={t('nmEmailPreview')}><TwoColumnKeyValue items={[{ label: t('nmFrom'), value: <bdi>{p.sender}</bdi> }, { label: t('nmTo'), value: <bdi>{currentSample.email}</bdi> }, { label: t('nmSubject'), value: currentSample.subject }]} /><Typography component="p" variant="body2" dir="auto" sx={{ whiteSpace: 'pre-wrap', mt: 2 }}>{currentSample.text}</Typography></SectionCard>}
          {draft.step === 2 && <Box component="form" id="notification-enqueue-form" onSubmit={(event) => { event.preventDefault(); void enqueue() }}><Stack spacing={2}><TextField label={t('nmReason')} required multiline minRows={2} value={draft.reason} onChange={(event) => patch({ reason: event.target.value })} /><FormControlLabel control={<Checkbox checked={draft.confirmed} onChange={(_, value) => patch({ confirmed: value })} />} label={t('nmConfirmQueue', { count: p.ready_count })} /></Stack></Box>}
        </>}
        {draft.step === 3 && <>
          <Alert severity={draft.uncertain ? 'warning' : 'info'}>{t(draft.uncertain ? 'nmUncertain' : 'nmQueuedResult', { count: draft.queued })}</Alert>
          {draft.attempt && <TechnicalValue label={t('nmRequestID')} value={draft.attempt} />}
          {receipt && <Typography>{t('nmReceiptConfirmed', { count: receipt.job_count, date: formatDate(receipt.created_at, language) })}</Typography>}
          <Stack direction="row" sx={{ gap: 1, flexWrap: 'wrap' }}><Button disabled={busy || !draft.attempt} onClick={() => void inspect()}>{t('nmInspectResult')}</Button><Button disabled={!draft.attempt || busy} onClick={() => setParams((old) => { const next = new URLSearchParams(old); next.set('notification_view', 'history'); next.set('notification_request', draft.attempt); return next }, { preventScrollReset: true })}>{t('nmViewHistory')}</Button></Stack>
        </>}
        {discard && <Alert severity="warning" action={<Button disabled={busy} onClick={reset}>{t('nmDiscard')}</Button>}>{t('nmUnsaved')}</Alert>}
        <Stack direction="row" sx={{ gap: 1, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          {draft.step < 3 && <Button disabled={busy} onClick={() => setDiscard(true)}>{t('common:cancel')}</Button>}
          {(draft.step === 1 || draft.step === 2) && <Button disabled={busy} onClick={() => patch({ step: draft.step - 1, confirmed: false })}>{t('nmBack')}</Button>}
          {draft.step === 0 && <Button variant="contained" disabled={busy || loading || !draft.selected.length || !readyConnectors.some((c) => c.id === draft.connector) || !page?.communication_configured} onClick={() => void preview()}>{t('nmPreview')}</Button>}
          {draft.step === 1 && <Button variant="contained" disabled={busy || expired || !p?.ready_count} onClick={() => patch({ step: 2 })}>{t('nmReviewQueue')}</Button>}
          {draft.step === 2 && <Button variant="contained" type="submit" form="notification-enqueue-form" disabled={busy || expired || !draft.confirmed || !validNotificationReason(draft.reason) || !p?.ready_count}>{t('nmQueue')}</Button>}
          {draft.step === 3 && !draft.uncertain && <Button disabled={busy} onClick={reset}>{t('nmNewBatch')}</Button>}
        </Stack>
        <Typography variant={typographyRoles.supportingText}>{t('nmBatchLimit', { max: formatNumber(100, language) })}</Typography>
      </Stack>
    </SectionCard>
  </Stack>
}
