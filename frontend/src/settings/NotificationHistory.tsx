import { useEffect, useRef, useState } from 'react'
import { Alert, Button, MenuItem, Stack, TableCell, TableRow, TextField, Typography } from '@mui/material'
import { useBeforeUnload, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { AuthConfigurationError } from '../api/authConfiguration'
import { cancelNotification, listNotificationHistory, notificationUUID, notificationsPath, readNotificationJob, readNotificationReceipt } from '../api/notificationManagement'
import type { HistoryPage, JobDetail, NotificationReceipt } from '../api/notificationManagement'
import type { QueryCache } from '../api/cache'
import { useQueryCache } from '../api/queries'
import { useSession } from '../auth/session'
import { useNotifications } from '../notifications/notifications'
import { PageTools } from '../components/PageTools'
import CompactTable from '../components/CompactTable'
import DetailDrawer from '../components/common/DetailDrawer'
import SectionCard from '../components/common/SectionCard'
import StatusBadge from '../components/common/StatusBadge'
import TechnicalValue from '../components/common/TechnicalValue'
import TwoColumnKeyValue from '../components/common/TwoColumnKeyValue'
import { typographyRoles } from '../design/theme'
import { formatDate } from '../i18n'
import { notificationDiagnostic, notificationErrorKey, queueStates, queueTones, validNotificationReason } from './notificationManagementState'
import { NotificationPager } from './NotificationControls'

const drafts = new WeakMap<QueryCache, { id: string; reason: string; cancelling: boolean; blocked: boolean }>()
export default function NotificationHistory() {
  const { t, i18n } = useTranslation(['admin', 'common'])
  const [params, setParams] = useSearchParams()
  const cache = useQueryCache(), session = useSession(), notify = useNotifications()
  const saved = drafts.get(cache)
  const receiptID = params.get('notification_request') || ''
  const [receiptInput, setReceiptInput] = useState(receiptID), [receipt, setReceipt] = useState<NotificationReceipt | null>(null)
  const [page, setPage] = useState<HistoryPage | null>(null), [offset, setOffset] = useState(0), [revision, setRevision] = useState(0)
  const [search, setSearch] = useState(''), [query, setQuery] = useState(''), [status, setStatus] = useState('')
  const [detailID, setDetailID] = useState(saved?.id || ''), [detail, setDetail] = useState<JobDetail | null>(null), [reason, setReason] = useState(saved?.reason || ''), [cancelling, setCancelling] = useState(saved?.cancelling || false)
  const [blocked, setBlocked] = useState(saved?.blocked || false), [discard, setDiscard] = useState(false)
  const [busy, setBusy] = useState(false), [loading, setLoading] = useState(true), [error, setError] = useState('')
  const inFlight = useRef(false), readVersion = useRef(0), mounted = useRef(false), language = i18n.resolvedLanguage || 'en'
  useEffect(() => { mounted.current = true; return () => { mounted.current = false } }, [])
  useEffect(() => { drafts.set(cache, { id: detailID, reason, cancelling, blocked: blocked || busy }) }, [cache, detailID, reason, cancelling, blocked, busy])
  useBeforeUnload((event) => { if (reason || busy) { event.preventDefault(); event.returnValue = '' } })
  useEffect(() => {
    const controller = new AbortController()
    const read = receiptID ? readNotificationReceipt(receiptID, offset, controller.signal).then((r) => { if (!controller.signal.aborted) { setReceipt(r); setPage(r.jobs) } }) : listNotificationHistory(query, status, offset, controller.signal).then((p) => { if (!controller.signal.aborted) { setReceipt(null); setPage(p) } })
    void read.catch((failure) => { if (!controller.signal.aborted) { setPage(null); setReceipt(null); report(failure, false) } }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
    // Reads are bounded and explicit; mutation outcomes are never retried.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [receiptID, query, status, offset, revision])
  useEffect(() => { if (detailID) void inspect(detailID) }, [detailID]) // eslint-disable-line react-hooks/exhaustive-deps
  function report(failure: unknown, mutation: boolean) {
    const key = notificationErrorKey(failure, mutation); setError(key)
    if (failure instanceof AuthConfigurationError && failure.status === 401) session.expire()
    if (failure instanceof AuthConfigurationError && failure.status === 403) void session.refreshAccess()
    if (mutation) setBlocked(true)
    notify({ severity: 'error', messageKey: `admin:${key}` })
  }
  function refresh() { setLoading(true); setError(''); setRevision((n) => n + 1); cache.invalidate([notificationsPath]) }
  async function inspect(id = detailID) {
    if (!id) return
    const version = ++readVersion.current
    setBusy(true)
    try { const value = await readNotificationJob(id); if (mounted.current && version === readVersion.current) { setDetail(value); setBlocked(false); setError('') } }
    catch (failure) { if (mounted.current && version === readVersion.current) report(failure, false) }
    finally { if (mounted.current && version === readVersion.current) setBusy(false) }
  }
  function close() { if (busy) return; if (reason) setDiscard(true); else clear() }
  function clear() { readVersion.current++; setDetailID(''); setDetail(null); setReason(''); setCancelling(false); setBlocked(false); setDiscard(false) }
  async function cancel() {
    if (!detail || blocked || inFlight.current || !validNotificationReason(reason)) return
    inFlight.current = true; setBusy(true)
    try { await cancelNotification(detail.item.id, detail.item.generation, reason); setReason(''); setCancelling(false); notify({ severity: 'success', messageKey: 'admin:nmCancelledSuccess' }); refresh(); await inspect() }
    catch (failure) { report(failure, true) }
    finally { inFlight.current = false; setBusy(false) }
  }
  const canCancel = detail && ['queued', 'leased'].includes(detail.item.status)
  return <Stack spacing={2}>
    <PageTools busy={loading || busy} error={error} onRefresh={refresh} />
    <SectionCard title={t('nmHistory')} description={t('nmAcceptanceHelp')}>
      <Stack spacing={2}>
        <Stack component="form" direction={{ xs: 'column', md: 'row' }} spacing={2} onSubmit={(event) => { event.preventDefault(); if (receiptInput && !notificationUUID.test(receiptInput)) { setError('nmInvalidReceipt'); return } setLoading(true); setRevision((n) => n + 1); setOffset(0); setParams((old) => { const p = new URLSearchParams(old); if (receiptInput) p.set('notification_request', receiptInput); else p.delete('notification_request'); return p }, { preventScrollReset: true }) }}>
          <TextField label={t('nmRequestID')} value={receiptInput} onChange={(event) => setReceiptInput(event.target.value)} /><Button disabled={loading || busy} type="submit">{t('nmInspectResult')}</Button>
          {receiptID && <Button disabled={busy} onClick={() => { setReceiptInput(''); setLoading(true); setRevision((n) => n + 1); setOffset(0); setParams((old) => { const p = new URLSearchParams(old); p.delete('notification_request'); return p }, { preventScrollReset: true }) }}>{t('nmAllHistory')}</Button>}
        </Stack>
        {receipt && <TwoColumnKeyValue items={[{ label: t('nmRequestID'), value: <TechnicalValue label={t('nmRequestID')} value={receipt.id} /> }, { label: t('nmReason'), value: receipt.reason }, { label: t('nmConfirmedJobs'), value: receipt.job_count }]} />}
        {!receiptID && <Stack component="form" direction={{ xs: 'column', sm: 'row' }} spacing={2} onSubmit={(event) => { event.preventDefault(); setLoading(true); setRevision((n) => n + 1); setQuery(search); setOffset(0) }}><TextField label={t('nmSearch')} value={search} onChange={(event) => setSearch(event.target.value)} /><TextField select label={t('nmQueueStatus')} value={status} onChange={(event) => { setLoading(true); setStatus(event.target.value); setOffset(0) }}><MenuItem value="">{t('nmAllStates')}</MenuItem>{queueStates.map((state) => <MenuItem key={state} value={state}>{t(`nmState_${state}`)}</MenuItem>)}</TextField><Button type="submit" disabled={loading}>{t('nmApplyFilters')}</Button></Stack>}
        <CompactTable label={t('nmHistory')} headers={[t('nmEmployee'), t('nmType'), t('nmConnector'), t('nmRequestedBy'), t('nmQueueStatus'), t('nmCreated'), t('actions')]} empty={!page?.items.length} emptyMessage={t('nmEmpty')} stickyActions minWidth={780}>
          {page?.items.map((row) => <TableRow key={row.id}>
            <TableCell><Typography variant={typographyRoles.primaryValue}>{row.display_name}</Typography><bdi>{row.recipient}</bdi></TableCell>
            <TableCell>{t(row.type === 'invitation' ? 'nmInvitationType' : 'nmReminderType')}</TableCell>
            <TableCell>{row.provider === 'gmail' ? 'Gmail' : 'Amazon SES'}<Typography variant={typographyRoles.supportingText}><bdi>{row.sender}</bdi></Typography></TableCell>
            <TableCell>{row.actor_name || t('nmAdministrator')}</TableCell>
            <TableCell><StatusBadge label={t(`nmState_${row.status}`)} tone={queueTones[row.status]} /><Typography variant={typographyRoles.supportingText}>{t(`nmAttempt_${row.attempt_outcome || 'none'}`)}</Typography></TableCell>
            <TableCell>{formatDate(row.created_at, language)}</TableCell>
            <TableCell><Button disabled={busy} onClick={() => { setDetail(null); setDetailID(row.id) }} aria-label={t('nmViewRecipient', { email: row.recipient })}>{t('nmView')}</Button></TableCell>
          </TableRow>)}
        </CompactTable>
        <NotificationPager offset={offset} total={page?.total || 0} busy={loading || busy} onChange={(value) => { setLoading(true); setOffset(value) }} />
      </Stack>
    </SectionCard>
    <DetailDrawer open={Boolean(detailID)} title={t('nmEmailDetails')} onClose={close} actions={<><Button disabled={busy} onClick={close}>{t('common:close')}</Button>{blocked ? <Button disabled={busy} onClick={() => void inspect()}>{t('nmInspectResult')}</Button> : canCancel && <Button color="error" disabled={busy || cancelling && !validNotificationReason(reason)} onClick={() => { if (cancelling) void cancel(); else setCancelling(true) }}>{t(cancelling ? 'nmConfirmCancel' : 'nmCancelJob')}</Button>}</>}>
      <Stack spacing={2}>
        {detail && <>
          <StatusBadge label={t(`nmState_${detail.item.status}`)} tone={queueTones[detail.item.status]} />
          <TwoColumnKeyValue items={[{ label: t('nmTo'), value: <bdi>{detail.item.recipient}</bdi> }, { label: t('nmFrom'), value: <bdi>{detail.item.sender}</bdi> }, { label: t('nmCreated'), value: formatDate(detail.item.created_at, language) }, { label: t('nmDiagnostic'), value: detail.item.disposition ? t(notificationDiagnostic(detail.item.disposition)) : t('nmNoDiagnostic') }, { label: t('nmRequestedBy'), value: detail.item.actor_name || t('nmAdministrator') }]} />
          <TechnicalValue label={t('nmJobID')} value={detail.item.id} /><TechnicalValue label={t('nmRequestID')} value={detail.item.request_id} /><TechnicalValue label={t('nmAdministratorID')} value={detail.item.actor_id} /><TechnicalValue label={t('nmConnectorID')} value={detail.item.connector_id} /><TechnicalValue label={t('nmTargetReference')} value={detail.item.target} />
          <Alert severity={detail.item.status === 'needs_inspection' ? 'warning' : 'info'}>{t(detail.item.status === 'needs_inspection' ? 'nmNeedsInspectionHelp' : 'nmAcceptanceHelp')}</Alert>
          <SectionCard title={t('nmAttempts')}>
            {!detail.attempts.length && <Typography>{t('nmAttempt_none')}</Typography>}
            {detail.attempts.map((attempt) => <Stack key={attempt.number} spacing={1} sx={{ mb: 2 }}><Typography>{t(`nmAttempt_${attempt.outcome}`)}</Typography><Typography variant="body2">{formatDate(attempt.started_at, language)}</Typography>{attempt.code && <Typography>{t(notificationDiagnostic(attempt.code))}</Typography>}{attempt.provider_message_id && <TechnicalValue label={t('nmProviderMessageID')} value={attempt.provider_message_id} />}</Stack>)}
          </SectionCard>
          {cancelling && <><Alert severity="warning">{t('nmCancelHelp')}</Alert><TextField required multiline minRows={2} label={t('nmReason')} value={reason} onChange={(event) => setReason(event.target.value)} /></>}
        </>}
        {error && <Alert severity="error">{t(error)}</Alert>}
        {discard && <Alert severity="warning" action={<Button onClick={clear}>{t('nmDiscard')}</Button>}>{t('nmUnsaved')}</Alert>}
      </Stack>
    </DetailDrawer>
  </Stack>
}
