import { useEffect, useRef, useState } from 'react'
import { Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, MenuItem, Stack, TableCell, TableRow, TextField, Typography } from '@mui/material'
import { useBeforeUnload } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { AuthConfigurationError } from '../api/authConfiguration'
import { accessPolicyPath, createInvitation, listInvitations, readInvitation, revokeInvitation } from '../api/accessPolicy'
import type { AccessPolicySettings, Invitation, InvitationExpectation, InvitationPage, InvitationStatus } from '../api/accessPolicy'
import { useQueryCache } from '../api/queries'
import type { QueryCache } from '../api/cache'
import { useSession } from '../auth/session'
import CompactTable from '../components/CompactTable'
import DetailDrawer from '../components/common/DetailDrawer'
import SectionCard from '../components/common/SectionCard'
import StatusBadge from '../components/common/StatusBadge'
import TechnicalValue from '../components/common/TechnicalValue'
import TwoColumnKeyValue from '../components/common/TwoColumnKeyValue'
import { typographyRoles } from '../design/theme'
import { formatDate, formatNumber } from '../i18n'
import { useNotifications } from '../notifications/notifications'

const statuses: InvitationStatus[] = ['pending', 'claimed', 'revoked', 'expired']
const tone = { pending: 'info', claimed: 'success', revoked: 'error', expired: 'neutral' } as const
const noControls = (value: string) => [...value].every((char) => { const code = char.codePointAt(0)!; return code >= 32 && (code < 127 || code > 159) })
const expiresInDays = (days: number) => new Date(Date.now() + days * 86400000).toISOString()
const validReason = (value: string) => new TextEncoder().encode(value.trim()).length >= 8 && new TextEncoder().encode(value).length <= 512 && noControls(value)
const validEmail = (value: string) => value.length <= 254 && /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/u.test(value) && value.split('@')[0].length <= 64 && value.split('@')[1].includes('.') && /^[A-Za-z]/u.test(value.split('@')[1].split('.').at(-1)!) && value.split('@')[1].split('.').every((label) => label.length <= 63 && /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u.test(label))
const canRevoke = (item: Invitation, now: number) => item.status === 'pending' && item.binding_current && Date.parse(item.expires_at) > now
const expectation = (page: InvitationPage): InvitationExpectation => ({ expected_policy_generation: page.policy_generation, expected_activation_generation: page.activation_generation, revision_id: page.revision_id, expected_revision_generation: page.revision_generation })
type Workflow = { kind: 'create'; expected: InvitationExpectation } | { kind: 'revoke'; item: Invitation; expected: InvitationExpectation }
type FormMemory = { workflow: Workflow | null; email: string; name: string; days: string; reason: string; error: string; conflict: boolean; uncertain: boolean }
// The existing cache belongs to one signed-in identity. Drafts survive route
// changes only in memory; disposing that cache also releases its draft.
const invitationDrafts = new WeakMap<QueryCache, FormMemory>()

export default function InvitationManagement({ mode, refresh, disabled, onChanged, onViewUser }: {
  mode?: AccessPolicySettings['mode']; refresh: number; disabled: boolean; onChanged: () => void; onViewUser: (id: string) => void
}) {
  const { t, i18n } = useTranslation(['auth', 'common', 'admin'])
  const cache = useQueryCache(), notify = useNotifications(), { expire, refreshAccess } = useSession()
  const [restored] = useState(() => invitationDrafts.get(cache))
  const [writing, setWriting] = useState(false)
  const [now, setNow] = useState(() => Date.now())
  const [page, setPage] = useState<InvitationPage | null>(null)
  const [search, setSearch] = useState(''), [status, setStatus] = useState(''), [offset, setOffset] = useState(0), [reload, setReload] = useState(0)
  const [loading, setLoading] = useState(true), [readError, setReadError] = useState('')
  const [workflow, setWorkflow] = useState<Workflow | null>(restored?.workflow || null), [detail, setDetail] = useState<Invitation | null>(null)
  const [email, setEmail] = useState(restored?.email || ''), [name, setName] = useState(restored?.name || ''), [days, setDays] = useState(restored?.days || '7'), [reason, setReason] = useState(restored?.reason || '')
  const [error, setError] = useState(restored?.error || ''), [busy, setBusy] = useState(false), [conflict, setConflict] = useState(restored?.conflict || false), [uncertain, setUncertain] = useState(restored?.uncertain || false), [discard, setDiscard] = useState(false)
  const inFlight = useRef(false), mounted = useRef(true), detailRequest = useRef<AbortController | null>(null)
  const dirty = Boolean(workflow && (reason || (workflow.kind === 'create' && (email || name || days !== '7'))))
  useEffect(() => {
    if (workflow || uncertain || writing) invitationDrafts.set(cache, { workflow, email, name, days, reason, error: writing ? 'invitationUncertain' : error, conflict, uncertain: uncertain || writing })
    else invitationDrafts.delete(cache)
  }, [cache, workflow, email, name, days, reason, error, conflict, uncertain, writing])
  useBeforeUnload((event) => { if (dirty || busy) { event.preventDefault(); event.returnValue = '' } })
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; detailRequest.current?.abort() } }, [])
  useEffect(() => {
    const controller = new AbortController()
    void listInvitations(search, status, offset, controller.signal).then((next) => {
      if (!controller.signal.aborted) { setPage(next); setReadError('') }
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      setReadError(failure instanceof AuthConfigurationError && [404, 409].includes(failure.status) ? 'invitationNotReady' : failure instanceof AuthConfigurationError && failure.status === 400 ? 'invitationInvalid' : 'invitationUnavailable')
      if (failure instanceof AuthConfigurationError && failure.status === 401) expire()
      if (failure instanceof AuthConfigurationError && failure.status === 403) { setReadError('common:accessDenied'); setPage(null); refreshAccess() }
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [search, status, offset, refresh, reload, expire, refreshAccess])
  // Re-evaluate local expiry without polling or making another write.
  useEffect(() => {
    const items = [...(page?.items || []), ...(detail ? [detail] : []), ...(workflow?.kind === 'revoke' ? [workflow.item] : [])]
    const deadlines = items.filter((item) => item.status === 'pending').map((item) => Date.parse(item.expires_at)).filter((time) => time > now)
    if (!deadlines.length) return
    const timer = window.setTimeout(() => setNow(Date.now()), Math.min(2147483647, Math.max(1, Math.min(...deadlines) - Date.now() + 1)))
    return () => window.clearTimeout(timer)
  }, [page, detail, workflow, now])
  const language = i18n.resolvedLanguage || 'en'
  const blocked = disabled || loading || busy || Boolean(readError) || uncertain || !page
  function refreshList() { setLoading(true); setReload((value) => value + 1) }
  function close() { if (!busy) { if (dirty) setDiscard(true); else setWorkflow(null) } }
  function begin(kind: 'create' | 'revoke', item?: Invitation) {
    if (blocked || !page || (kind === 'revoke' && (!item || !canRevoke(item, now)))) return
    detailRequest.current?.abort(); setDetail(null); setReason(''); setEmail(''); setName(''); setDays('7'); setError(''); setConflict(false); setDiscard(false)
    setWorkflow(kind === 'create' ? { kind, expected: expectation(page) } : { kind, item: item!, expected: expectation(page) })
  }
  async function view(item: Invitation) {
    detailRequest.current?.abort()
    const controller = new AbortController(); detailRequest.current = controller
    try { const current = await readInvitation(item.id, controller.signal); if (!controller.signal.aborted) setDetail(current) }
    catch (failure) { if (!controller.signal.aborted) report(failure, false) }
  }
  function report(failure: unknown, mutation: boolean) {
    const status = failure instanceof AuthConfigurationError ? failure.status : 0
    const ambiguous = mutation && (!status || status >= 500)
    const key = ambiguous ? 'invitationUncertain' : status === 400 ? 'invitationInvalid' : status === 409 ? 'invitationConflict' : status === 404 ? 'invitationMissing' : [401, 403].includes(status) ? 'common:accessDenied' : 'invitationUnavailable'
    setError(key); notify({ severity: ambiguous ? 'warning' : 'error', messageKey: key.includes(':') ? key as `${string}:${string}` : `auth:${key}` })
    if (ambiguous) setUncertain(true)
    if (status === 409 || status === 404) { if (mutation) setConflict(true); refreshList() }
    if ([401, 403].includes(status)) { setReadError('common:accessDenied'); setPage(null) }
    if (status === 401) expire()
    if (status === 403) { setConflict(true); refreshAccess() }
  }
  async function reviewFresh() {
    if (!workflow || busy || uncertain || inFlight.current) return
    inFlight.current = true; setBusy(true)
    try {
      const next = await listInvitations(search, status, offset)
      const item = workflow.kind === 'revoke' ? await readInvitation(workflow.item.id) : null
      if (!mounted.current) return
      setPage(next)
      if (item && !canRevoke(item, now)) { setConflict(true); setError('invitationNotRevocable'); return }
      setWorkflow(item ? { kind: 'revoke', item, expected: expectation(next) } : { kind: 'create', expected: expectation(next) })
      setConflict(false); setError(''); setReadError('')
    } catch (failure) { if (mounted.current) report(failure, false) }
    finally { inFlight.current = false; if (mounted.current) setBusy(false) }
  }
  const valid = validReason(reason) && (workflow?.kind !== 'create' || (validEmail(email) && [...name].length <= 200 && noControls(name) && Number.isInteger(Number(days)) && Number(days) >= 1 && Number(days) <= 30))
  async function submit() {
    if (!workflow || !valid || blocked || conflict || inFlight.current || (workflow.kind === 'revoke' && !canRevoke(workflow.item, now))) return
    inFlight.current = true; setBusy(true); setWriting(true); setError('')
    try {
      if (workflow.kind === 'create') await createInvitation({ email, display_name: name, reason, ...(days === '7' ? {} : { expires_at: expiresInDays(Number(days)) }) }, workflow.expected)
      else await revokeInvitation(workflow.item.id, workflow.expected, workflow.item.generation, reason)
      cache.invalidate([accessPolicyPath, '/api/admin/users', '/api/admin/audit'])
      if (!mounted.current) return
      notify({ severity: 'success', messageKey: workflow.kind === 'create' ? 'auth:invitationCreated' : 'auth:invitationRevoked' })
      setWorkflow(null); setReason(''); setEmail(''); setName(''); setSearch(''); setStatus(''); setOffset(0)
      refreshList(); onChanged()
    } catch (failure) { if (mounted.current) report(failure, true) }
    finally { inFlight.current = false; if (mounted.current) { setBusy(false); setWriting(false) } }
  }
  return <SectionCard title={t('invitationsTitle')} description={t('invitationNoEmail')} busy={loading || busy}
    actions={<Button variant="contained" disabled={blocked} onClick={() => begin('create')}>{t('invitationAddUser')}</Button>}>
    <Stack spacing={2}>
      <Alert severity="info">{t(mode === 'approved_users_only' ? 'invitationApprovedOnly' : 'invitationAllowAll')}</Alert>
      {readError && <Alert severity="warning">{t(readError)}</Alert>}
      {uncertain && <Alert severity="warning" role="alert">{t('invitationUncertain')}</Alert>}
      {error && !workflow && !uncertain && <Alert severity="error">{t(error)}</Alert>}
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
        <TextField fullWidth label={t('invitationSearch')} value={search} onChange={(event) => { if (new TextEncoder().encode(event.target.value).length <= 200) { setSearch(event.target.value); setOffset(0); setLoading(true) } }} slotProps={{ htmlInput: { maxLength: 200 } }} />
        <TextField select label={t('invitationStatus')} value={status} sx={{ minWidth: 180 }} onChange={(event) => { setStatus(event.target.value); setOffset(0); setLoading(true) }}>
          <MenuItem value="">{t('accessAllStatuses')}</MenuItem>{statuses.map((value) => <MenuItem key={value} value={value}>{t(`invitationStatus_${value}`)}</MenuItem>)}
        </TextField>
      </Stack>
      {loading && <Typography role="status" variant={typographyRoles.supportingText}>{t('common:loading')}</Typography>}
      <CompactTable label={t('invitationsTitle')} headers={[t('invitationEmployee'), t('invitationStatus'), t('createdAt'), t('invitationExpires'), t('actions')]} minWidth={600} stickyActions empty={!loading && !page?.items.length} emptyMessage={t('invitationEmpty')}>
        {page?.items.map((item) => <TableRow key={item.id}>
          <TableCell sx={{ maxWidth: 260 }}><Typography variant={typographyRoles.primaryValue} noWrap title={item.display_name || item.email} sx={{ fontWeight: 600 }}><bdi>{item.display_name || item.email}</bdi></Typography>{item.display_name && <Typography variant={typographyRoles.supportingText} noWrap color="text.secondary" title={item.email}><bdi>{item.email}</bdi></Typography>}{!item.binding_current && <Typography variant={typographyRoles.detailLabel} color="warning.main">{t('invitationHistorical')}</Typography>}</TableCell>
          <TableCell><StatusBadge label={t(`invitationStatus_${item.status}`)} tone={tone[item.status]} /></TableCell>
          <TableCell sx={{ whiteSpace: 'nowrap' }}>{formatDate(item.created_at, language)}</TableCell><TableCell sx={{ whiteSpace: 'nowrap' }}>{formatDate(item.expires_at, language)}</TableCell>
          <TableCell><Stack direction="row" sx={{ gap: 0.5, flexWrap: 'wrap' }}><Button size="small" disabled={busy} onClick={() => void view(item)} aria-label={t('invitationViewEmployee', { email: item.email })}>{t('view')}</Button>{item.status === 'pending' && <Button size="small" color="error" disabled={blocked || !canRevoke(item, now)} onClick={() => begin('revoke', item)} aria-label={t('invitationRevokeEmployee', { email: item.email })}>{t('invitationRevoke')}</Button>}</Stack></TableCell>
        </TableRow>)}
      </CompactTable>
      <Stack direction="row" role="group" aria-label={t('invitationPagination')} sx={{ gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
        <Button disabled={loading || offset === 0} onClick={() => { setOffset(Math.max(0, offset - 20)); setLoading(true) }}>{t('common:previousPage')}</Button>
        <Typography variant={typographyRoles.supportingText} color="text.secondary">{t('invitationCount', { count: page?.total || 0, page: formatNumber(offset / 20 + 1, language) })}</Typography>
        <Button disabled={loading || !page || offset + 20 >= page.total || offset >= 100000} onClick={() => { setOffset(offset + 20); setLoading(true) }}>{t('common:nextPage')}</Button>
      </Stack>
    </Stack>
    <Dialog open={Boolean(workflow)} onClose={close} fullWidth maxWidth="sm" aria-labelledby="invitation-dialog-title">
      <DialogTitle id="invitation-dialog-title">{t(workflow?.kind === 'revoke' ? 'invitationRevokeTitle' : 'invitationAddUser')}</DialogTitle>
      <DialogContent dividers><Box component="form" id="invitation-form" onSubmit={(event) => { event.preventDefault(); void submit() }}><Stack spacing={2}>
        {error && <Alert severity={uncertain ? 'warning' : 'error'}>{t(error)}</Alert>}
        {workflow?.kind === 'create' ? <>
          <Typography variant={typographyRoles.supportingText}>{t('invitationNoEmail')}</Typography>
          <TextField autoFocus required fullWidth label={t('email')} value={email} error={Boolean(email && !validEmail(email))} helperText={email && !validEmail(email) ? t('invitationEmailHelp') : undefined} onChange={(event) => setEmail(event.target.value)} disabled={busy || uncertain} slotProps={{ htmlInput: { maxLength: 254, dir: 'ltr', autoComplete: 'off' } }} />
          <TextField fullWidth label={t('displayName')} value={name} onChange={(event) => setName(event.target.value)} disabled={busy || uncertain} slotProps={{ htmlInput: { maxLength: 200 } }} />
          <TextField required type="number" label={t('invitationExpiration')} value={days} onChange={(event) => setDays(event.target.value)} disabled={busy || uncertain} helperText={t('invitationExpirationHelp')} slotProps={{ htmlInput: { min: 1, max: 30, step: 1 } }} />
        </> : workflow && <><Typography variant={typographyRoles.primaryValue}><bdi>{workflow.item.email}</bdi></Typography><Typography variant={typographyRoles.supportingText}>{t('invitationRevokeHelp')}</Typography><Alert severity="warning">{t('invitationAccessHelp')}</Alert></>}
        <TextField autoFocus={workflow?.kind === 'revoke'} required fullWidth multiline minRows={2} label={t('accessReason')} value={reason} disabled={busy || uncertain} onChange={(event) => setReason(event.target.value)} helperText={t('invitationReasonHelp')} slotProps={{ htmlInput: { maxLength: 512 } }} />
        {discard && <Alert severity="warning">{t('invitationDiscardHelp')}</Alert>}
        {conflict && !uncertain && <Button disabled={busy} onClick={() => void reviewFresh()}>{t('invitationReviewFresh')}</Button>}
        {uncertain && <Button disabled={busy} onClick={() => { setWorkflow(null); refreshList() }}>{t('invitationInspect')}</Button>}
      </Stack></Box></DialogContent>
      <DialogActions>{discard ? <><Button onClick={() => setDiscard(false)}>{t('invitationKeepEditing')}</Button><Button color="error" onClick={() => { setWorkflow(null); setDiscard(false) }}>{t('invitationDiscard')}</Button></> : <><Button disabled={busy} onClick={close}>{t('common:cancel')}</Button><Button type="submit" form="invitation-form" variant="contained" color={workflow?.kind === 'revoke' ? 'error' : 'primary'} disabled={blocked || conflict || !valid} >{t(workflow?.kind === 'revoke' ? 'invitationConfirmRevoke' : 'invitationCreate')}</Button></>}</DialogActions>
    </Dialog>
    <DetailDrawer open={Boolean(detail)} onClose={() => setDetail(null)} title={t('invitationDetails')} titleAdornment={detail && <StatusBadge label={t(`invitationStatus_${detail.status}`)} tone={tone[detail.status]} />}
      actions={detail && <><Button onClick={() => setDetail(null)}>{t('common:close')}</Button>{detail.claimed_user_id && <Button disabled={busy} onClick={() => { const id = detail.claimed_user_id!; setDetail(null); onViewUser(id) }}>{t('accessDetails')}</Button>}{detail.status === 'pending' && <Button color="error" disabled={blocked || !canRevoke(detail, now)} onClick={() => begin('revoke', detail)}>{t('invitationRevoke')}</Button>}</>}>
      {detail && <Stack spacing={2}>
        {!detail.binding_current && <Alert severity="warning">{t('invitationStaleHelp')}</Alert>}
        <TwoColumnKeyValue items={[
          { label: t('displayName'), value: <bdi>{detail.display_name || t('common:none')}</bdi> }, { label: t('email'), value: <bdi>{detail.email}</bdi> },
          { label: t('createdAt'), value: formatDate(detail.created_at, language) }, { label: t('invitationExpires'), value: formatDate(detail.expires_at, language) },
          { label: t('accessReason'), value: <bdi>{detail.reason}</bdi> },
        ]} />
        {detail.status === 'claimed' && <><Typography component="h3" variant={typographyRoles.sectionTitle}>{t('invitationClaimedIdentity')}</Typography><TwoColumnKeyValue items={[
          { label: t('invitationClaimedAt'), value: detail.claimed_at ? formatDate(detail.claimed_at, language) : t('common:none') },
          ...[[t('invitationUserID'), detail.claimed_user_id], [t('accessIssuer'), detail.claimed_issuer], [t('accessSubject'), detail.claimed_subject]].map(([label, value]) => ({ label: label!, value: value ? <TechnicalValue label={label!} value={value} /> : t('common:none') })),
        ]} /></>}
        <Typography component="h3" variant={typographyRoles.sectionTitle}>{t('detailConfiguration')}</Typography>
        <TwoColumnKeyValue items={[
          ...[[t('invitationID'), detail.id], [t('accessIssuer'), detail.issuer], [t('clientID'), detail.client_id], [t('revisionID'), detail.revision_id]].map(([label, value]) => ({ label, value: <TechnicalValue label={label} value={value} /> })),
          { label: t('revisionGeneration'), value: formatNumber(detail.revision_generation, language) },
          { label: t('invitationActivation'), value: formatNumber(detail.activation_generation, language) },
        ]} />
      </Stack>}
    </DetailDrawer>
  </SectionCard>
}
