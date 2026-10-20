import { useEffect, useRef, useState } from 'react'
import { Alert, Box, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, MenuItem, Stack, TableCell, TableRow, TextField, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { AuthConfigurationError } from '../api/authConfiguration'
import { accessPolicyPath, listAccessIdentities, previewAccessPolicy, readAccessIdentity, readAccessPolicy, setUserApproval, updateAccessPolicy } from '../api/accessPolicy'
import type { AccessIdentity, AccessPolicySettings, IdentityPage, PolicyExpectation, PolicyPreview, PolicySnapshot } from '../api/accessPolicy'
import { useQueryCache } from '../api/queries'
import { useSession } from '../auth/session'
import CompactTable from '../components/CompactTable'
import DetailDrawer from '../components/common/DetailDrawer'
import SectionCard from '../components/common/SectionCard'
import StatusBadge from '../components/common/StatusBadge'
import TwoColumnKeyValue from '../components/common/TwoColumnKeyValue'
import { formatDate, formatNumber, roleKeys } from '../i18n'
import { useNotifications } from '../notifications/notifications'

type Draft = { settings: AccessPolicySettings; domains: string; expected: PolicyExpectation }
type Confirmation = { kind: 'policy'; preview: PolicyPreview; draft: Draft } | { kind: 'approval'; identity: AccessIdentity; status: 'approved' | 'revoked'; expected: PolicyExpectation }
const validReason = (value: string) => value.trim().length >= 8 && new TextEncoder().encode(value).length <= 512 && [...value].every((char) => { const code = char.codePointAt(0)!; return code >= 32 && (code < 127 || code > 159) })
const settingsOf = (draft: Draft): AccessPolicySettings => ({ mode: draft.settings.mode, default_role: draft.settings.default_role, allowed_email_domains: draft.domains.trim() ? draft.domains.split(/[\s,;]+/u).filter(Boolean) : [] })
function failureKey(error: unknown): `${string}:${string}` {
  if (!(error instanceof AuthConfigurationError)) return 'auth:accessUnavailable'
  if (error.code === 'access_policy_last_oidc_administrator') return 'auth:accessLastAdmin'
  if (error.code === 'access_policy_self_access_loss_confirmation_required') return 'auth:accessSelfLoss'
  if (error.code === 'access_policy_conflict' || error.status === 409) return 'auth:accessConflict'
  if (error.code === 'access_policy_invalid' || error.status === 400) return 'auth:accessInvalid'
  if (error.status === 401 || error.status === 403) return 'common:accessDenied'
  return 'auth:accessUnavailable'
}

export default function UserAccess() {
  const { t, i18n } = useTranslation(['auth', 'admin', 'common'])
  const session = useSession(), cache = useQueryCache(), notify = useNotifications()
  const { expire, refreshAccess } = session
  const authorized = session.authentication.status === 'authenticated' && session.access.user?.active && session.access.user.permissions.includes('admin.manage')
  const [snapshot, setSnapshot] = useState<PolicySnapshot | null>(null), [page, setPage] = useState<IdentityPage | null>(null)
  const [search, setSearch] = useState(''), [status, setStatus] = useState(''), [offset, setOffset] = useState(0), [refresh, setRefresh] = useState(0)
  const [readFailed, setReadFailed] = useState(false)
  const [loading, setLoading] = useState(true), [setup, setSetup] = useState(false), [error, setError] = useState('')
  const [draft, setDraft] = useState<Draft | null>(null), [confirmation, setConfirmation] = useState<Confirmation | null>(null)
  const [reason, setReason] = useState(''), [confirmLoss, setConfirmLoss] = useState(false), [busy, setBusy] = useState(false), [uncertain, setUncertain] = useState(false)
  const [detail, setDetail] = useState<AccessIdentity | null>(null)
  const inFlight = useRef(false), mounted = useRef(true)
  useEffect(() => { mounted.current = true; return () => { mounted.current = false } }, [])
  useEffect(() => {
    if (!authorized) return
    const controller = new AbortController()
    void Promise.all([readAccessPolicy(controller.signal), listAccessIdentities(search, status, offset, controller.signal)]).then(([next, identities]) => {
      if (controller.signal.aborted) return
      if (next.policy.generation !== identities.policy_generation || next.activation_generation !== identities.activation_generation) {
        setError('auth:accessConflict'); setReadFailed(true); return
      }
      setSnapshot(next); setPage(identities); setSetup(false); setReadFailed(false)
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      if (failure instanceof AuthConfigurationError && failure.code === 'access_policy_setup_required') { setSetup(true); setSnapshot(null); setPage(null) }
      else {
        setError(failureKey(failure)); setReadFailed(true)
        if (failure instanceof AuthConfigurationError && failure.status === 401) expire()
        else if (failure instanceof AuthConfigurationError && failure.status === 403) refreshAccess()
      }
    }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [authorized, search, status, offset, refresh, expire, refreshAccess])
  if (!authorized) return <Alert severity="error">{t('common:accessDenied')}</Alert>
  const language = i18n.resolvedLanguage || 'en', policy = snapshot?.policy
  const expected: PolicyExpectation = { expected_policy_generation: policy?.generation || 0, expected_activation_generation: snapshot?.activation_generation || 0 }
  const values = draft?.settings || policy
  const domains = draft?.domains ?? policy?.allowed_email_domains.join(', ') ?? ''
  const blocked = busy || loading || setup || uncertain || readFailed || !snapshot
  function requestRefresh() { setLoading(true); setRefresh((n) => n + 1) }
  function edit(next: Partial<AccessPolicySettings>, newDomains = domains) {
    if (!policy) return
    setDraft({ settings: { ...(draft?.settings || policy), ...next }, domains: newDomains, expected: draft?.expected || expected })
  }
  function report(failure: unknown, mutation: boolean) {
    const unknown = mutation && (!(failure instanceof AuthConfigurationError) || failure.status >= 500)
    const key = unknown ? 'auth:accessUncertain' : failureKey(failure)
    if (unknown) setUncertain(true)
    setError(key); notify({ severity: unknown ? 'warning' : 'error', messageKey: key })
    // Refresh is read-only; never retry a write, including an ambiguous one.
    if (failure instanceof AuthConfigurationError && failure.status === 409) requestRefresh()
  }
  async function run(operation: () => Promise<void>) {
    if (inFlight.current) return
    inFlight.current = true; setBusy(true); setError('')
    try { await operation() } finally { inFlight.current = false; if (mounted.current) setBusy(false) }
  }
  async function review() {
    if (!draft || blocked) return
    await run(async () => {
      try {
        const preview = await previewAccessPolicy(settingsOf(draft), draft.expected)
        setConfirmation({ kind: 'policy', preview, draft }); setReason(''); setConfirmLoss(false)
      } catch (failure) { report(failure, false) }
    })
  }
  async function save() {
    if (!confirmation || !validReason(reason) || busy || uncertain || error === 'auth:accessConflict') return
    const change = confirmation
    await run(async () => {
      try {
        if (change.kind === 'policy') await updateAccessPolicy(settingsOf(change.draft), change.draft.expected, reason, confirmLoss)
        else await setUserApproval(change.identity.user_id, change.status, change.expected, change.identity.approval_generation, reason)
        setDraft(null); setConfirmation(null); requestRefresh()
        cache.invalidate([accessPolicyPath, '/api/admin/users', '/api/admin/audit'])
        session.refreshAccess()
        notify({ severity: 'success', messageKey: 'auth:accessSaved' })
      } catch (failure) { report(failure, true) }
    })
  }
  const selfLoss = confirmation?.kind === 'policy' ? confirmation.preview.current_administrator_loses_access
    : confirmation?.kind === 'approval' && confirmation.status === 'revoked' && confirmation.identity.user_id === session.access.user?.id
  return <Stack spacing={2} sx={{ minWidth: 0 }}>
    <Stack direction="row" sx={{ justifyContent: 'flex-end' }}><Button disabled={busy || loading} onClick={() => { setError(''); requestRefresh() }}>{t('accessReload')}</Button></Stack>
    {error && <Alert severity={uncertain ? 'warning' : 'error'} role="alert">{t(error)}</Alert>}
    {setup ? <SectionCard title={t('accessSetupTitle')}><Alert severity="info">{t('accessSetupHelp')}</Alert></SectionCard> : <>
    {loading && !snapshot && <Typography role="status">{t('common:loading')}</Typography>}
    {snapshot && <SectionCard title={t('accessOverview')} busy={loading}>
      <TwoColumnKeyValue items={[
        { label: t('accessWho'), value: t(policy?.mode === 'allow_all' ? 'accessAllowAll' : 'accessApprovedOnly') },
        { label: t('accessApprovedCount'), value: formatNumber(snapshot.overview.approved, language) },
        { label: t('accessRevokedCount'), value: formatNumber(snapshot.overview.revoked, language) },
        { label: t('accessActiveCount'), value: formatNumber(snapshot.overview.active_oidc_users, language) },
        { label: t('accessDomains'), value: <bdi>{policy?.allowed_email_domains.join(', ') || t('accessNoDomains')}</bdi> },
        { label: t('accessDefaultRole'), value: t(`admin:${roleKeys[policy?.default_role || 'Viewer']}`) },
      ]} />
    </SectionCard>}
    {values && <SectionCard title={t('accessPolicyTitle')} busy={busy}>
      <Box component="form" onSubmit={(event) => { event.preventDefault(); void review() }}>
      <Stack spacing={2}>
        <TextField select fullWidth label={t('accessWho')} value={values.mode} disabled={blocked} onChange={(event) => edit({ mode: event.target.value as AccessPolicySettings['mode'] })}>
          <MenuItem value="allow_all">{t('accessAllowAll')}</MenuItem><MenuItem value="approved_users_only">{t('accessApprovedOnly')}</MenuItem>
        </TextField>
        <TextField fullWidth label={t('accessDomains')} value={domains} disabled={blocked} helperText={t('accessDomainsHelp')} onChange={(event) => edit({}, event.target.value)} slotProps={{ htmlInput: { maxLength: 5100, dir: 'ltr' } }} />
        <TextField select fullWidth label={t('accessDefaultRole')} value={values.default_role} disabled={blocked} onChange={(event) => edit({ default_role: event.target.value as 'Viewer' | 'User' })}>
          {(['Viewer', 'User'] as const).map((role) => <MenuItem key={role} value={role}>{t(`admin:${roleKeys[role]}`)}</MenuItem>)}
        </TextField>
        {draft && <Typography role="status" variant="body2">{t('accessUnsaved')}</Typography>}
        <Stack direction="row" spacing={1}><Button type="submit" variant="contained" disabled={blocked || !draft}>{t('accessSave')}</Button><Button disabled={busy || !draft} onClick={() => { setDraft(null); setError('') }}>{t('common:cancel')}</Button></Stack>
      </Stack></Box>
    </SectionCard>}
    <SectionCard title={t('accessIdentities')} description={t('accessIdentitiesHelp')} busy={loading}>
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} sx={{ mb: 2 }}>
        <TextField fullWidth label={t('accessSearch')} value={search} onChange={(event) => { setLoading(true); setError(''); setSearch(event.target.value); setOffset(0) }} slotProps={{ htmlInput: { maxLength: 200 } }} />
        <TextField select label={t('accessFilter')} value={status} onChange={(event) => { setLoading(true); setError(''); setStatus(event.target.value); setOffset(0) }} sx={{ minWidth: 180 }}>
          <MenuItem value="">{t('accessAllStatuses')}</MenuItem>{(['approved', 'revoked', 'not_approved'] as const).map((value) => <MenuItem key={value} value={value}>{t(value === 'approved' ? 'accessApproved' : value === 'revoked' ? 'accessRevoked' : 'accessNotApproved')}</MenuItem>)}
        </TextField>
      </Stack>
      <CompactTable label={t('accessIdentities')} headers={[t('accessIssuer'), t('accessSubject'), t('email'), t('accessFilter'), t('admin:userRecordStatus'), t('common:navRoles'), t('accessModified'), t('actions')]}
        minWidth={900} empty={!loading && !page?.items.length} emptyMessage={t('admin:usersEmpty')}>
        {page?.items.map((identity) => <TableRow key={JSON.stringify([identity.issuer, identity.subject])}>
          <TableCell sx={{ maxWidth: 220 }}><bdi>{identity.issuer}</bdi><Typography component="div" variant="caption" color="text.secondary">{t(identity.provider_current ? 'admin:providerCurrent' : 'admin:providerUnavailable')}</Typography></TableCell>
          <TableCell sx={{ maxWidth: 180 }}><bdi>{identity.subject}</bdi></TableCell><TableCell><bdi>{identity.email || t('common:none')}</bdi></TableCell>
          <TableCell><StatusBadge label={t(identity.approval_status === 'approved' ? 'accessApproved' : identity.approval_status === 'revoked' ? 'accessRevoked' : 'accessNotApproved')} tone={identity.approval_status === 'approved' ? 'success' : 'neutral'} /></TableCell>
          <TableCell>{identity.user_id ? t(identity.user_active ? 'common:statusActive' : 'common:statusInactive') : t('accessNoUser')}</TableCell>
          <TableCell>{identity.roles.map((role) => t(`admin:${roleKeys[role] || role}`)).join(', ') || t('common:none')}</TableCell>
          <TableCell>{formatDate(identity.updated_at, language)}</TableCell>
          <TableCell sx={{ minWidth: 150 }}><Stack spacing={0.5}>
            <Button size="small" disabled={blocked || !identity.user_id} onClick={() => { setReason(''); setConfirmLoss(false); setConfirmation({ kind: 'approval', identity, status: identity.approval_status === 'approved' ? 'revoked' : 'approved', expected: { expected_policy_generation: page!.policy_generation, expected_activation_generation: page!.activation_generation } }) }}>{t(identity.approval_status === 'approved' ? 'accessRevoke' : 'accessApprove')}</Button>
            {policy?.mode === 'allow_all' && identity.approval_status === 'not_approved' && <Button size="small" disabled={blocked || !identity.user_id} onClick={() => { setReason(''); setConfirmLoss(false); setConfirmation({ kind: 'approval', identity, status: 'revoked', expected: { expected_policy_generation: page!.policy_generation, expected_activation_generation: page!.activation_generation } }) }}>{t('accessRevoke')}</Button>}
            <Button size="small" disabled={busy || !identity.user_id} onClick={() => void run(async () => { try { setDetail(await readAccessIdentity(identity.user_id)) } catch (failure) { report(failure, false) } })}>{t('accessDetails')}</Button>
          </Stack></TableCell>
        </TableRow>)}
      </CompactTable>
      <Stack direction="row" spacing={1} sx={{ mt: 2 }}><Button disabled={loading || offset === 0} onClick={() => { setLoading(true); setOffset(Math.max(0, offset - 20)) }}>{t('common:previousPage')}</Button><Button disabled={loading || !page || offset + 20 >= page.total} onClick={() => { setLoading(true); setOffset(offset + 20) }}>{t('common:nextPage')}</Button></Stack>
      <Typography variant="caption" color="text.secondary">{t('accessProviderHelp')}</Typography>
    </SectionCard>
    </>}
    <Dialog open={Boolean(confirmation)} onClose={() => { if (!busy && !uncertain) setConfirmation(null) }} fullWidth maxWidth="sm" aria-labelledby="access-confirm-title">
      <DialogTitle id="access-confirm-title">{t('accessConfirm')}</DialogTitle>
      <DialogContent dividers><Stack spacing={2}>
        {error && <Alert severity="error">{t(error)}</Alert>}
        {confirmation?.kind === 'policy' ? <>
          <TwoColumnKeyValue items={[
            { label: t('accessWho'), value: t(confirmation.draft.settings.mode === 'allow_all' ? 'accessAllowAll' : 'accessApprovedOnly') },
            { label: t('accessDomains'), value: <bdi>{settingsOf(confirmation.draft).allowed_email_domains.join(', ') || t('accessNoDomains')}</bdi> },
            { label: t('accessDefaultRole'), value: t(`admin:${roleKeys[confirmation.draft.settings.default_role]}`) },
          ]} />
          <Typography>{t('accessImpact', { count: confirmation.preview.affected_users })}</Typography><Typography>{t('accessEligibleAdmin', { count: confirmation.preview.eligible_administrators })}</Typography>
          <Typography variant="body2">{t('accessPreviewHelp')}</Typography>
          {!confirmation.preview.can_apply && <Alert severity="error">{t('accessLastAdmin')}</Alert>}
        </> : confirmation && <><Typography>{t(confirmation.status === 'approved' ? 'accessApproveHelp' : 'accessRevokeHelp')}</Typography><TwoColumnKeyValue items={[{ label: t('accessIssuer'), value: <bdi>{confirmation.identity.issuer}</bdi> }, { label: t('accessSubject'), value: <bdi>{confirmation.identity.subject}</bdi> }]} /></>}
        {selfLoss && <FormControlLabel control={<Checkbox checked={confirmLoss} disabled={busy} onChange={(_, checked) => setConfirmLoss(checked)} />} label={t('accessSelfLoss')} />}
        <TextField autoFocus fullWidth required label={t('accessReason')} value={reason} onChange={(event) => setReason(event.target.value)} disabled={busy || uncertain} slotProps={{ htmlInput: { minLength: 8, maxLength: 512 } }} helperText={t('accessReasonHelp')} />
      </Stack></DialogContent>
      <DialogActions><Button disabled={busy} onClick={() => setConfirmation(null)}>{t('common:cancel')}</Button><Button variant="contained" disabled={busy || uncertain || error === 'auth:accessConflict' || !validReason(reason) || Boolean(selfLoss && !confirmLoss) || (confirmation?.kind === 'policy' && !confirmation.preview.can_apply)} onClick={() => void save()}>{t('admin:confirmPermissions')}</Button></DialogActions>
    </Dialog>
    <DetailDrawer open={Boolean(detail)} onClose={() => setDetail(null)} title={t('accessDetails')}>
      {detail && <TwoColumnKeyValue items={[
        { label: t('accessIssuer'), value: <bdi>{detail.issuer}</bdi> }, { label: t('accessSubject'), value: <bdi>{detail.subject}</bdi> },
        { label: t('email'), value: <bdi>{detail.email || t('common:none')}</bdi> },
        { label: t('admin:userRecordStatus'), value: t(detail.user_active ? 'common:statusActive' : 'common:statusInactive') },
        { label: t('accessFilter'), value: t(detail.approval_status === 'approved' ? 'accessApproved' : detail.approval_status === 'revoked' ? 'accessRevoked' : 'accessNotApproved') },
        { label: t('common:navRoles'), value: detail.roles.map((role) => t(`admin:${roleKeys[role] || role}`)).join(', ') || t('common:none') },
      ]} />}
    </DetailDrawer>
  </Stack>
}
