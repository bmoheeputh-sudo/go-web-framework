import { useEffect, useRef, useState } from 'react'
import { Alert, Box, Button, Checkbox, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, LinearProgress, Stack, Step, StepLabel, Stepper, TableCell, TableRow, TextField, Typography } from '@mui/material'
import { useBeforeUnload, useSearchParams } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { AuthConfigurationError } from '../api/authConfiguration'
import { accessPolicyPath, importInvitationCSV, previewInvitationCSV, readImportReceipt } from '../api/accessPolicy'
import type { CSVImportInput, CSVPreview, ImportReceipt, InvitationExpectation } from '../api/accessPolicy'
import type { QueryCache } from '../api/cache'
import { useQueryCache } from '../api/queries'
import { useSession } from '../auth/session'
import CompactTable from '../components/CompactTable'
import StatusBadge from '../components/common/StatusBadge'
import TechnicalValue from '../components/common/TechnicalValue'
import TwoColumnKeyValue from '../components/common/TwoColumnKeyValue'
import { typographyRoles } from '../design/theme'
import { formatDate, formatNumber } from '../i18n'
import { useNotifications } from '../notifications/notifications'

const maxBytes = 1024 * 1024
const receiptParameter = 'invitation_import'
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu
const steps = ['csvUpload', 'csvPreview', 'csvConfirm', 'csvResult'] as const
const validReason = (value: string) => [...value.trim()].length >= 8 && new TextEncoder().encode(value).length <= 512 && [...value].every((char) => { const code = char.codePointAt(0)!; return code >= 32 && (code < 127 || code > 159) })
type State = {
  open: boolean; step: number; csv: string; filename: string; size: number; days: string; reason: string; acknowledged: boolean
  preview: CSVPreview | null; selected: number[]; receipt: ImportReceipt | null; attempt: string; error: string
  busy: boolean; writing: boolean; uncertain: boolean; discard: boolean
}
const initial = (id = ''): State => ({ open: Boolean(id), step: id ? 3 : 0, csv: '', filename: '', size: 0, days: '7', reason: '', acknowledged: false, preview: null, selected: [], receipt: null, attempt: id, error: '', busy: Boolean(id), writing: false, uncertain: Boolean(id), discard: false })
// One bounded in-memory draft per signed-in cache, never browser storage. Only
// the non-secret receipt UUID goes into SPA history for interrupted-session recovery.
const drafts = new WeakMap<QueryCache, State>()
const expectations = (preview: CSVPreview): InvitationExpectation => ({ expected_policy_generation: preview.expected_policy_generation, expected_activation_generation: preview.expected_activation_generation, revision_id: preview.revision_id, expected_revision_generation: preview.expected_revision_generation })
function readFile(file: File): Promise<ArrayBuffer> {
  if (typeof file.arrayBuffer === 'function') return file.arrayBuffer()
  return new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(reader.result as ArrayBuffer); reader.onerror = () => reject(new Error('file read failed')); reader.readAsArrayBuffer(file) })
}

export default function CSVInvitationImport({ expected, disabled, mode, onImported }: {
  expected: InvitationExpectation | null; disabled: boolean; mode?: 'allow_all' | 'approved_users_only'; onImported: (id: string) => void
}) {
  const { t, i18n } = useTranslation(['auth', 'common'])
  const cache = useQueryCache(), notify = useNotifications(), { expire, refreshAccess } = useSession()
  const [params, setParams] = useSearchParams()
  const receiptID = params.get(receiptParameter) || ''
  const [state, setState] = useState<State>(() => { const draft = drafts.get(cache); return uuid.test(receiptID) && draft?.attempt !== receiptID ? initial(receiptID) : draft || initial() })
  const mounted = useRef(true), inFlight = useRef(false), ownAttempt = useRef('')
  const reading = useRef<AbortController | null>(null)
  const patch = (value: Partial<State>) => setState((current) => ({ ...current, ...value }))
  const dirty = state.csv !== '' && !state.receipt
  useBeforeUnload((event) => { if (dirty || state.writing) { event.preventDefault(); event.returnValue = '' } })
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; reading.current?.abort() } }, [])
  useEffect(() => {
    if (state.csv || state.attempt) drafts.set(cache, { ...state, step: state.writing ? 3 : state.step, writing: false, busy: false, uncertain: state.uncertain || state.writing })
    else drafts.delete(cache)
  }, [cache, state])
  useEffect(() => {
    if (!uuid.test(receiptID) || ownAttempt.current === receiptID) return
    const controller = new AbortController()
    void readImportReceipt(receiptID, controller.signal).then((receipt) => {
      if (!controller.signal.aborted) setState((current) => ({ ...current, open: true, step: 3, busy: false, writing: false, uncertain: false, attempt: receiptID, receipt, csv: '', error: '' }))
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return
      if (failure instanceof AuthConfigurationError && failure.status === 401) expire()
      if (failure instanceof AuthConfigurationError && failure.status === 403) refreshAccess()
      setState((current) => ({ ...current, open: true, step: 3, busy: false, writing: false, attempt: receiptID, uncertain: true, error: failure instanceof AuthConfigurationError && failure.status === 404 ? 'csvReceiptMissing' : failure instanceof AuthConfigurationError && [401, 403].includes(failure.status) ? 'common:accessDenied' : 'csvInspectHelp' }))
    })
    return () => controller.abort()
  }, [receiptID, expire, refreshAccess])
  const language = i18n.resolvedLanguage || 'en'
  const daysValid = Number.isInteger(Number(state.days)) && Number(state.days) >= 1 && Number(state.days) <= 30
  function clearReceiptParameter() { setParams((current) => { const next = new URLSearchParams(current); next.delete(receiptParameter); return next }, { replace: true, preventScrollReset: true }) }
  function report(failure: unknown, mutation: boolean) {
    const status = failure instanceof AuthConfigurationError ? failure.status : 0
    const code = failure instanceof AuthConfigurationError ? failure.code : ''
    const uncertain = mutation && (!status || status >= 500)
    const key = uncertain ? 'csvInspectHelp' : [401, 403].includes(status) ? 'common:accessDenied' : status === 409 ? 'csvConflict' : status === 413 || code === 'oidc_import_file_too_large' ? 'csvSizeError' : code === 'oidc_import_too_many_rows' ? 'csvRowsError' : code === 'oidc_import_empty' ? 'csvEmptyError' : status === 400 ? 'csvFormatError' : 'csvUnavailable'
    patch({ error: key, uncertain, ...(uncertain ? { step: 3 } : {}) })
    notify({ severity: uncertain ? 'warning' : 'error', messageKey: key.includes(':') ? key as `${string}:${string}` : `auth:${key}` })
    if (status === 401) expire()
    if (status === 403) refreshAccess()
    if (mutation && !uncertain) { clearReceiptParameter(); ownAttempt.current = ''; patch({ attempt: '', step: 1, preview: null, acknowledged: false }) }
  }
  async function fileSelected(file?: File) {
    if (!file || state.busy || state.uncertain || inFlight.current) return
    if (file.size > maxBytes) { patch({ error: 'csvSizeError' }); return }
    inFlight.current = true; patch({ busy: true, error: '' })
    try {
      const buffer = await readFile(file)
      if (buffer.byteLength > maxBytes) throw new Error('file too large')
      const csv = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buffer)
      if (mounted.current) patch({ csv, filename: file.name, size: file.size, preview: null, selected: [], error: csv ? '' : 'csvEmptyError', step: 0 })
    } catch { if (mounted.current) patch({ error: 'csvFormatError' }) }
    finally { inFlight.current = false; if (mounted.current) patch({ busy: false }) }
  }
  async function preview(confirm = false) {
    const binding = state.preview ? expectations(state.preview) : expected
    if (!binding || !state.csv || !daysValid || (state.step === 0 && ['csvSizeError', 'csvFormatError', 'csvEmptyError'].includes(state.error)) || state.busy || state.uncertain || inFlight.current || (confirm && !state.selected.length)) return
    const controller = new AbortController(); reading.current = controller
    inFlight.current = true; patch({ busy: true, error: '' })
    try {
      const result = await previewInvitationCSV({ ...binding, csv: state.csv, expiration_days: Number(state.days), ...(confirm ? { selected_rows: state.selected } : {}) }, controller.signal)
      if (mounted.current) patch({ preview: result, selected: result.selected_rows, step: confirm && result.will_create > 0 && result.preview_digest ? 2 : 1, acknowledged: false })
    } catch (failure) { if (mounted.current && !controller.signal.aborted) report(failure, false) }
    finally { inFlight.current = false; if (mounted.current) patch({ busy: false }) }
  }
  async function confirmImport() {
    if (!state.preview || !state.selected.length || !state.acknowledged || !validReason(state.reason) || state.busy || state.uncertain || disabled || inFlight.current) return
    if (Date.parse(state.preview.preview_expires_at) <= Date.now()) { patch({ error: 'csvConflict', step: 1, acknowledged: false }); return }
    let request: CSVImportInput
    try {
      request = { ...expectations(state.preview), csv: state.csv, selected_rows: state.preview.selected_rows, expiration_days: state.preview.expiration_days, preview_digest: state.preview.preview_digest, preview_expires_at: state.preview.preview_expires_at, import_id: crypto.randomUUID(), idempotency_key: crypto.randomUUID(), reason: state.reason, confirm: true }
    } catch { patch({ error: 'csvUnavailable' }); return }
    inFlight.current = true; ownAttempt.current = request.import_id
    patch({ busy: true, writing: true, attempt: request.import_id, error: '' })
    setParams((current) => { const next = new URLSearchParams(current); next.set(receiptParameter, request.import_id); return next }, { replace: true, preventScrollReset: true })
    try {
      const receipt = await importInvitationCSV(request)
      cache.invalidate([accessPolicyPath, '/api/admin/audit'])
      if (mounted.current) { patch({ receipt, csv: '', step: 3, uncertain: false }); notify({ severity: 'success', messageKey: 'auth:csvImported' }) }
    } catch (failure) { if (mounted.current) report(failure, true) }
    finally { inFlight.current = false; if (mounted.current) patch({ busy: false, writing: false }) }
  }
  async function inspect() {
    if (!state.attempt || state.busy || inFlight.current) return
    inFlight.current = true; patch({ busy: true, error: '' })
    try { const receipt = await readImportReceipt(state.attempt); if (mounted.current) { patch({ receipt, csv: '', step: 3, uncertain: false }); cache.invalidate([accessPolicyPath, '/api/admin/audit']) } }
    catch (failure) {
      if (!mounted.current) return
      if (failure instanceof AuthConfigurationError && failure.status === 401) expire()
      if (failure instanceof AuthConfigurationError && failure.status === 403) refreshAccess()
      patch({ uncertain: true, error: failure instanceof AuthConfigurationError && failure.status === 404 ? 'csvReceiptMissing' : failure instanceof AuthConfigurationError && [401, 403].includes(failure.status) ? 'common:accessDenied' : 'csvInspectHelp' })
    } finally { inFlight.current = false; if (mounted.current) patch({ busy: false }) }
  }
  function close() {
    if (state.busy) return
    if (dirty && !state.uncertain) patch({ discard: true })
    else patch({ open: false })
  }
  function reset() { clearReceiptParameter(); ownAttempt.current = ''; setState(initial()) }
  const selected = new Set(state.selected)
  const ready = state.preview?.rows.filter((row) => row.status === 'ready') || []
  const heading = state.step === 3 ? 'csvResult' : 'csvTitle'
  return <>
    <Button variant="outlined" disabled={state.busy || (!state.attempt && disabled)} onClick={() => patch({ open: true, discard: false })}>{t(state.attempt ? state.receipt ? 'csvResult' : 'csvInspect' : 'csvImportButton')}</Button>
    {state.uncertain && !state.open && <Alert severity="warning">{t('csvInspectHelp')}</Alert>}
    <Dialog open={state.open} onClose={close} fullWidth maxWidth="md" aria-labelledby="csv-import-title">
      <DialogTitle id="csv-import-title">{t(heading)}</DialogTitle>
      <DialogContent dividers><Stack spacing={2}>
        <Stepper activeStep={state.step} alternativeLabel>{steps.map((step) => <Step key={step}><StepLabel>{t(step)}</StepLabel></Step>)}</Stepper>
        {state.busy && <LinearProgress aria-label={t('common:loading')} />}
        {state.error && <Alert severity={state.uncertain ? 'warning' : 'error'}>{t(state.error)}</Alert>}
        {state.discard && <Alert severity="warning">{t('invitationDiscardHelp')}</Alert>}
        {state.step === 0 && <Stack spacing={2}>
          <Typography variant={typographyRoles.supportingText}>{t('csvUploadHelp')}</Typography>
          <Button component="label" variant="outlined" disabled={state.busy || state.uncertain}>{t('csvChooseFile')}<input type="file" accept=".csv,text/csv" aria-label={t('csvChooseFile')} hidden disabled={state.busy || state.uncertain} onChange={(event) => { void fileSelected(event.target.files?.[0]); event.target.value = '' }} /></Button>
          {state.filename && <TwoColumnKeyValue items={[{ label: t('csvFilename'), value: <bdi>{state.filename}</bdi> }, { label: t('csvFileSize'), value: t('csvBytes', { value: formatNumber(state.size, language) }) }, { label: t('csvTotal'), value: state.preview ? formatNumber(state.preview.total_rows, language) : t('csvCountAfterPreview') }]} />}
          <TextField required type="number" label={t('invitationExpiration')} value={state.days} disabled={state.busy || state.uncertain} helperText={t('invitationExpirationHelp')} slotProps={{ htmlInput: { min: 1, max: 30, step: 1 } }} onChange={(event) => patch({ days: event.target.value, preview: null, selected: [] })} />
          <Alert severity="info">{t('invitationNoEmail')}</Alert>
        </Stack>}
        {state.step === 1 && <>
          {state.preview && <>
            <TwoColumnKeyValue items={[[t('csvTotal'), state.preview.total_rows], [t('csvReady'), state.preview.ready_rows], [t('csvSkipped'), state.preview.total_rows - state.preview.invalid_rows - state.selected.length], [t('csvInvalid'), state.preview.invalid_rows], [t('csvWillCreate'), state.selected.length]].map(([label, value]) => ({ label: String(label), value: formatNumber(Number(value), language) }))} />
            <Typography variant={typographyRoles.supportingText}>{t('csvSelectionHelp')}</Typography>
            <FormControlLabel label={t('csvSelectReady')} control={<Checkbox checked={ready.length > 0 && selected.size === ready.length} indeterminate={selected.size > 0 && selected.size < ready.length} disabled={state.busy || !ready.length} onChange={(_, checked) => patch({ selected: checked ? ready.map((row) => row.row) : [] })} />} />
            <Box sx={{ maxHeight: 360, overflowY: 'auto' }}><CompactTable label={t('csvPreviewRows')} headers={[t('csvSelect'), t('csvRow'), t('invitationEmployee'), t('csvRowResult')]} minWidth={560} empty={!state.preview.rows.length} emptyMessage={t('csvEmptyError')}>
              {state.preview.rows.map((row) => <TableRow key={row.row}>
                <TableCell padding="checkbox"><Checkbox checked={selected.has(row.row)} disabled={state.busy || row.status !== 'ready'} slotProps={{ input: { 'aria-label': t('csvSelectRow', { row: formatNumber(row.row, language), email: row.email }) } }} onChange={(_, checked) => patch({ selected: checked ? [...state.selected, row.row].sort((a, b) => a - b) : state.selected.filter((value) => value !== row.row) })} /></TableCell>
                <TableCell>{formatNumber(row.row, language)}</TableCell><TableCell sx={{ maxWidth: 260 }}><Typography variant={typographyRoles.primaryValue} noWrap title={row.display_name || row.email}><bdi>{row.display_name || row.email}</bdi></Typography>{row.display_name && <Typography variant={typographyRoles.supportingText} color="text.secondary" noWrap title={row.email}><bdi>{row.email}</bdi></Typography>}</TableCell>
                <TableCell><Typography variant={typographyRoles.supportingText}>{t(`csvStatus_${row.status}`)}</Typography></TableCell>
              </TableRow>)}
            </CompactTable></Box>
          </>}
          <Button disabled={state.busy || !state.csv} onClick={() => void preview()}>{t('csvRefreshPreview')}</Button>
        </>}
        {state.step === 2 && state.preview && <Box component="form" id="csv-confirm-form" onSubmit={(event) => { event.preventDefault(); void confirmImport() }}><Stack spacing={2}>
          <TwoColumnKeyValue items={[{ label: t('csvWillCreate'), value: formatNumber(state.preview.will_create, language) }, { label: t('invitationExpiration'), value: formatNumber(state.preview.expiration_days, language) }, { label: t('csvPreviewExpires'), value: formatDate(state.preview.preview_expires_at, language) }]} />
          <Alert severity="info">{t(mode === 'approved_users_only' ? 'invitationApprovedOnly' : 'invitationAllowAll')}</Alert>
          <Typography variant={typographyRoles.supportingText}>{t('invitationNoEmail')}</Typography>
          <TextField required autoFocus fullWidth label={t('accessReason')} value={state.reason} disabled={state.busy} helperText={t('csvReasonHelp')} slotProps={{ htmlInput: { maxLength: 512 } }} onChange={(event) => patch({ reason: event.target.value })} />
          <FormControlLabel label={t('csvConfirmAck')} control={<Checkbox checked={state.acknowledged} disabled={state.busy} onChange={(_, checked) => patch({ acknowledged: checked })} />} />
        </Stack></Box>}
        {state.step === 3 && <>
          {state.receipt ? <>
            <StatusBadge label={t('csvCompleted')} tone="success" />
            <TwoColumnKeyValue items={[{ label: t('csvReceiptID'), value: <TechnicalValue label={t('csvReceiptID')} value={state.receipt.id} /> }, { label: t('csvCreated'), value: formatNumber(state.receipt.created_count, language) }, { label: t('csvSkipped'), value: formatNumber(state.receipt.skipped_count, language) }, { label: t('csvInvalid'), value: formatNumber(state.receipt.rejected_count, language) }, { label: t('csvCompletedAt'), value: formatDate(state.receipt.completed_at, language) }]} />
            <Typography variant={typographyRoles.supportingText}>{t('csvReceiptHelp')}</Typography>
          </> : <><Alert severity="warning">{t('csvInspectHelp')}</Alert>{state.attempt && <TechnicalValue label={t('csvReceiptID')} value={state.attempt} />}</>}
        </>}
      </Stack></DialogContent>
      <DialogActions sx={{ flexWrap: 'wrap', gap: 1 }}>
        {state.discard ? <><Button onClick={() => patch({ discard: false })}>{t('invitationKeepEditing')}</Button><Button color="error" onClick={reset}>{t('invitationDiscard')}</Button></> : <>
          <Button disabled={state.busy} onClick={close}>{t(state.step === 3 ? 'common:close' : 'common:cancel')}</Button>
          {state.step > 0 && state.step < 3 && <Button disabled={state.busy} onClick={() => patch({ step: state.step - 1, error: '', acknowledged: false })}>{t('csvBack')}</Button>}
          {state.step === 0 && <Button variant="contained" disabled={state.busy || !state.csv || !daysValid || disabled || ['csvSizeError', 'csvFormatError', 'csvEmptyError'].includes(state.error)} onClick={() => void preview()}>{t('csvPreview')}</Button>}
          {state.step === 1 && <Button variant="contained" disabled={state.busy || !state.selected.length || disabled || !state.preview?.preview_digest} onClick={() => void preview(true)}>{t('csvReviewImport')}</Button>}
          {state.step === 2 && <Button variant="contained" type="submit" form="csv-confirm-form" disabled={state.busy || disabled || !state.acknowledged || !validReason(state.reason)}>{t('csvConfirmImport')}</Button>}
          {state.step === 3 && !state.receipt && <Button variant="contained" disabled={state.busy} onClick={() => void inspect()}>{t('csvInspect')}</Button>}
          {state.step === 3 && state.receipt && <><Button onClick={reset}>{t('csvNewImport')}</Button><Button variant="contained" onClick={() => { const id = state.receipt!.id; reset(); onImported(id) }}>{t('csvViewInvitations')}</Button></>}
        </>}
      </DialogActions>
    </Dialog>
  </>
}
