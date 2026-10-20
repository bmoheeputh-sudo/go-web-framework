import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { I18nextProvider } from 'react-i18next'
import LanguageProvider from '../LanguageProvider'
import NotificationProvider from '../notifications/NotificationProvider'
import { SessionContext } from '../auth/session'
import type { Session } from '../auth/session'
import { createI18n, resources } from '../i18n'
import { admin, identity, mockMedia } from '../test/fixtures'
import type { ActivationPreparation, ActivationResult, ActivationStatus, AuthRevision, ConnectionTest } from '../api/authConfiguration'
import ActivationWorkflow from './ActivationWorkflow'
import RecoveryDraftDialog from './RecoveryDraftDialog'

const en = resources.en.auth
const future = () => new Date(Date.now() + 300_000).toISOString()
const revision: AuthRevision = {
  id: 'revision-7', configuration_version: 7, generation: 3, status: 'approved', provider: 'oidc',
  issuer_url: 'https://issuer.example.test', client_id: 'client-id', redirect_uri: 'https://app.example.test/api/auth/callback',
  iap_audience: '', allow_http_development: false, deployment_id: 'deployment', environment: 'production',
  created_by: admin.id, created_at: '', updated_by: admin.id, updated_at: '', validation: {}, has_secret: true,
}
const isolated: ConnectionTest = {
  id: 'test-1', revision_id: revision.id, configuration_version: 7, generation: 3, status: 'succeeded',
  expires_at: future(), callback_uri: revision.redirect_uri, tested_identity: identity,
  evidence_id: 'isolated-evidence', evidence_expires_at: future(),
}
const status: ActivationStatus = {
  authoritative_source: 'environment', authoritative_generation: 0,
  local_source: 'environment', local_provider: 'local_dev', local_applied_generation: 0, local_desired_generation: 0,
  listener_connected: true, synchronization_degraded: false, reconciled: true, reconciliation_required: false,
  preparation_affinity_mode: 'single_instance', preparation_enabled: true, automatic_activation_retry: false,
}
const preparation = (normal = false): ActivationPreparation => ({
  preparation_id: 'instance.preparation', revision_id: revision.id, revision_generation: revision.generation,
  expected_activation_generation: 0, target_activation_generation: 1, expires_at: future(),
  current_provider: 'local_dev', current_source: 'environment', requires_reauthentication: true,
  maximum_transition_seconds: 0, warning: 'immediate_reauthentication_required', emergency_recovery_required: true,
  offline_recovery_procedure: 'auth-recovery-cli', normal_callback_status: normal ? 'succeeded' : 'not_started',
  ...(normal ? { normal_evidence_id: 'normal-evidence', normal_evidence_expires_at: future() } : {}),
})
const committed = (outcome: ActivationResult['outcome']): ActivationResult => ({
  outcome, commit_persisted: outcome === 'commit_uncertain' ? null : outcome !== 'not_committed',
  authoritative_state_known: outcome !== 'commit_uncertain', authoritative_generation: outcome === 'not_committed' ? 0 : 1,
  authoritative_revision_id: outcome === 'not_committed' ? undefined : revision.id, desired_generation: 1,
  applied_generation: outcome === 'committed_applied' ? 1 : 0, revision_id: revision.id,
  applied: outcome === 'committed_applied', commit_uncertain: outcome === 'commit_uncertain',
  reconciliation_required: outcome === 'committed_not_applied', automatic_retry_allowed: false,
})

type SetupOptions = {
  preparationEnabled?: boolean
  activation?: ActivationResult | 'network' | 'auth_loss'
  activationStatus?: number
  popupBlocked?: boolean
  wrongInstance?: boolean
  readinessPending?: boolean
}

beforeEach(() => { mockMedia(); vi.useFakeTimers(); localStorage.clear(); sessionStorage.clear() })
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

function setup(options: SetupOptions = {}) {
  let ready = false
  let activationSubmitted = false
  const popup = { closed: false, opener: window, location: { replace: vi.fn() }, close: vi.fn(() => { popup.closed = true }) }
  vi.spyOn(window, 'open').mockReturnValue(options.popupBlocked ? null : popup as unknown as Window)
  const fetcher = vi.fn(async (path: string, init?: RequestInit) => {
    if (path === '/api/admin/auth/activation/status') {
      const committedNotApplied = activationSubmitted && typeof options.activation === 'object' && options.activation.outcome === 'committed_not_applied'
      return Response.json(committedNotApplied ? {
        ...status, authoritative_source: 'database', authoritative_generation: 1, authoritative_revision_id: revision.id,
        local_desired_generation: 1, reconciled: false, reconciliation_required: true,
        preparation_enabled: options.preparationEnabled ?? true,
      } : { ...status, preparation_enabled: options.preparationEnabled ?? true })
    }
    if (path.endsWith('/activation/prepare')) return Response.json(preparation(), { status: 201 })
    if (path.endsWith('/readiness')) { ready = !options.readinessPending; return Response.json({ preparation_id: 'instance.preparation', status: 'pending', authorization_url: 'https://issuer.example.test/authorize?state=opaque', callback_url: revision.redirect_uri, expires_at: future() }, { status: 201 }) }
    if (path === '/api/admin/auth/activation-preparations/instance.preparation' && init?.method === 'GET') {
      if (options.wrongInstance) return Response.json({ error: 'activation_preparation_wrong_instance' }, { status: 404 })
      return Response.json(preparation(ready))
    }
    if (path.endsWith('/activate')) {
      activationSubmitted = true
      if (options.activation === 'network') throw new TypeError('network disconnected')
      if (options.activation === 'auth_loss') return Response.json({ error: 'unauthenticated' }, { status: 401 })
      const result = options.activation || committed('committed_applied')
      return Response.json(options.activationStatus ? { error: 'auth_activation_runtime_mismatch', ...result } : result, { status: options.activationStatus || 200 })
    }
    if (path === '/api/admin/auth/activation/reconcile') return Response.json({ ...status, authoritative_source: 'database', authoritative_generation: 1, authoritative_revision_id: revision.id, local_source: 'database', local_provider: 'oidc', local_applied_generation: 1, local_desired_generation: 1, local_revision_id: revision.id, reconciled: true, reconciliation_required: false })
    if (path.endsWith('/recovery-readiness')) return Response.json({ revision_id: revision.id, source_revision_id: '', status: 'approved', configuration_pre_staged: true, enrolled_administrator_ready: true, fresh_isolated_evidence: true, fresh_normal_callback_evidence: true, ready_for_portal_activation: true, live_provider_required: true, offline_recovery_procedure: 'auth-recovery-cli' })
    throw new Error(`unexpected endpoint ${path}`)
  })
  vi.stubGlobal('fetch', fetcher)
  const session: Session = {
    authentication: { status: 'authenticated', identity }, access: { loading: false, user: admin, error: '' },
    health: 'ok', oidcEnabled: false, loggingOut: false, logoutFailed: false, loginFailed: false,
    logout: vi.fn(), expire: vi.fn(), refreshAccess: vi.fn(),
  }
  const instance = createI18n('en')
  const view = render(<I18nextProvider i18n={instance}><LanguageProvider><NotificationProvider><SessionContext.Provider value={session}>
    <ActivationWorkflow revision={revision} isolatedTest={isolated} enrolledUser={admin} disabled={false} onResolvedUser={vi.fn()} />
  </SessionContext.Provider></NotificationProvider></LanguageProvider></I18nextProvider>)
  return { ...view, fetcher, popup, session, instance }
}

async function tick(ms = 0) { await act(async () => { await vi.advanceTimersByTimeAsync(ms) }) }
async function prepareAndVerify() {
  await tick()
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.activationPrepare })) })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.activationRunNormalTest })) })
  await tick(1000)
}

describe('OIDC activation state machine', () => {
  it('prepares and verifies both evidence paths without activating', async () => {
    const { fetcher, popup } = setup()
    await prepareAndVerify()
    expect(popup.opener).toBeNull()
    expect(popup.location.replace).toHaveBeenCalledWith(expect.stringMatching(/^https:\/\/issuer\.example\.test\/authorize/))
    expect(document.body.textContent).toContain(`${en.activationNormalEvidence}: ${en.activationEvidenceReady}`)
    expect(fetcher.mock.calls.some(([path]) => String(path).endsWith('/activate'))).toBe(false)
  })

  it('requires both first-cutover acknowledgements and submits every required field once with zero transition', async () => {
    const { fetcher } = setup()
    const localWrite = vi.spyOn(Storage.prototype, 'setItem')
    await prepareAndVerify()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.activationReview })) })
    const dialog = screen.getByRole('dialog')
    const activate = within(dialog).getByRole('button', { name: en.activationConfirmAction }) as HTMLButtonElement
    expect(activate.disabled).toBe(true)
    expect(within(dialog).getAllByRole('checkbox').every((item) => !(item as HTMLInputElement).checked)).toBe(true)
    fireEvent.change(within(dialog).getByLabelText(new RegExp(en.activationReason)), { target: { value: 'Approved security cutover' } })
    for (const checkbox of within(dialog).getAllByRole('checkbox')) fireEvent.click(checkbox)
    expect(activate.disabled).toBe(false)
    await act(async () => { fireEvent.click(activate); fireEvent.click(activate) })
    const calls = fetcher.mock.calls.filter(([path]) => String(path).endsWith('/activate'))
    expect(calls).toHaveLength(1)
    expect(JSON.parse(calls[0][1]!.body as string)).toEqual({
      revision_id: revision.id, expected_revision_generation: 3, expected_activation_generation: 0,
      isolated_evidence_id: 'isolated-evidence', normal_evidence_id: 'normal-evidence', enrolled_user_id: admin.id,
      transition_seconds: 0, acknowledge_reauthentication: true, acknowledge_emergency_recovery: true,
      confirm: true, reason: 'Approved security cutover',
    })
    expect(screen.getByText(en.activationOutcome_committed_applied)).toBeTruthy()
    expect(localWrite).not.toHaveBeenCalled()
  })

  it('preserves structured committed-not-applied responses and reconciles without resubmitting activation', async () => {
    const { fetcher } = setup({ activation: committed('committed_not_applied'), activationStatus: 503 })
    await prepareAndVerify(); await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.activationReview })) })
    const dialog = screen.getByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText(new RegExp(en.activationReason)), { target: { value: 'Approved security cutover' } })
    for (const checkbox of within(dialog).getAllByRole('checkbox')) fireEvent.click(checkbox)
    await act(async () => { fireEvent.click(within(dialog).getByRole('button', { name: en.activationConfirmAction })) })
    expect(screen.getByText(en.activationOutcome_committed_not_applied)).toBeTruthy()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.activationRefreshStatus })) })
    const reconcileButton = screen.getByRole('button', { name: en.activationReconcile }) as HTMLButtonElement
    expect(reconcileButton.disabled).toBe(false)
    await act(async () => { fireEvent.click(reconcileButton) })
    const reconcile = fetcher.mock.calls.find(([path]) => path === '/api/admin/auth/activation/reconcile')!
    expect(JSON.parse(reconcile[1]!.body as string)).toEqual({ expected_desired_generation: 1, confirm: true })
    expect(fetcher.mock.calls.filter(([path]) => String(path).endsWith('/activate'))).toHaveLength(1)
  })

  it('treats a lost activation response as unknown and never retries or converts an unavailable inspection to failure', async () => {
    const { fetcher } = setup({ activation: 'network' })
    await prepareAndVerify(); await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.activationReview })) })
    const dialog = screen.getByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText(new RegExp(en.activationReason)), { target: { value: 'Approved security cutover' } })
    for (const checkbox of within(dialog).getAllByRole('checkbox')) fireEvent.click(checkbox)
    await act(async () => { fireEvent.click(within(dialog).getByRole('button', { name: en.activationConfirmAction })) })
    expect(screen.getByText(en.activationOutcome_outcome_unknown)).toBeTruthy()
    fetcher.mockImplementation(async (path: string) => path === '/api/admin/auth/activation/status' ? Response.json({ error: 'unavailable' }, { status: 503 }) : Promise.reject(new Error('unexpected')))
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.activationInspectStatus })) })
    expect(screen.getByText(en.activationOutcome_outcome_unknown)).toBeTruthy()
    await tick(60_000)
    expect(fetcher.mock.calls.filter(([path]) => String(path).endsWith('/activate'))).toHaveLength(1)
  })

  it('keeps an uncertain commit ambiguous and treats immediate authentication loss as an unknown outcome', async () => {
    const uncertain = setup({ activation: committed('commit_uncertain'), activationStatus: 503 })
    await prepareAndVerify(); await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.activationReview })) })
    let dialog = screen.getByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText(new RegExp(en.activationReason)), { target: { value: 'Approved security cutover' } })
    for (const checkbox of within(dialog).getAllByRole('checkbox')) fireEvent.click(checkbox)
    await act(async () => { fireEvent.click(within(dialog).getByRole('button', { name: en.activationConfirmAction })) })
    expect(screen.getByText(en.activationOutcome_commit_uncertain)).toBeTruthy()
    expect(screen.queryByText(en.activationOutcome_committed_applied)).toBeNull()
    expect(uncertain.fetcher.mock.calls.filter(([path]) => String(path).endsWith('/activate'))).toHaveLength(1)
    uncertain.unmount(); cleanup()

    const lostSession = setup({ activation: 'auth_loss' })
    await prepareAndVerify(); await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.activationReview })) })
    dialog = screen.getByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText(new RegExp(en.activationReason)), { target: { value: 'Approved security cutover' } })
    for (const checkbox of within(dialog).getAllByRole('checkbox')) fireEvent.click(checkbox)
    await act(async () => { fireEvent.click(within(dialog).getByRole('button', { name: en.activationConfirmAction })) })
    expect(screen.getByText(en.activationOutcome_outcome_unknown)).toBeTruthy()
    expect(lostSession.session.expire).toHaveBeenCalledOnce()
  })

  it('fails closed on cross-instance preparation routing and does not retry or consume evidence', async () => {
    const { fetcher } = setup({ wrongInstance: true })
    await tick(); await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.activationPrepare })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.activationRunNormalTest })) })
    await tick(1000)
    expect(screen.getByText(en.activationBlocked_wrong_instance)).toBeTruthy()
    const calls = fetcher.mock.calls.length
    await tick(20_000)
    expect(fetcher).toHaveBeenCalledTimes(calls)
    expect(fetcher.mock.calls.some(([path]) => String(path).endsWith('/activate'))).toBe(false)
  })

  it('handles a closed readiness popup and requires a fresh preparation', async () => {
    const { fetcher, popup } = setup({ readinessPending: true })
    await tick(); await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.activationPrepare })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.activationRunNormalTest })) })
    popup.closed = true
    await tick(1000)
    expect(screen.getByText(en.activationBlocked_popup_closed)).toBeTruthy()
    expect(fetcher.mock.calls.some(([path]) => String(path).endsWith('/activate'))).toBe(false)
  })

  it('blocks preparation when affinity is disabled and handles a blocked popup without consuming readiness', async () => {
    const disabled = setup({ preparationEnabled: false }); await tick()
    expect(screen.getByText(en.activationAffinityUnavailable)).toBeTruthy()
    expect((screen.getByRole('button', { name: en.activationPrepare }) as HTMLButtonElement).disabled).toBe(true)
    disabled.unmount(); cleanup()
    const blocked = setup({ popupBlocked: true }); await tick()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.activationPrepare })) })
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.activationRunNormalTest })) })
    expect(blocked.fetcher.mock.calls.some(([path]) => String(path).endsWith('/readiness'))).toBe(false)
    expect(screen.getByText(en.testPopupBlocked)).toBeTruthy()
  })

  it('keeps important results accessible and retains RTL direction', async () => {
    const { instance } = setup(); await tick()
    await act(async () => { await instance.changeLanguage('ar') })
    expect(document.documentElement.dir).toBe('rtl')
    expect(screen.getByRole('region', { name: resources.ar.auth.activationStatusTitle })).toBeTruthy()
  })
})

it('creates an immutable recovery draft with explicit confirmation data', async () => {
  const fetcher = vi.fn(async () => Response.json({ revision: { ...revision, id: 'recovery-8', configuration_version: 8, status: 'draft' }, activation_required: true }, { status: 201 }))
  vi.stubGlobal('fetch', fetcher)
  const session: Session = { authentication: { status: 'authenticated', identity }, access: { loading: false, user: admin, error: '' }, health: 'ok', oidcEnabled: false, loggingOut: false, logoutFailed: false, loginFailed: false, logout: vi.fn(), expire: vi.fn(), refreshAccess: vi.fn() }
  const created = vi.fn()
  render(<I18nextProvider i18n={createI18n('en')}><LanguageProvider><NotificationProvider><SessionContext.Provider value={session}>
    <RecoveryDraftDialog revision={{ ...revision, status: 'superseded' }} latestVersion={7} open onClose={vi.fn()} onCreated={created} />
  </SessionContext.Provider></NotificationProvider></LanguageProvider></I18nextProvider>)
  fireEvent.change(screen.getByLabelText(new RegExp(en.activationReason)), { target: { value: 'Restore trusted provider' } })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.recoveryCreateAction })) })
  const calls = fetcher.mock.calls as unknown as [string, RequestInit][]
  expect(JSON.parse(calls[0][1].body as string)).toEqual({ expected_latest_version: 7, confirm: true, reason: 'Restore trusted provider' })
  expect(created).toHaveBeenCalledWith(expect.objectContaining({ id: 'recovery-8', status: 'draft' }))
})
