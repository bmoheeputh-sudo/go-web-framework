import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { I18nextProvider } from 'react-i18next'
import { MemoryRouter } from 'react-router-dom'
import { createI18n, resources } from '../i18n'
import type { Language } from '../i18n'
import LanguageProvider from '../LanguageProvider'
import NotificationProvider from '../notifications/NotificationProvider'
import QueryProvider from '../api/QueryProvider'
import { SessionContext } from '../auth/session'
import type { Session } from '../auth/session'
import { admin, bob, identity, mockMedia } from '../test/fixtures'
import type { HistoryItem, NotificationPreviewInput, NotificationEnqueueInput, OnboardingTarget } from '../api/notificationManagement'
import NotificationSettings from './NotificationSettings'

const en = resources.en.admin
const uuid = (n: number) => `${n.toString(16).padStart(8, '0')}-1111-4111-8111-111111111111`
const connectorID = uuid(1000), jobID = uuid(2000), originalRequestID = uuid(3000)
type Options = { view?: string; user?: typeof admin; language?: Language; enqueueStatus?: number; malformed?: boolean; missingReceipt?: boolean; expired?: boolean; ready?: boolean; skip?: boolean; receipt?: boolean; needsInspection?: boolean; suppressStatus?: number; cancelStatus?: number; recipientCode?: string; total?: number; connectorTotal?: number; historyEmpty?: boolean; communication?: boolean; accessMode?: string }
function setup(options: Options = {}) {
  let queuedInput: NotificationEnqueueInput | null = null
  let cancelled = false
  let suppression = { target: `user:${uuid(1)}`, active: false, generation: 0, reason: '' }
  const row = (n: number, category = 'pending'): OnboardingTarget => ({ target: `${category === 'pending' ? 'invitation' : 'user'}:${uuid(n)}`, email: `employee${n}@vopak.com`, display_name: `Employee ${n}`, category: category as OnboardingTarget['category'], code: n === 1 ? options.recipientCode || '' : '', claim_evidence: category === 'onboarded' && n === 1, ...(category === 'onboarded' && n === 2 ? { first_successful_oidc_login_at: '2026-01-01T00:00:00Z', last_successful_oidc_login_at: '2026-01-02T00:00:00Z' } : {}) })
  const historyItem = (): HistoryItem => ({ id: jobID, request_id: queuedInput?.input.request_id || originalRequestID, target: 'invitation:' + uuid(1), recipient: 'employee1@vopak.com', display_name: 'Employee 1', type: 'invitation', connector_id: connectorID, provider: 'ses', sender: 'onboarding@vopak.com', actor_id: uuid(400), actor_name: admin.display_name, status: options.needsInspection ? 'needs_inspection' : cancelled ? 'cancelled' : 'queued', attempt_outcome: options.needsInspection ? 'uncertain' : '', disposition: options.needsInspection ? 'provider_uncertain' : '', created_at: '2026-01-01T00:00:00Z', generation: cancelled ? 2 : 1, attempt_count: options.needsInspection ? 1 : 0 })
  const historyPage = () => ({ items: options.historyEmpty ? [] : [historyItem()], total: options.historyEmpty ? 0 : 1, offset: 0, limit: 20, delivery_enabled: false })
  const receipt = (id: string) => ({ id, actor_id: uuid(400), type: queuedInput?.input.type || 'invitation', connector_id: connectorID, sender: 'onboarding@vopak.com', template_version: 'onboarding.v1', locale: 'en', reason: 'Reviewed employee onboarding', job_count: queuedInput?.selected_targets.length || 1, outcome: 'enqueued', created_at: '2026-01-01T00:00:00Z', jobs: { ...historyPage(), total: queuedInput?.selected_targets.length || 1 }, delivery_enabled: false })
  const fetcher = vi.fn(async (path: string, init?: RequestInit) => {
    const url = new URL(path, 'https://app.test')
    const method = init?.method || 'GET'
    if (url.pathname.endsWith('/email-connectors')) return Response.json({ items: [{ id: connectorID, provider: 'ses', sender: 'onboarding@vopak.com', region: 'eu-west-1', enabled: true, default: true, per_minute: 30, per_day: 1500, generation: 1, failure_count: 0, last_error: '', readiness: { status: options.ready === false ? 'configured' : 'ready', code: options.ready === false ? 'not_tested' : 'ready', quota_known: true, remaining_24_hours: 5000, max_per_second: 5 }, tested_at: new Date().toISOString(), expires_at: new Date(Date.now() + 60000).toISOString(), has_authorization: false }], total: options.connectorTotal || 1, offset: Number(url.searchParams.get('offset') || 0), limit: 20, gmail_authorization_available: false, gmail_callback_url: '', gmail_scopes: [] })
    if (url.pathname.endsWith('/onboarding')) {
      const category = url.searchParams.get('category') || 'pending', offset = Number(url.searchParams.get('offset') || 0)
      const rows = Array.from({ length: url.searchParams.get('import_id') ? 1 : options.total ?? 23 }, (_, index) => row(index + 1, category))
      return Response.json({ items: rows.slice(offset, offset + 20), counts: { pending: 23, onboarded: 2, unobserved: 3, inactive: 1 }, total: rows.length, offset, limit: 20, communication_configured: options.communication !== false, delivery_enabled: false, max_batch: 100, access_mode: options.accessMode || 'approved_users_only' })
    }
    if (url.pathname.endsWith('/preview')) {
      const input = JSON.parse(String(init?.body)) as NotificationPreviewInput
      const rows = [...input.targets].sort().map((target, index) => ({ target, email: `employee${index + 1}@vopak.com`, display_name: `Employee ${index + 1}`, code: options.skip && index === 0 ? 'suppressed' : '', subject: 'VGCA invitation', text: 'Hello <script>unsafe()</script>,\nSign in: https://app.test/api/auth/login' }))
      return Response.json({ input: { ...input, targets: [...input.targets].sort() }, expected: { expected_policy_generation: 1, expected_activation_generation: 1, revision_id: uuid(4000), expected_revision_generation: 1 }, connector_generation: 1, sender: 'onboarding@vopak.com', template_version: 'onboarding.v1', rows, selected_targets: rows.filter((r) => !r.code).map((r) => r.target), ready_count: rows.filter((r) => !r.code).length, skipped_count: rows.filter((r) => r.code).length, preview_digest: 'a'.repeat(64), preview_expires_at: new Date(Date.now() + (options.expired ? -1000 : 60000)).toISOString(), delivery_enabled: false })
    }
    if (url.pathname.endsWith('/enqueue')) {
      queuedInput = JSON.parse(String(init?.body))
      if (options.enqueueStatus) return Response.json({ error: 'PRIVATE PROVIDER DETAILS' }, { status: options.enqueueStatus })
      if (options.malformed) return Response.json({ success: true })
      return Response.json({ request_id: queuedInput!.input.request_id, job_count: queuedInput!.selected_targets.length, outcome: 'queued', delivery_enabled: false }, { status: 201 })
    }
    if (url.pathname.includes('/requests/')) return options.missingReceipt ? Response.json({ error: 'missing' }, { status: 404 }) : Response.json(receipt(url.pathname.split('/').at(-1)!))
    if (url.pathname.endsWith('/history')) return Response.json(historyPage())
    if (url.pathname.endsWith('/cancel')) {
      if (options.cancelStatus) return Response.json({ error: 'PRIVATE' }, { status: options.cancelStatus })
      cancelled = true; return Response.json({ id: jobID, outcome: 'cancelled' })
    }
    if (url.pathname.includes('/jobs/')) return Response.json({ item: historyItem(), attempts: options.needsInspection ? [{ number: 1, adapter: 'ses', outcome: 'uncertain', provider_message_id: '', code: 'provider_uncertain', started_at: '2026-01-01T00:00:00Z' }] : [], delivery_enabled: false })
    if (url.pathname.endsWith('/suppressions')) {
      if (method === 'GET') return Response.json({ ...suppression, target: url.searchParams.get('target') })
      if (options.suppressStatus) return Response.json({ error: 'PRIVATE' }, { status: options.suppressStatus })
      const input = JSON.parse(String(init?.body)); suppression = { ...input, generation: input.expected_generation + 1 }; return Response.json(suppression)
    }
    throw new Error('unexpected test endpoint')
  })
  vi.stubGlobal('fetch', fetcher)
  const instance = createI18n(options.language || 'en')
  const session: Session = { authentication: { status: 'authenticated', identity }, access: { loading: false, user: options.user || admin, error: '' }, health: 'ok', oidcEnabled: true, loggingOut: false, logoutFailed: false, loginFailed: false, logout: vi.fn(), expire: vi.fn(), refreshAccess: vi.fn() }
  const view = options.view || 'invitations'
  render(<I18nextProvider i18n={instance}><LanguageProvider><NotificationProvider><SessionContext.Provider value={session}><QueryProvider><MemoryRouter initialEntries={[`/settings?tab=notifications&notification_view=${view}${options.receipt ? '&notification_request=' + originalRequestID : ''}`]}><NotificationSettings /></MemoryRouter></QueryProvider></SessionContext.Provider></NotificationProvider></LanguageProvider></I18nextProvider>)
  return { fetcher, instance, session }
}
beforeEach(() => { mockMedia(); localStorage.clear(); sessionStorage.clear() })
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })
const posts = (f: ReturnType<typeof setup>['fetcher'], suffix: string) => f.mock.calls.filter(([path, init]) => path.endsWith(suffix) && init?.method === 'POST')
async function selectFirst() { await userEvent.click(await screen.findByRole('checkbox', { name: 'Select employee1@vopak.com' })) }
async function previewFirst() { await selectFirst(); await userEvent.click(screen.getByRole('button', { name: en.nmPreview })); await screen.findByText(en.nmTemplateLanguage) }
async function confirm() {
  await userEvent.click(screen.getByRole('button', { name: en.nmReviewQueue }))
  fireEvent.change(screen.getByLabelText(en.nmReason + ' *'), { target: { value: 'Reviewed employee onboarding' } })
  await userEvent.click(screen.getByRole('checkbox', { name: /I confirm queueing/ }))
}

it('provides all notification views and clearly disables real delivery', async () => {
  const { fetcher } = setup(); await selectFirst()
  for (const name of [en.emailConnectorsTitle, en.nmInvitations, en.nmReminders, en.nmHistory, en.nmOverview]) expect(screen.getByRole('tab', { name })).toBeTruthy()
  expect(screen.getByText(en.nmDeliveryDisabled)).toBeTruthy(); expect(screen.getByText(en.nmIndependentInvitations)).toBeTruthy()
  for (const tab of screen.getAllByRole('tab')) {
    const panel = document.getElementById(tab.getAttribute('aria-controls')!)!
    expect(panel).toBeTruthy(); expect(panel.hidden).toBe(tab.getAttribute('aria-selected') !== 'true')
  }
  expect(posts(fetcher, '/enqueue')).toHaveLength(0)
})
it('previews an individual email as text and queues only after explicit confirmation', async () => {
  const { fetcher } = setup(); await previewFirst()
  expect(screen.getByText(/Hello <script>/)).toBeTruthy(); expect(document.querySelector('script')).toBeNull()
  await userEvent.click(screen.getByRole('button', { name: en.nmReviewQueue }))
  expect((screen.getByRole('button', { name: en.nmQueue }) as HTMLButtonElement).disabled).toBe(true)
  fireEvent.change(screen.getByLabelText(en.nmReason + ' *'), { target: { value: 'Reviewed employee onboarding' } })
  await userEvent.click(screen.getByRole('checkbox', { name: /I confirm queueing/ })); await userEvent.click(screen.getByRole('button', { name: en.nmQueue }))
  await waitFor(() => expect(posts(fetcher, '/enqueue')).toHaveLength(1))
  const input = JSON.parse(String(posts(fetcher, '/enqueue')[0][1]?.body))
  expect(input).toMatchObject({ confirm: true, reason: 'Reviewed employee onboarding', connector_generation: 1, selected_targets: ['invitation:' + uuid(1)], input: { type: 'invitation', connector_id: connectorID, locale: 'en' } })
  expect(input).not.toHaveProperty('recipient'); expect(await screen.findByText('Queued: 1. No email has been sent.')).toBeTruthy()
  expect(fetcher.mock.calls.some(([path]) => /\/(send|simulate|retry)$/u.test(path))).toBe(false)
})
it('retains bulk selection across pages and reviews skipped recipients', async () => {
  const { fetcher } = setup({ skip: true }); await screen.findByText('employee1@vopak.com')
  await userEvent.click(screen.getByRole('button', { name: en.nmSelectPage }))
  await userEvent.click(screen.getAllByRole('button', { name: resources.en.common.nextPage })[0]); await screen.findByText('employee21@vopak.com')
  await userEvent.click(screen.getByRole('button', { name: en.nmSelectPage })); expect(screen.getByText('Selected: 23 of 100, across pages.')).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: en.nmPreview })); await screen.findByText('Ready: 22 · Skipped: 1')
  expect(screen.getByText(en.nmCode_suppressed)).toBeTruthy(); expect(posts(fetcher, '/preview')).toHaveLength(1)
})
it('filters pending invitations through an existing CSV import receipt', async () => {
  const { fetcher } = setup(); await screen.findByText('employee1@vopak.com')
  fireEvent.change(screen.getByLabelText(en.nmImportReceipt), { target: { value: uuid(9000) } }); await userEvent.click(screen.getByRole('button', { name: en.nmApplyFilters }))
  await waitFor(() => expect(fetcher.mock.calls.some(([path]) => path.includes('import_id=' + uuid(9000)))).toBe(true))
  await waitFor(() => expect(screen.queryByText('employee2@vopak.com')).toBeNull())
})
it('requires an enabled connector with current readiness', async () => {
  setup({ ready: false }); await selectFirst()
  expect(screen.getByText(en.nmReadyConnectorRequired)).toBeTruthy(); expect((screen.getByRole('button', { name: en.nmPreview }) as HTMLButtonElement).disabled).toBe(true)
})
it('prevents confirming an expired preview', async () => {
  const { fetcher } = setup({ expired: true }); await previewFirst()
  expect(screen.getByText(en.nmPreviewExpired)).toBeTruthy(); expect((screen.getByRole('button', { name: en.nmReviewQueue }) as HTMLButtonElement).disabled).toBe(true); expect(posts(fetcher, '/enqueue')).toHaveLength(0)
})
it('requires a fresh preview after a generation conflict and never retries the write', async () => {
  const { fetcher } = setup({ enqueueStatus: 409 }); await previewFirst(); await confirm(); await userEvent.click(screen.getByRole('button', { name: en.nmQueue }))
  await screen.findAllByText(en.nmConflict); expect(posts(fetcher, '/enqueue')).toHaveLength(1); expect(screen.queryByText('PRIVATE PROVIDER DETAILS')).toBeNull()
  await userEvent.click(screen.getByRole('button', { name: en.nmPreview })); await screen.findByText(en.nmTemplateLanguage); await userEvent.click(screen.getByRole('button', { name: en.nmReviewQueue }))
  expect((screen.getByLabelText(en.nmReason + ' *') as HTMLInputElement).value).toBe('Reviewed employee onboarding'); expect(posts(fetcher, '/enqueue')).toHaveLength(1)
})
it.each([{ enqueueStatus: 503 }, { malformed: true }])('inspects an uncertain enqueue without an automatic retry: %j', async (options) => {
  const { fetcher } = setup(options); await previewFirst(); await confirm(); await userEvent.click(screen.getByRole('button', { name: en.nmQueue }))
  await screen.findAllByText(en.nmUncertain); expect(posts(fetcher, '/enqueue')).toHaveLength(1); expect(screen.queryByRole('button', { name: en.nmNewBatch })).toBeNull()
  await userEvent.click(screen.getByRole('button', { name: en.nmInspectResult })); await screen.findByText('Queued: 1. No email has been sent.'); expect(posts(fetcher, '/enqueue')).toHaveLength(1)
})
it('does not treat a missing receipt as proof of rollback', async () => {
  const { fetcher } = setup({ receipt: true, missingReceipt: true })
  await screen.findByRole('button', { name: en.nmInspectResult }); await userEvent.click(screen.getByRole('button', { name: en.nmInspectResult }))
  await screen.findAllByText(en.nmNotFound); expect(screen.queryByRole('button', { name: en.nmNewBatch })).toBeNull(); expect(posts(fetcher, '/enqueue')).toHaveLength(0)
})
it('previews manual reminders using exact known user references', async () => {
  const { fetcher } = setup({ view: 'reminders' }); await screen.findByText('employee1@vopak.com')
  await userEvent.click(screen.getByLabelText(en.nmTargetGroup)); await userEvent.click(await screen.findByRole('option', { name: en.nmCategory_unobserved })); await selectFirst()
  await userEvent.click(screen.getByRole('button', { name: en.nmPreview })); await screen.findByText(en.nmTemplateLanguage)
  expect(JSON.parse(String(posts(fetcher, '/preview')[0][1]?.body))).toMatchObject({ type: 'reminder', targets: ['user:' + uuid(1)] })
})
it('distinguishes queued history from provider attempts and supports cancellation', async () => {
  const { fetcher } = setup({ view: 'history' }); await screen.findByText('employee1@vopak.com')
  expect(screen.getByText(en.nmState_queued)).toBeTruthy(); expect(screen.getByText(en.nmAttempt_none)).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: 'View notification for employee1@vopak.com' })); await screen.findByText(en.nmEmailDetails)
  await userEvent.click(screen.getByRole('button', { name: en.nmCancelJob })); expect((screen.getByRole('button', { name: en.nmConfirmCancel }) as HTMLButtonElement).disabled).toBe(true)
  fireEvent.change(screen.getByLabelText(en.nmReason + ' *'), { target: { value: 'Employee request cancelled' } }); await userEvent.click(screen.getByRole('button', { name: en.nmConfirmCancel }))
  await waitFor(() => expect(posts(fetcher, '/cancel')).toHaveLength(1)); expect(JSON.parse(String(posts(fetcher, '/cancel')[0][1]?.body))).toEqual({ expected_generation: 1, reason: 'Employee request cancelled' })
  await screen.findAllByText(en.nmState_cancelled)
})
it('shows Needs Inspection attempts and offers no resend or terminal reset', async () => {
  const { fetcher } = setup({ view: 'history', needsInspection: true }); await screen.findByText(en.nmState_needs_inspection)
  await userEvent.click(screen.getByRole('button', { name: 'View notification for employee1@vopak.com' })); await screen.findByText(en.nmNeedsInspectionHelp)
  expect(screen.getAllByText(en.nmAttempt_uncertain).length).toBeGreaterThan(0); expect(screen.queryByRole('button', { name: en.nmCancelJob })).toBeNull(); expect(posts(fetcher, '/cancel')).toHaveLength(0)
})
it('blocks uncertain cancellation until authoritative inspection', async () => {
  const { fetcher } = setup({ view: 'history', cancelStatus: 503 }); await screen.findByText('employee1@vopak.com'); await userEvent.click(screen.getByRole('button', { name: 'View notification for employee1@vopak.com' }))
  await userEvent.click(await screen.findByRole('button', { name: en.nmCancelJob })); fireEvent.change(screen.getByLabelText(en.nmReason + ' *'), { target: { value: 'Employee request cancelled' } }); await userEvent.click(screen.getByRole('button', { name: en.nmConfirmCancel }))
  await screen.findAllByText(en.nmUncertain); expect(screen.queryByRole('button', { name: en.nmConfirmCancel })).toBeNull(); expect(posts(fetcher, '/cancel')).toHaveLength(1)
  await userEvent.click(screen.getByRole('button', { name: en.nmInspectResult })); await screen.findByRole('button', { name: en.nmConfirmCancel }); expect(posts(fetcher, '/cancel')).toHaveLength(1)
})
it('separates unknown login history, claim evidence and workforce coverage', async () => {
  setup({ view: 'onboarding' }); await screen.findByText('employee1@vopak.com')
  expect(screen.getByText(en.nmCoverageHelp)).toBeTruthy(); expect(screen.getByText(en.nmUnknownHelp)).toBeTruthy(); expect(screen.getByText(en.nmClaimEvidence)).toBeTruthy(); expect(screen.getAllByText(en.nmNoObservation).length).toBeGreaterThan(0)
})
it('repeats authoritative inspection even when the request filter is unchanged', async () => {
  const { fetcher } = setup({ view: 'history', receipt: true }); await screen.findByText('employee1@vopak.com')
  const reads = () => fetcher.mock.calls.filter(([path]) => path.includes('/requests/')).length
  const before = reads(); await userEvent.click(screen.getByRole('button', { name: en.nmInspectResult }))
  await waitFor(() => expect(reads()).toBe(before + 1)); await waitFor(() => expect((screen.getByRole('button', { name: en.nmInspectResult }) as HTMLButtonElement).disabled).toBe(false))
})
it('uses audited generation checks for exact-target suppression', async () => {
  const { fetcher } = setup({ view: 'onboarding' }); await screen.findByText('employee1@vopak.com')
  await userEvent.click(screen.getByRole('button', { name: 'Manage notifications for employee1@vopak.com' })); await userEvent.click(screen.getByRole('button', { name: en.nmInspectSuppression }))
  const dialog = screen.getByRole('dialog')
  expect(within(dialog).getByText(en.nmSuppressionHelp)).toBeTruthy(); fireEvent.change(await within(dialog).findByLabelText(en.nmReason + ' *'), { target: { value: 'Employee requested notification suppression' } })
  await userEvent.click(screen.getByRole('checkbox', { name: en.nmSuppressed })); await userEvent.click(screen.getByRole('button', { name: en.nmSaveSuppression }))
  await waitFor(() => expect(posts(fetcher, '/suppressions')).toHaveLength(1)); expect(JSON.parse(String(posts(fetcher, '/suppressions')[0][1]?.body))).toMatchObject({ target: 'user:' + uuid(1), expected_generation: 0, active: true })
})
it('uses no management API for an unauthorized administrator', () => {
  const { fetcher } = setup({ user: bob }); expect(screen.getByText(resources.en.common.accessDenied)).toBeTruthy(); expect(fetcher).not.toHaveBeenCalled()
})
it('covers all locale keys and preserves preview confirmation fields through Arabic RTL', async () => {
  const keys = Object.keys(en).filter((key) => key.startsWith('nm'))
  for (const locale of Object.values(resources)) for (const key of keys) expect(locale.admin[key]).toBeTruthy()
  const { instance } = setup(); await previewFirst(); await confirm(); await act(async () => { await instance.changeLanguage('ar') })
  expect(document.documentElement.dir).toBe('rtl'); expect((screen.getByLabelText(resources.ar.admin.nmReason + ' *') as HTMLInputElement).value).toBe('Reviewed employee onboarding')
  expect(JSON.stringify(localStorage)).not.toContain('preview_digest'); expect(JSON.stringify(sessionStorage)).not.toContain('preview_digest')
})
it('opens notification details with the keyboard and mirrors the drawer in Arabic RTL', async () => {
  setup({ view: 'history', language: 'ar' }); await screen.findByText('employee1@vopak.com')
  const button = screen.getByRole('button', { name: resources.ar.admin.nmViewRecipient.replace('{{email}}', 'employee1@vopak.com') })
  button.focus(); await userEvent.keyboard('{Enter}'); await screen.findByText(resources.ar.admin.nmEmailDetails)
  const drawer = document.querySelector('.MuiDrawer-paper') as HTMLElement
  expect(drawer.style.left).toBe('0px'); expect(drawer.style.right).toBe('auto')
})
it.each(['dark', 'light'])('renders notification history in %s appearance', async (appearance) => {
  localStorage.setItem('gwf.appearance', appearance); setup({ view: 'history' }); await screen.findByText('employee1@vopak.com'); expect(screen.getByRole('table', { name: en.nmHistory })).toBeTruthy()
})

it.each(['invitations', 'reminders'])('disables ineligible %s recipients and links the visible explanation', async (view) => {
  const { fetcher } = setup({ view, recipientCode: 'suppressed', total: 2 }); await screen.findByText('employee1@vopak.com')
  const blocked = screen.getByRole('checkbox', { name: 'Select employee1@vopak.com' }) as HTMLInputElement
  expect(blocked.disabled).toBe(true)
  expect(document.getElementById(blocked.getAttribute('aria-describedby')!)?.textContent).toBe(en.nmCode_suppressed)
  blocked.click(); expect(blocked.checked).toBe(false)
  await userEvent.click(screen.getByRole('button', { name: en.nmSelectPage }))
  expect(screen.getByText('Selected: 1 of 100, across pages.')).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: en.nmPreview })); await screen.findByText(en.nmTemplateLanguage)
  expect(JSON.parse(String(posts(fetcher, '/preview')[0][1]?.body)).targets).toEqual(['invitation:' + uuid(2)])
})
it('hides single-page controls while keeping bounded server-side recipient pagination', async () => {
  const { fetcher } = setup(); await screen.findByText('employee1@vopak.com')
  expect(screen.getAllByRole('navigation')).toHaveLength(1)
  expect(screen.getByRole('navigation', { name: en.nmRecipients })).toBeTruthy()
  expect(screen.queryByRole('navigation', { name: en.nmConnector })).toBeNull()
  await userEvent.click(screen.getByRole('button', { name: resources.en.common.nextPage })); await screen.findByText('employee21@vopak.com')
  expect(fetcher.mock.calls.some(([path]) => path.includes('/onboarding?') && path.includes('offset=20') && path.includes('limit=20'))).toBe(true)
})
it('retains separate server pagination when connector selection needs multiple pages', async () => {
  const { fetcher } = setup({ total: 1, connectorTotal: 21 }); await screen.findByText('employee1@vopak.com')
  const pager = screen.getByRole('navigation', { name: en.nmConnector })
  await userEvent.click(within(pager).getByRole('button', { name: resources.en.common.nextPage }))
  await waitFor(() => expect(fetcher.mock.calls.some(([path]) => path.includes('/email-connectors?') && path.includes('offset=20'))).toBe(true))
  expect(screen.queryByRole('navigation', { name: en.nmRecipients })).toBeNull()
})
it('explains an empty recipient list without unnecessary pagination', async () => {
  setup({ total: 0 }); await screen.findByText(en.nmRecipientsEmpty)
  expect(screen.queryByRole('navigation')).toBeNull()
  expect((screen.getByRole('button', { name: en.nmSelectPage }) as HTMLButtonElement).disabled).toBe(true)
  expect((screen.getByRole('button', { name: en.nmPreview }) as HTMLButtonElement).disabled).toBe(true)
})
it('keeps configuration warnings and usable search when no connector is ready', async () => {
  const { fetcher } = setup({ ready: false, communication: false }); await screen.findByText('employee1@vopak.com')
  expect(screen.getByText(en.nmCommunicationSetup)).toBeTruthy(); expect(screen.getByText(en.nmReadyConnectorRequired)).toBeTruthy()
  fireEvent.change(screen.getByLabelText(en.nmSearch), { target: { value: 'employee2' } })
  await userEvent.click(screen.getByRole('button', { name: en.nmApplyFilters }))
  await waitFor(() => expect(fetcher.mock.calls.some(([path]) => path.includes('search=employee2'))).toBe(true))
})
it('retains confirmation input while navigating back through the workflow', async () => {
  setup({ total: 1, accessMode: 'allow_all' }); await previewFirst(); await confirm()
  expect(screen.getByText(en.nmAllowAll)).toBeTruthy()
  expect(screen.getByRole('heading', { level: 3, name: en.nmConfirm })).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: en.nmBack }))
  expect(screen.getByRole('heading', { level: 3, name: en.nmEmailPreview })).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: en.nmReviewQueue }))
  expect((screen.getByLabelText(en.nmReason + ' *') as HTMLInputElement).value).toBe('Reviewed employee onboarding')
  expect(screen.getByRole('listitem', { current: 'step' }).textContent).toContain(en.nmConfirm)
})
it('provides helpful empty history and preserves the delivery warning', async () => {
  setup({ view: 'history', historyEmpty: true }); await screen.findByText(en.nmHistoryEmpty)
  expect(screen.getByText(en.nmDeliveryDisabled)).toBeTruthy(); expect(screen.queryByRole('navigation')).toBeNull()
  expect(screen.getByLabelText(en.nmQueueStatus)).toBeTruthy()
})
it('presents onboarding counts and dated positive login evidence with semantic labels', async () => {
  setup({ view: 'onboarding', total: 2 }); await screen.findByText('employee2@vopak.com')
  const overview = screen.getByRole('heading', { name: en.nmOverview }).closest('section')!
  expect(overview.querySelectorAll('dt')).toHaveLength(4); expect(overview.querySelectorAll('dd')).toHaveLength(4)
  expect(screen.getByText(en.nmFirstLoginLabel)).toBeTruthy(); expect(screen.getByText(en.nmLastLoginLabel)).toBeTruthy()
  expect(overview.querySelector('time[datetime="2026-01-01T00:00:00Z"]')).toBeTruthy()
  expect(screen.getByText(en.nmCoverageHelp)).toBeTruthy(); expect(screen.getByText(en.nmUnknownHelp)).toBeTruthy()
  expect(screen.queryByRole('navigation')).toBeNull()
})
it('explains an empty onboarding category and keeps group filtering available', async () => {
  const { fetcher } = setup({ view: 'onboarding', total: 0 }); await screen.findByText(en.nmOnboardingEmpty)
  await userEvent.click(screen.getByLabelText(en.nmTargetGroup)); await userEvent.click(screen.getByRole('option', { name: en.nmCategory_inactive }))
  await waitFor(() => expect(fetcher.mock.calls.some(([path]) => path.includes('category=inactive'))).toBe(true))
  expect(screen.queryByRole('navigation')).toBeNull()
})

it('applies history search and status filters without changing inspection semantics', async () => {
  const { fetcher } = setup({ view: 'history' }); await screen.findByText('employee1@vopak.com')
  fireEvent.change(screen.getByLabelText(en.nmSearch), { target: { value: 'employee1' } })
  await userEvent.click(screen.getByRole('button', { name: en.nmApplyFilters }))
  await waitFor(() => expect(fetcher.mock.calls.some(([path]) => path.includes('/history?') && path.includes('search=employee1'))).toBe(true))
  await userEvent.click(screen.getByLabelText(en.nmQueueStatus)); await userEvent.click(screen.getByRole('option', { name: en.nmState_needs_inspection }))
  await waitFor(() => expect(fetcher.mock.calls.some(([path]) => path.includes('status=needs_inspection') && path.includes('offset=0'))).toBe(true))
  expect(posts(fetcher, '/enqueue')).toHaveLength(0)
})
