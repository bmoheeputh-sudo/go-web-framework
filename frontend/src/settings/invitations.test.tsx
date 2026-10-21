import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { I18nextProvider } from 'react-i18next'
import { MemoryRouter } from 'react-router-dom'
import { accessPolicyPath, invitationsPath } from '../api/accessPolicy'
import type { Invitation, InvitationPage, PolicySnapshot } from '../api/accessPolicy'
import { QueryCache } from '../api/cache'
import { QueryContext } from '../api/queries'
import type { Session } from '../auth/session'
import { SessionContext } from '../auth/session'
import { appearanceStorageKey } from '../appearance/appearance'
import { createI18n, resources } from '../i18n'
import type { Language } from '../i18n'
import LanguageProvider from '../LanguageProvider'
import NotificationProvider from '../notifications/NotificationProvider'
import { admin, bob, identity, mockMedia } from '../test/fixtures'
import UserAccess from './UserAccess'
import InvitationManagement from './InvitationManagement'

const en = resources.en.auth, common = resources.en.common, stamp = '2026-10-20T10:00:00Z'
function setup(options: { mode?: 'allow_all' | 'approved_users_only'; user?: typeof admin; language?: Language; readStatus?: number; writeStatuses?: number[]; stale?: boolean; theme?: 'dark' | 'light'; wholePage?: boolean } = {}) {
  if (options.theme) localStorage.setItem(appearanceStorageKey, options.theme)
  const snapshot: PolicySnapshot = { policy: { deployment_id: 'deployment-a', environment: 'development', generation: 8, mode: options.mode || 'allow_all', default_role: 'Viewer', allowed_email_domains: [], created_by: admin.id, updated_by: admin.id, created_at: stamp, updated_at: stamp, reason: 'existing policy' }, activation_generation: 3, active_issuer: identity.issuer, overview: { approved: 1, revoked: 0, active_oidc_users: 2 } }
  const rows: Invitation[] = (['pending', 'claimed', 'revoked', 'expired'] as const).map((status, index) => ({
    id: `invitation-${index}`, deployment_id: 'deployment-a', environment: 'development', issuer: identity.issuer, client_id: 'trusted-client', revision_id: 'trusted-revision', revision_generation: 4, activation_generation: 3,
    email: `${status}@example.test`, email_key: `${status}@example.test`, display_name: `Employee ${index}`, expires_at: status === 'expired' ? stamp : new Date(Date.now() + 20 * 86400000).toISOString(), status,
    generation: status === 'pending' ? 1 : 2, created_by: admin.id, created_at: stamp, updated_by: admin.id, updated_at: stamp, reason: 'Employee onboarding', source: 'manual', binding_current: !options.stale,
    ...(status === 'claimed' ? { claimed_user_id: bob.id, claimed_subject: 'claimed-exact-subject', claimed_issuer: identity.issuer, claimed_at: stamp } : {}),
  }))
  const page: InvitationPage = { items: rows, total: 21, offset: 0, limit: 20, policy_generation: 8, activation_generation: 3, revision_id: 'trusted-revision', revision_generation: 4 }
  const statuses = [...(options.writeStatuses || [])]
  const fetcher = vi.fn(async (path: string, init?: RequestInit) => {
    const method = init?.method || 'GET'
    if (path === accessPolicyPath) return Response.json(snapshot)
    if (path === `${accessPolicyPath}/approvals/${bob.id}`) return Response.json({ ...bob, user_id: bob.id, user_active: false, approval_status: 'approved', approval_generation: 1, updated_at: stamp, provider_current: true })
    if (path.startsWith(accessPolicyPath + '/approvals?')) return Response.json({ items: [{ user_id: bob.id, issuer: identity.issuer, subject: bob.subject, display_name: bob.display_name, email: bob.email, user_active: false, roles: ['Viewer'], approval_status: 'approved', approval_generation: 1, updated_at: stamp, provider_current: true }], total: 1, offset: 0, limit: 20, policy_generation: 8, activation_generation: 3 })
    if (path.startsWith(invitationsPath + '?')) {
      if (options.readStatus) return Response.json({ error: 'UNTRUSTED INTERNAL MESSAGE' }, { status: options.readStatus })
      const q = new URL(path, 'https://app.test').searchParams
      const items = rows.filter((row) => (!q.get('status') || row.status === q.get('status')) && `${row.email} ${row.display_name}`.includes(q.get('search') || ''))
      return Response.json({ ...page, items: q.get('offset') === '20' ? [{ ...rows[0], display_name: 'Second page' }] : items, offset: Number(q.get('offset')) })
    }
    if (path.startsWith(invitationsPath) && method === 'POST') {
      const status = statuses.shift()
      if (status) return Response.json({ error: status === 503 ? 'oidc_invitation_commit_uncertain' : 'access_policy_conflict', automatic_retry_allowed: false, inspection_required: status === 503 }, { status })
      const body = JSON.parse(String(init?.body))
      if (path.endsWith('/revoke')) { rows[0].status = 'revoked'; rows[0].generation++; return Response.json(rows[0]) }
      const next: Invitation = { ...rows[0], id: 'created-invitation', status: 'pending', email: body.email, email_key: body.email, display_name: body.display_name, reason: body.reason, generation: 1, expires_at: body.expires_at || new Date(Date.now() + 7 * 86400000).toISOString() }
      rows.unshift(next); return Response.json(next, { status: 201 })
    }
    const row = rows.find((item) => path === `${invitationsPath}/${item.id}`)
    if (row) return Response.json(row)
    throw new Error(`Unexpected test request: ${path}`)
  })
  vi.stubGlobal('fetch', fetcher)
  const session: Session = { authentication: { status: 'authenticated', identity }, access: { loading: false, user: options.user || admin, error: '' }, health: 'ok', oidcEnabled: true, loggingOut: false, logoutFailed: false, loginFailed: false, logout: vi.fn(), expire: vi.fn(), refreshAccess: vi.fn() }
  const instance = createI18n(options.language || 'en')
  const queryCache = new QueryCache(session.expire), invalidated = vi.spyOn(queryCache, 'invalidate')
  const content = (visible = true) => <I18nextProvider i18n={instance}><LanguageProvider><NotificationProvider><SessionContext.Provider value={session}><QueryContext.Provider value={queryCache}><MemoryRouter>{visible && (options.wholePage || options.user ? <UserAccess /> : <InvitationManagement mode={options.mode || 'allow_all'} refresh={0} disabled={false} onChanged={() => {}} onViewUser={() => {}} />)}</MemoryRouter></QueryContext.Provider></SessionContext.Provider></NotificationProvider></LanguageProvider></I18nextProvider>
  const view = render(content())
  return { fetcher, page, rows, session, instance, invalidated, hide: () => view.rerender(content(false)), show: () => view.rerender(content()) }
}
beforeEach(() => { mockMedia(); localStorage.clear(); sessionStorage.clear() })
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })
const section = () => screen.getByRole('heading', { name: en.invitationsTitle }).closest('section')!
const dialog = () => screen.getByRole('dialog')
async function loaded() { await waitFor(() => expect((screen.getByRole('button', { name: en.invitationAddUser }) as HTMLButtonElement).disabled).toBe(false)) }
async function add() { await loaded(); await userEvent.click(screen.getByRole('button', { name: en.invitationAddUser })) }
function fill(email = 'Employee+tag@EXAMPLE.TEST') {
  fireEvent.change(within(dialog()).getByLabelText(en.email + ' *'), { target: { value: email } })
  fireEvent.change(within(dialog()).getByLabelText(en.accessReason + ' *'), { target: { value: 'Approved employee onboarding' } })
}
const writes = (fetcher: ReturnType<typeof setup>['fetcher']) => fetcher.mock.calls.filter(([path, init]) => path.startsWith(invitationsPath) && init?.method === 'POST')
const submit = () => within(dialog()).getByRole('button', { name: en.invitationCreate })

it('creates once with trusted expectations, server-default seven days and cache invalidation', async () => {
  const { invalidated, fetcher } = setup(); await add(); fill()
  fireEvent.change(within(dialog()).getByLabelText(en.displayName), { target: { value: 'New Employee' } })
  expect((within(dialog()).getByLabelText(en.invitationExpiration + ' *') as HTMLInputElement).value).toBe('7')
  await userEvent.dblClick(submit()); await screen.findByText(en.invitationCreated)
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  expect(writes(fetcher)).toHaveLength(1)
  expect(JSON.parse(String(writes(fetcher)[0][1]?.body))).toEqual({ email: 'Employee+tag@EXAMPLE.TEST', display_name: 'New Employee', reason: 'Approved employee onboarding', expected_policy_generation: 8, expected_activation_generation: 3, revision_id: 'trusted-revision', expected_revision_generation: 4 })
  expect(await within(section()).findByText('Employee+tag@EXAMPLE.TEST')).toBeTruthy()
  expect(invalidated).toHaveBeenCalledWith([accessPolicyPath, '/api/admin/users', '/api/admin/audit'])
  expect(fetcher.mock.calls.every(([, init]) => init?.credentials === 'same-origin' && init.cache === 'no-store')).toBe(true)
})
it('validates required fields, email, audit bytes and whole-day expiry bounds', async () => {
  const { fetcher } = setup(); await add(); expect((submit() as HTMLButtonElement).disabled).toBe(true)
  fill('Employee <employee@example.test>'); expect((submit() as HTMLButtonElement).disabled).toBe(true)
  expect(within(dialog()).getByText(en.invitationEmailHelp)).toBeTruthy(); fill()
  for (const days of ['0', '31', '1.5', '']) {
    fireEvent.change(within(dialog()).getByLabelText(en.invitationExpiration + ' *'), { target: { value: days } }); expect((submit() as HTMLButtonElement).disabled).toBe(true)
  }
  fireEvent.change(within(dialog()).getByLabelText(en.invitationExpiration + ' *'), { target: { value: '30' } })
  fireEvent.change(within(dialog()).getByLabelText(en.accessReason + ' *'), { target: { value: '界'.repeat(200) } }); expect((submit() as HTMLButtonElement).disabled).toBe(true)
  fill(); expect((submit() as HTMLButtonElement).disabled).toBe(false); expect(writes(fetcher)).toHaveLength(0)
})
it.each([1, 30])('sends an explicit expiration for a custom %s-day invitation', async (days) => {
  const { fetcher } = setup(); await add(); fill()
  fireEvent.change(within(dialog()).getByLabelText(en.invitationExpiration + ' *'), { target: { value: String(days) } })
  const before = Date.now(); await userEvent.click(submit()); await screen.findByText(en.invitationCreated)
  const expires = Date.parse(JSON.parse(String(writes(fetcher)[0][1]?.body)).expires_at)
  expect(expires).toBeGreaterThanOrEqual(before + days * 86400000); expect(expires).toBeLessThanOrEqual(Date.now() + days * 86400000)
})
it('lists states, searches, filters and paginates without technical identifiers in the table', async () => {
  const { fetcher } = setup(); await loaded()
  for (const state of ['pending', 'claimed', 'revoked', 'expired'] as const) expect(within(section()).getByText(en[`invitationStatus_${state}`])).toBeTruthy()
  const table = within(section()).getByRole('table'); expect(within(table).queryByText(identity.issuer)).toBeNull(); expect(within(table).queryByText('trusted-client')).toBeNull()
  expect(within(table).getAllByRole('button').filter((item) => item.textContent === en.invitationRevoke)).toHaveLength(1)
  await userEvent.click(within(screen.getByRole('group', { name: en.invitationPagination })).getByRole('button', { name: common.nextPage })); await screen.findByText('Second page')
  fireEvent.change(screen.getByLabelText(en.invitationSearch), { target: { value: 'claimed@' } })
  await waitFor(() => expect(within(table).queryByText('pending@example.test')).toBeNull())
  fireEvent.mouseDown(screen.getByLabelText(en.invitationStatus)); await userEvent.click(await screen.findByRole('option', { name: en.invitationStatus_claimed }))
  await waitFor(() => expect(fetcher.mock.calls.some(([path]) => path.includes('search=claimed%40') && path.includes('status=claimed') && path.includes('offset=0') && path.includes('limit=20'))).toBe(true))
})
it('requires revocation confirmation and a reason with authoritative generations', async () => {
  const { fetcher } = setup(); await loaded(); await userEvent.click(screen.getByRole('button', { name: en.invitationRevokeEmployee.replace('{{email}}', 'pending@example.test') }))
  expect(within(dialog()).getByText('pending@example.test')).toBeTruthy(); expect(within(dialog()).getByText(en.invitationAccessHelp)).toBeTruthy()
  const confirm = within(dialog()).getByRole('button', { name: en.invitationConfirmRevoke }); expect((confirm as HTMLButtonElement).disabled).toBe(true)
  fireEvent.change(within(dialog()).getByLabelText(en.accessReason + ' *'), { target: { value: 'Employee onboarding cancelled' } })
  await userEvent.dblClick(confirm); await screen.findByText(en.invitationRevoked)
  expect(writes(fetcher)).toHaveLength(1); expect(writes(fetcher)[0][0]).toBe(invitationsPath + '/invitation-0/revoke')
  expect(JSON.parse(String(writes(fetcher)[0][1]?.body))).toEqual({ expected_policy_generation: 8, expected_activation_generation: 3, revision_id: 'trusted-revision', expected_revision_generation: 4, expected_invitation_generation: 1, reason: 'Employee onboarding cancelled' })
})
it('keeps stale invitations historical and exposes claimed identity metadata in details', async () => {
  setup({ stale: true }); await loaded()
  expect((screen.getByRole('button', { name: en.invitationRevokeEmployee.replace('{{email}}', 'pending@example.test') }) as HTMLButtonElement).disabled).toBe(true)
  await userEvent.click(screen.getByRole('button', { name: en.invitationViewEmployee.replace('{{email}}', 'claimed@example.test') })); await screen.findByRole('heading', { name: en.invitationDetails })
  expect(screen.getByText(en.invitationStaleHelp)).toBeTruthy(); expect(screen.getByText('claimed-exact-subject')).toBeTruthy(); expect(screen.getByText(bob.id)).toBeTruthy(); expect(screen.getAllByRole('dialog')).toHaveLength(1)
})
it.each([400, 404, 409])('preserves the draft after HTTP %s without retrying', async (status) => {
  const { fetcher } = setup({ writeStatuses: [status] }); await add(); fill(); await userEvent.click(submit())
  await within(dialog()).findByText(en[status === 400 ? 'invitationInvalid' : status === 404 ? 'invitationMissing' : 'invitationConflict'])
  expect((within(dialog()).getByLabelText(en.email + ' *') as HTMLInputElement).value).toBe('Employee+tag@EXAMPLE.TEST'); expect(writes(fetcher)).toHaveLength(1)
  if (status !== 400) expect((submit() as HTMLButtonElement).disabled).toBe(true)
})
it('requires explicit review before another decision after a generation conflict', async () => {
  const { fetcher, page } = setup({ writeStatuses: [409] }); await add(); fill(); await userEvent.click(submit()); await within(dialog()).findByText(en.invitationConflict)
  page.policy_generation = 9; await userEvent.click(within(dialog()).getByRole('button', { name: en.invitationReviewFresh }))
  await waitFor(() => expect((submit() as HTMLButtonElement).disabled).toBe(false)); expect(writes(fetcher)).toHaveLength(1)
  await userEvent.click(submit()); await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull()); expect(writes(fetcher)).toHaveLength(2); expect(JSON.parse(String(writes(fetcher)[1][1]?.body)).expected_policy_generation).toBe(9)
})
it('blocks uncertain writes while allowing inspection and persists no security data', async () => {
  const { fetcher } = setup({ writeStatuses: [503] }); await add(); fill(); await userEvent.click(submit()); await within(dialog()).findByText(en.invitationUncertain)
  expect((submit() as HTMLButtonElement).disabled).toBe(true)
  await userEvent.click(within(dialog()).getByRole('button', { name: en.invitationInspect })); await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  expect(screen.getAllByText(en.invitationUncertain).length).toBeGreaterThan(0); expect((screen.getByRole('button', { name: en.invitationAddUser }) as HTMLButtonElement).disabled).toBe(true)
  expect(writes(fetcher)).toHaveLength(1); expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0)
})
it.each([404, 409, 503])('explains unavailable creation after read HTTP %s', async (readStatus) => {
  setup({ readStatus }); await screen.findByText(readStatus === 503 ? en.invitationUnavailable : en.invitationNotReady)
  expect((screen.getByRole('button', { name: en.invitationAddUser }) as HTMLButtonElement).disabled).toBe(true)
})
it.each([401, 403])('revalidates authorization after read HTTP %s', async (readStatus) => {
  const { session } = setup({ readStatus }); await waitFor(() => expect(readStatus === 401 ? session.expire : session.refreshAccess).toHaveBeenCalled())
  expect((screen.getByRole('button', { name: en.invitationAddUser }) as HTMLButtonElement).disabled).toBe(true)
})
it('does not fetch invitations without admin.manage', () => {
  const { fetcher } = setup({ user: bob }); expect(screen.getByText(common.accessDenied)).toBeTruthy(); expect(fetcher).not.toHaveBeenCalled()
})
it.each(['allow_all', 'approved_users_only'] as const)('explains %s and retains compact approved-user and policy sections', async (mode) => {
  setup({ mode, wholePage: true }); await loaded(); expect(screen.getByText(mode === 'allow_all' ? en.invitationAllowAll : en.invitationApprovedOnly)).toBeTruthy()
  for (const title of [en.accessPolicyTitle, en.invitationsTitle, en.accessIdentities]) expect(screen.getByRole('heading', { name: title, level: 2 })).toBeTruthy()
  const table = screen.getByRole('table', { name: en.accessIdentities }); expect(within(table).getByText(bob.display_name)).toBeTruthy(); expect(within(table).getByText(bob.email)).toBeTruthy(); expect(within(table).queryByText(bob.subject)).toBeNull()
  expect(within(table).getByRole('columnheader', { name: en.invitationProviderStatus })).toBeTruthy()
})
it('preserves unsaved input through Escape and language changes and requires explicit discard', async () => {
  const { instance } = setup(); await add(); fill()
  const event = new Event('beforeunload', { cancelable: true }); window.dispatchEvent(event); expect(event.defaultPrevented).toBe(true)
  await userEvent.keyboard('{Escape}'); expect(within(dialog()).getByText(en.invitationDiscardHelp)).toBeTruthy(); expect(screen.getAllByRole('dialog')).toHaveLength(1)
  await userEvent.click(within(dialog()).getByRole('button', { name: en.invitationKeepEditing })); await act(async () => { await instance.changeLanguage('ar') })
  expect((within(dialog()).getByLabelText(resources.ar.auth.email + ' *') as HTMLInputElement).value).toBe('Employee+tag@EXAMPLE.TEST')
  await userEvent.click(within(dialog()).getByRole('button', { name: resources.ar.common.cancel })); await userEvent.click(within(dialog()).getByRole('button', { name: resources.ar.auth.invitationDiscard })); await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
})
it.each([['light', 'en'], ['dark', 'en'], ['light', 'ar'], ['dark', 'ar']] as const)('renders %s theme and %s drawer with keyboard controls', async (theme, language) => {
  setup({ theme, language }); const labels = resources[language].auth
  const view = await screen.findByRole('button', { name: labels.invitationViewEmployee.replace('{{email}}', 'pending@example.test') }); view.focus(); await userEvent.keyboard('{Enter}'); await screen.findByRole('heading', { name: labels.invitationDetails })
  expect(getComputedStyle(document.querySelector('.MuiDrawer-paper')!)[language === 'ar' ? 'left' : 'right']).toBe('0px'); expect(document.documentElement.dir).toBe(language === 'ar' ? 'rtl' : 'ltr'); expect(getComputedStyle(document.body).colorScheme).toBe(theme)
})
it('has complete invitation translations and placeholders in all twelve locales', () => {
  const keys = Object.keys(en).filter((key) => key.startsWith('invitation')); expect(Object.keys(resources)).toHaveLength(12)
  for (const namespaces of Object.values(resources)) for (const key of keys) { expect(namespaces.auth[key]?.trim()).toBeTruthy(); expect(namespaces.auth[key].match(/{{\w+}}/g) || []).toEqual(en[key].match(/{{\w+}}/g) || []) }
})

it.each([401, 403])('blocks further writes after mutation authorization HTTP %s', async (status) => {
  const { fetcher, session } = setup({ writeStatuses: [status] }); await add(); fill(); await userEvent.click(submit())
  await within(dialog()).findByText(common.accessDenied)
  expect(status === 401 ? session.expire : session.refreshAccess).toHaveBeenCalled()
  expect((submit() as HTMLButtonElement).disabled).toBe(true); expect(writes(fetcher)).toHaveLength(1)
})
it('treats a lost mutation response as uncertain and never retries it', async () => {
  const { fetcher } = setup(); await add(); fill()
  const original = fetcher.getMockImplementation()!
  fetcher.mockImplementation(async (path, init) => { if (init?.method === 'POST') throw new Error('Synthetic transport loss'); return original(path, init) })
  await userEvent.click(submit()); await within(dialog()).findByText(en.invitationUncertain)
  expect((submit() as HTMLButtonElement).disabled).toBe(true); expect(writes(fetcher)).toHaveLength(1)
})
it('does not retry a revoke after authoritative inspection discovers a concurrent claim', async () => {
  const { fetcher, rows } = setup({ writeStatuses: [409] }); await loaded()
  await userEvent.click(screen.getByRole('button', { name: en.invitationRevokeEmployee.replace('{{email}}', 'pending@example.test') }))
  fireEvent.change(within(dialog()).getByLabelText(en.accessReason + ' *'), { target: { value: 'Employee onboarding cancelled' } })
  await userEvent.click(within(dialog()).getByRole('button', { name: en.invitationConfirmRevoke })); await within(dialog()).findByText(en.invitationConflict)
  rows[0].status = 'claimed'
  await userEvent.click(within(dialog()).getByRole('button', { name: en.invitationReviewFresh })); await within(dialog()).findByText(en.invitationNotRevocable)
  expect((within(dialog()).getByRole('button', { name: en.invitationConfirmRevoke }) as HTMLButtonElement).disabled).toBe(true); expect(writes(fetcher)).toHaveLength(1)
})
it('opens the claimed user through the existing user-detail API without stacking drawers', async () => {
  const { fetcher } = setup({ wholePage: true }); await loaded()
  await userEvent.click(screen.getByRole('button', { name: en.invitationViewEmployee.replace('{{email}}', 'claimed@example.test') })); await screen.findByRole('heading', { name: en.invitationDetails })
  await userEvent.click(within(dialog()).getByRole('button', { name: en.accessDetails })); await screen.findByRole('heading', { name: en.accessDetails })
  expect(fetcher.mock.calls.some(([path]) => path === `${accessPolicyPath}/approvals/${bob.id}`)).toBe(true)
  await waitFor(() => expect(screen.getAllByRole('dialog')).toHaveLength(1))
})
it('keeps actions sticky at the logical trailing edge on a narrow Arabic view', async () => {
  mockMedia(false); setup({ language: 'ar' })
  await screen.findByText('pending@example.test')
  const table = screen.getByRole('table', { name: resources.ar.auth.invitationsTitle }) as HTMLTableElement
  const action = table.rows[1].lastElementChild!
  expect(getComputedStyle(action).position).toBe('sticky'); expect(parseInt(getComputedStyle(action).insetInlineEnd)).toBe(0)
})

it('restores unsaved input after route content unmounts without browser storage or automatic writes', async () => {
  const { fetcher, hide, show } = setup(); await add(); fill()
  hide(); expect(screen.queryByRole('dialog')).toBeNull(); show(); await screen.findByRole('dialog')
  expect((within(dialog()).getByLabelText(en.email + ' *') as HTMLInputElement).value).toBe('Employee+tag@EXAMPLE.TEST')
  expect((within(dialog()).getByLabelText(en.accessReason + ' *') as HTMLInputElement).value).toBe('Approved employee onboarding')
  expect(writes(fetcher)).toHaveLength(0); expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0)
})
it('requires inspection after navigating away during a pending write', async () => {
  const { fetcher, hide, show } = setup(); await add(); fill()
  const original = fetcher.getMockImplementation()!
  let release!: () => void
  const pending = new Promise<void>((resolve) => { release = resolve })
  fetcher.mockImplementation(async (path, init) => { if (init?.method === 'POST') await pending; return original(path, init) })
  await userEvent.click(submit()); expect(writes(fetcher)).toHaveLength(1)
  hide(); show(); await within(dialog()).findByText(en.invitationUncertain)
  expect((submit() as HTMLButtonElement).disabled).toBe(true)
  await act(async () => { release(); await pending })
  expect(writes(fetcher)).toHaveLength(1); expect((submit() as HTMLButtonElement).disabled).toBe(true)
})
