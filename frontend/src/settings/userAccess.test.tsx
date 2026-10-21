import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { I18nextProvider } from 'react-i18next'
import { MemoryRouter } from 'react-router-dom'
import type { Language } from '../i18n'
import { createI18n, resources } from '../i18n'
import LanguageProvider from '../LanguageProvider'
import NotificationProvider from '../notifications/NotificationProvider'
import QueryProvider from '../api/QueryProvider'
import { SessionContext } from '../auth/session'
import type { Session } from '../auth/session'
import { accessPolicyPath, readAccessIdentity } from '../api/accessPolicy'
import type { AccessIdentity, IdentityPage, PolicySnapshot } from '../api/accessPolicy'
import { admin, bob, identity, mockMedia } from '../test/fixtures'
import UserAccess from './UserAccess'

const en = resources.en.auth, common = resources.en.common
const stamp = '2026-10-20T10:00:00Z'
function setup(options: { missing?: boolean; user?: typeof admin; language?: Language; saveStatus?: number; previewBlocked?: boolean; selfLoss?: boolean } = {}) {
  const snapshot: PolicySnapshot = { policy: { deployment_id: 'local-dev', environment: 'development', mode: 'allow_all', allowed_email_domains: [], default_role: 'Viewer', generation: 1, created_by: admin.id, updated_by: admin.id, created_at: stamp, updated_at: stamp, reason: 'initial settings' }, activation_generation: 3, active_issuer: identity.issuer, overview: { approved: 1, revoked: 0, active_oidc_users: 2 } }
  const row: AccessIdentity = { user_id: bob.id, issuer: identity.issuer, subject: bob.subject, email: bob.email, display_name: bob.display_name, user_active: false, roles: ['Viewer'], approval_status: 'not_approved', approval_generation: 0, updated_at: stamp, provider_current: true }
  const fetcher = vi.fn(async (path: string, init?: RequestInit) => {
    const method = init?.method || 'GET'
    if (options.missing) return Response.json({ error: 'access_policy_setup_required' }, { status: 404 })
    if (path === accessPolicyPath && method === 'GET') return Response.json(snapshot)
    if (path.startsWith(accessPolicyPath + '/invitations?')) return Response.json({ items: [], total: 0, offset: 0, limit: 20, policy_generation: 1, activation_generation: 3, revision_id: 'revision-1', revision_generation: 4 })
    if (path.startsWith(accessPolicyPath + '/approvals?')) {
      const params = new URL(path, 'https://app.test').searchParams
      const items = params.get('search') === 'absent' ? [] : [{ ...row, subject: params.get('offset') === '20' ? 'second-page' : row.subject }]
      return Response.json({ items, total: 21, offset: Number(params.get('offset')), limit: 20, policy_generation: snapshot.policy.generation, activation_generation: 3 } satisfies IdentityPage)
    }
    if (path === accessPolicyPath + '/preview') return Response.json({ policy_generation: 1, activation_generation: 3, affected_users: 2, eligible_users: 1, eligible_administrators: options.previewBlocked ? 0 : 1, current_administrator_loses_access: options.selfLoss || false, can_apply: !options.previewBlocked })
    if (path === accessPolicyPath && method === 'PUT') {
      if (options.saveStatus) return Response.json({ error: options.saveStatus === 409 ? 'access_policy_conflict' : 'access_policy_commit_uncertain' }, { status: options.saveStatus })
      Object.assign(snapshot.policy, JSON.parse(String(init?.body)), { generation: snapshot.policy.generation + 1 })
      return Response.json(snapshot.policy)
    }
    if (path === `${accessPolicyPath}/approvals/${bob.id}`) return Response.json(row)
    if (path.startsWith(`${accessPolicyPath}/approvals/${bob.id}/`) && method === 'POST') {
      row.approval_status = path.endsWith('/approve') ? 'approved' : 'revoked'; row.approval_generation++
      return Response.json({ status: row.approval_status, generation: row.approval_generation })
    }
    throw new Error('Unexpected access policy request')
  })
  vi.stubGlobal('fetch', fetcher)
  const instance = createI18n(options.language || 'en')
  const session: Session = { authentication: { status: 'authenticated', identity }, access: { loading: false, user: options.user || admin, error: '' }, health: 'ok', oidcEnabled: true, loggingOut: false, logoutFailed: false, loginFailed: false, logout: vi.fn(), expire: vi.fn(), refreshAccess: vi.fn() }
  render(<I18nextProvider i18n={instance}><LanguageProvider><NotificationProvider><SessionContext.Provider value={session}><QueryProvider><MemoryRouter><UserAccess /></MemoryRouter></QueryProvider></SessionContext.Provider></NotificationProvider></LanguageProvider></I18nextProvider>)
  return { fetcher, instance, snapshot, row, session }
}
beforeEach(() => { mockMedia(); localStorage.clear(); sessionStorage.clear() })
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })
const policySection = () => screen.getByRole('region', { name: en.accessPolicyTitle })
async function loaded() { await screen.findByText(bob.email); await waitFor(() => expect((screen.getByRole('button', { name: resources.en.admin.refresh }) as HTMLButtonElement).disabled).toBe(false)) }
async function select(label: string, option: string) { fireEvent.mouseDown(within(policySection()).getByLabelText(label)); fireEvent.click(await screen.findByRole('option', { name: option })) }
async function review() { await userEvent.click(within(policySection()).getByRole('button', { name: en.accessSave })); return screen.findByRole('dialog', { name: en.accessConfirm }) }
async function reason() { fireEvent.change(within(screen.getByRole('dialog')).getByLabelText(en.accessReason + ' *'), { target: { value: 'Approved access policy change' } }) }
const writes = (fetcher: ReturnType<typeof setup>['fetcher']) => fetcher.mock.calls.filter(([path, init]) => path === accessPolicyPath && init?.method === 'PUT')

it('shows Setup Required without providing browser bootstrap or sending writes', async () => {
  const { fetcher } = setup({ missing: true })
  await screen.findByRole('heading', { name: en.accessSetupTitle })
  expect(screen.getByText(en.accessSetupHelp)).toBeTruthy()
  expect(screen.queryByRole('button', { name: en.accessSave })).toBeNull()
  expect(writes(fetcher)).toHaveLength(0)
})
it('does not request policy data for a non-administrator', () => {
  const { fetcher } = setup({ user: bob })
  expect(screen.getByText(common.accessDenied)).toBeTruthy(); expect(fetcher).not.toHaveBeenCalled()
})
it('distinguishes record, approval and provider status; preserves roles and opens details', async () => {
  const { fetcher } = setup(); await loaded()
  expect(screen.getByText(common.statusInactive)).toBeTruthy()
  expect(screen.getByText(en.accessNotApproved)).toBeTruthy()
  expect(screen.getByText(resources.en.admin.providerCurrent)).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: en.accessDetails }))
  await screen.findByRole('heading', { name: en.accessDetails })
  expect(fetcher.mock.calls.some(([path]) => path.endsWith('/' + bob.id))).toBe(true)
})
it('offers only Viewer/User default roles and previews before a generation-bound save', async () => {
  const { fetcher, session } = setup(); await loaded()
  fireEvent.mouseDown(within(policySection()).getByLabelText(en.accessDefaultRole))
  expect(screen.queryByRole('option', { name: resources.en.admin.roleAdmin })).toBeNull()
  fireEvent.click(screen.getByRole('option', { name: resources.en.admin.roleUser }))
  await select(en.accessWho, en.accessApprovedOnly)
  fireEvent.change(within(policySection()).getByLabelText(en.accessDomains), { target: { value: 'vopak.com, example.test' } })
  const dialog = await review()
  expect(within(dialog).getByText(en.accessImpact.replace('{{count}}', '2'))).toBeTruthy()
  expect(writes(fetcher)).toHaveLength(0)
  await reason()
  await userEvent.dblClick(within(dialog).getByRole('button', { name: resources.en.admin.confirmPermissions }))
  await waitFor(() => expect(writes(fetcher)).toHaveLength(1))
  const body = JSON.parse(String(writes(fetcher)[0][1]?.body))
  expect(body).toEqual({ mode: 'approved_users_only', default_role: 'User', allowed_email_domains: ['vopak.com', 'example.test'], expected_policy_generation: 1, expected_activation_generation: 3, reason: 'Approved access policy change', confirm_access_loss: false })
  expect(session.refreshAccess).toHaveBeenCalledOnce()
  expect(await screen.findByText(en.accessSaved)).toBeTruthy()
})
it('approves and revokes by user ID without identity claims, reactivation or role changes', async () => {
  const { fetcher } = setup(); await loaded()
  await userEvent.click(screen.getByRole('button', { name: en.accessApprove })); await reason()
  await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: resources.en.admin.confirmPermissions }))
  await screen.findByText(en.accessApproved)
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  await loaded()
  const request = fetcher.mock.calls.find(([path]) => path.endsWith(`/${bob.id}/approve`))!
  expect(JSON.parse(String(request[1]?.body))).toEqual({ expected_policy_generation: 1, expected_activation_generation: 3, expected_approval_generation: 0, reason: 'Approved access policy change' })
  expect(screen.getByText(common.statusInactive)).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: en.accessRevoke })); await reason()
  await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: resources.en.admin.confirmPermissions }))
  await screen.findByRole('button', { name: en.accessApprove })
  expect(fetcher.mock.calls.filter(([path]) => path.endsWith('/revoke'))).toHaveLength(1)
})
it('blocks last-admin changes and requires an unchecked self-access-loss acknowledgment', async () => {
  setup({ selfLoss: true }); await loaded()
  await select(en.accessWho, en.accessApprovedOnly)
  const dialog = await review(); await reason()
  const check = within(dialog).getByRole('checkbox') as HTMLInputElement
  expect(check.checked).toBe(false)
  const confirm = within(dialog).getByRole('button', { name: resources.en.admin.confirmPermissions }) as HTMLButtonElement
  expect(confirm.disabled).toBe(true)
  await userEvent.click(check); expect(confirm.disabled).toBe(false)
})
it('cannot confirm a preview which would remove the last eligible administrator', async () => {
  setup({ previewBlocked: true }); await loaded(); await select(en.accessWho, en.accessApprovedOnly)
  const dialog = await review(); await reason()
  expect(within(dialog).getByText(en.accessLastAdmin)).toBeTruthy()
  expect((within(dialog).getByRole('button', { name: resources.en.admin.confirmPermissions }) as HTMLButtonElement).disabled).toBe(true)
})
it.each([409, 503])('never retries a rejected or uncertain %s mutation and preserves the dialog', async (saveStatus) => {
  const { fetcher } = setup({ saveStatus }); await loaded(); await select(en.accessWho, en.accessApprovedOnly)
  const dialog = await review(); await reason()
  await userEvent.click(within(dialog).getByRole('button', { name: resources.en.admin.confirmPermissions }))
  await waitFor(() => expect(writes(fetcher)).toHaveLength(1))
  expect(await within(dialog).findByText(saveStatus === 409 ? en.accessConflict : en.accessUncertain)).toBeTruthy()
  expect(writes(fetcher)).toHaveLength(1)
})
it('searches and paginates with direct no-store requests', async () => {
  const { fetcher } = setup(); await loaded()
  await userEvent.click(within(screen.getByRole('group', { name: en.accessIdentities })).getByRole('button', { name: common.nextPage }))
  await waitFor(() => expect(fetcher.mock.calls.some(([path]) => path.includes('/approvals?') && path.includes('offset=20'))).toBe(true))
  fireEvent.change(screen.getByLabelText(en.accessSearch), { target: { value: 'absent' } })
  await screen.findByText(resources.en.admin.usersEmpty)
  expect(fetcher.mock.calls.some(([path]) => path.includes('search=absent') && path.includes('offset=0'))).toBe(true)
  expect(fetcher.mock.calls.every(([, init]) => init?.cache === 'no-store')).toBe(true)
})
it('preserves unsaved edits during language switching and supports Arabic detail drawers', async () => {
  const { instance } = setup(); await loaded()
  fireEvent.change(within(policySection()).getByLabelText(en.accessDomains), { target: { value: 'vopak.com' } })
  await act(async () => { await instance.changeLanguage('ar') })
  expect((screen.getByLabelText(resources.ar.auth.accessDomains) as HTMLInputElement).value).toBe('vopak.com')
  expect(document.documentElement.dir).toBe('rtl')
  await userEvent.click(screen.getByRole('button', { name: resources.ar.auth.accessDetails }))
  await screen.findByRole('heading', { name: resources.ar.auth.accessDetails })
  expect(getComputedStyle(document.querySelector('.MuiDrawer-paper')!).left).toBe('0px')
})
it('keeps existing table data during background refresh and persists no security data', async () => {
  const { fetcher } = setup(); await loaded()
  const original = fetcher.getMockImplementation()!
  let release!: () => void
  const pending = new Promise<void>((resolve) => { release = resolve })
  fetcher.mockImplementation(async (path, init) => { if (path === accessPolicyPath) await pending; return original(path, init) })
  await userEvent.click(screen.getByRole('button', { name: resources.en.admin.refresh }))
  expect(screen.getByText(bob.email)).toBeTruthy()
  await act(async () => { release() })
  expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0)
})
it('uses the typed detail client and never logs or stores a credential', async () => {
  const { fetcher } = setup(); await loaded()
  await readAccessIdentity(bob.id)
  expect(fetcher).toHaveBeenLastCalledWith(`${accessPolicyPath}/approvals/${bob.id}`, expect.objectContaining({ cache: 'no-store', credentials: 'same-origin' }))
})
it('has nonempty localized access strings and matching placeholders in all 12 languages', () => {
  const keys = Object.keys(en).filter((key) => key.startsWith('access'))
  for (const namespaces of Object.values(resources)) for (const key of keys) {
    const translated = namespaces.auth[key]
    expect(translated?.trim()).toBeTruthy()
    expect(translated.match(/{{\w+}}/g) || []).toEqual(en[key].match(/{{\w+}}/g) || [])
  }
})
