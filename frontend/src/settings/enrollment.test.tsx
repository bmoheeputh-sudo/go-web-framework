import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { I18nextProvider } from 'react-i18next'
import { createI18n, resources } from '../i18n'
import LanguageProvider from '../LanguageProvider'
import NotificationProvider from '../notifications/NotificationProvider'
import QueryProvider from '../api/QueryProvider'
import { SessionContext } from '../auth/session'
import type { Session } from '../auth/session'
import type { AuthRevision, ConnectionTest } from '../api/authConfiguration'
import { admin, bob, identity, mockMedia } from '../test/fixtures'
import IdentityEnrollment from './IdentityEnrollment'

const en = resources.en.auth
const revision: AuthRevision = {
  id: 'revision-1', configuration_version: 7, generation: 3, status: 'approved', provider: 'oidc',
  issuer_url: 'https://issuer.test', client_id: 'public-client', redirect_uri: 'https://app.test/api/auth/callback',
  iap_audience: '', allow_http_development: false, deployment_id: 'local-dev', environment: 'development',
  created_by: 'admin-1', created_at: '', updated_by: 'admin-1', updated_at: '', validation: {}, has_secret: true,
}
beforeEach(() => { mockMedia(); localStorage.clear(); vi.useFakeTimers() })
afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals() })
function setup(options: { status?: number; user?: typeof admin; authenticated?: boolean; result?: Partial<ConnectionTest>; revision?: Partial<AuthRevision> } = {}) {
  const fetcher = vi.fn(async () => Response.json(options.status ? { error: 'PRIVATE INTERNAL DETAILS' } : { id: 'new-user' }, { status: options.status || 200 }))
  vi.stubGlobal('fetch', fetcher)
  const instance = createI18n('en')
  const result: ConnectionTest = { id: 'test-1', status: 'succeeded', revision_id: revision.id, generation: revision.generation,
    configuration_version: 7, callback_uri: 'https://app.test/api/auth/test/callback', expires_at: new Date(Date.now() + 300_000).toISOString(),
    tested_identity: { ...identity, subject: 'verified-subject' }, evidence_id: 'server-evidence', evidence_expires_at: new Date(Date.now() + 60_000).toISOString(), ...options.result }
  const session: Session = { authentication: options.authenticated === false ? { status: 'unauthenticated' } : { status: 'authenticated', identity },
    access: { loading: false, user: options.user || admin, error: '' }, health: 'ok', oidcEnabled: false, loggingOut: false, logoutFailed: false,
    loginFailed: false, logout: vi.fn(), expire: vi.fn(), refreshAccess: vi.fn() }
  render(<I18nextProvider i18n={instance}><LanguageProvider><NotificationProvider><SessionContext.Provider value={session}><QueryProvider>
    <IdentityEnrollment revision={{ ...revision, ...options.revision }} result={result} disabled={false} />
  </QueryProvider></SessionContext.Provider></NotificationProvider></LanguageProvider></I18nextProvider>)
  return { fetcher, instance, session }
}
async function selectRole(role: string) {
  await act(async () => { fireEvent.mouseDown(screen.getByRole('combobox')) })
  await act(async () => { fireEvent.click(screen.getByRole('option', { name: role })) })
}
async function openConfirmation() { await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.enrollIdentity })) }) }
async function confirm() {
  await act(async () => { fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: en.enrollIdentity })) })
  await act(async () => { await vi.advanceTimersByTimeAsync(250) })
}

it.each(['Admin', 'User', 'Viewer'])('requires explicit selection and confirmation for %s; submits no identity fields', async (role) => {
  const { fetcher } = setup()
  expect(fetcher).not.toHaveBeenCalled()
  expect((screen.getByRole('button', { name: en.enrollIdentity }) as HTMLButtonElement).disabled).toBe(true)
  await selectRole(resources.en.admin[{ Admin: 'roleAdmin', User: 'roleUser', Viewer: 'roleViewer' }[role]!])
  await openConfirmation()
  expect(within(screen.getByRole('dialog')).getByText('verified-subject')).toBeTruthy()
  expect(within(screen.getByRole('dialog')).getByText('https://issuer.test')).toBeTruthy()
  expect(fetcher).not.toHaveBeenCalled()
  await confirm()
  expect(fetcher).toHaveBeenCalledOnce()
  const [path, init] = (fetcher.mock.calls as unknown as [string, RequestInit][])[0]
  expect(path).toBe('/api/admin/auth/settings/revision-1/enroll')
  expect(JSON.parse(init.body as string)).toEqual({ evidence_id: 'server-evidence', expected_generation: 3, role, confirm: true })
  expect(screen.getByRole('status').textContent).toContain(en.enrollmentSuccess)
  fireEvent.click(within(screen.getByRole('status')).getByRole('button', { name: 'Close' }))
  await act(async () => { await vi.advanceTimersByTimeAsync(300) })
  expect(screen.queryByRole('status')).toBeNull()
  expect((screen.getByRole('button', { name: en.enrollIdentity }) as HTMLButtonElement).disabled).toBe(true)
})
it.each([bob, { ...admin, roles: ['User'], permissions: ['accounts.read'] }, { ...admin, active: false }])('hides enrollment without active admin.manage', (user) => {
  setup({ user }); expect(screen.queryByRole('button', { name: en.enrollIdentity })).toBeNull()
})
it('hides enrollment when unauthenticated', () => { setup({ authenticated: false }); expect(screen.queryByRole('button')).toBeNull() })
it.each([{ evidence_id: undefined }, { status: 'failed' as const }, { generation: 99 }, { revision_id: 'other' }])('rejects unqualified results', (result) => {
  setup({ result }); expect(screen.queryByRole('button')).toBeNull()
})
it('does not offer enrollment for an unapproved revision', () => { setup({ revision: { status: 'draft' } }); expect(screen.queryByRole('button')).toBeNull() })
it('expires evidence while a confirmation is open and sends nothing', async () => {
  const { fetcher } = setup(); await selectRole(resources.en.admin.roleAdmin); await openConfirmation()
  await act(async () => { await vi.advanceTimersByTimeAsync(60_001) })
  expect((within(screen.getByRole('dialog')).getByRole('button', { name: en.enrollIdentity }) as HTMLButtonElement).disabled).toBe(true)
  expect(fetcher).not.toHaveBeenCalled()
})
it.each([401, 403, 409, 503])('handles HTTP %s safely', async (status) => {
  const { fetcher, session } = setup({ status }); await selectRole(resources.en.admin.roleAdmin); await openConfirmation(); await confirm()
  expect(fetcher).toHaveBeenCalledOnce()
  expect(document.body.textContent).not.toContain('PRIVATE INTERNAL DETAILS')
  expect(screen.getAllByRole('alert').some((a) => a.textContent?.includes(status === 409 ? en.enrollmentConflict : en.enrollmentFailed))).toBe(true)
  if (status === 401) expect(session.expire).toHaveBeenCalledOnce()
})
it('preserves selection in Arabic and supports cancellation without a mutation', async () => {
  const { instance, fetcher } = setup(); await selectRole(resources.en.admin.roleViewer)
  await act(async () => { await instance.changeLanguage('ar') })
  expect(document.documentElement.dir).toBe('rtl')
  expect(screen.getByRole('combobox').textContent).toContain(resources.ar.admin.roleViewer)
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: resources.ar.auth.enrollIdentity })) })
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: resources.ar.common.cancel })) })
  expect(fetcher).not.toHaveBeenCalled()
})
