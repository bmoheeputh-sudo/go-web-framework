import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { I18nextProvider } from 'react-i18next'
import App from '../App'
import LanguageProvider from '../LanguageProvider'
import { createI18n, resources } from '../i18n'
import { bob, mockAPI, mockMedia } from '../test/fixtures'
import { authSettingsPath as settings, authStatusPath as statusPath } from '../api/authConfiguration'
import type { AuthProvider, AuthRevision } from '../api/authConfiguration'

beforeEach(() => { mockMedia(); localStorage.clear(); sessionStorage.clear() })
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })
const en = resources.en.auth
const stamp = '2026-10-19T10:00:00Z'
function revision(overrides: Partial<AuthRevision> = {}): AuthRevision {
  return { id: '11111111-1111-4111-8111-111111111111', deployment_id: 'local-dev', environment: 'development',
    configuration_version: 1, provider: 'oidc', issuer_url: 'https://issuer.example.test', client_id: 'test-client',
    redirect_uri: 'https://app.example.test/api/auth/callback', iap_audience: '', allow_http_development: false,
    status: 'draft', generation: 1, created_by: '22222222-2222-4222-8222-222222222222', created_at: stamp,
    updated_by: '22222222-2222-4222-8222-222222222222', updated_at: stamp, validation: {}, has_secret: true, ...overrides }
}
function authAPI(initial: AuthRevision[] = [], runtime: AuthProvider = 'local_dev') {
  const fixture = mockAPI({ provider: runtime })
  const records = structuredClone(initial)
  const original = fixture.fetcher.getMockImplementation()!
  const failures = new Map<string, number>()
  fixture.fetcher.mockImplementation(async (path, init) => {
    const method = init?.method || 'GET'
    if (path === '/api/admin/permissions') return Response.json({ revision: 'a'.repeat(64), roles: ['Admin', 'User', 'Viewer'], permissions: [] })
    if (!path.startsWith('/api/admin/auth/')) return original(path, init)
    const failure = failures.get(`${method} ${path}`)
    if (failure) return Response.json({ error: 'UNTRUSTED SERVER DETAILS' }, { status: failure })
    if (path === statusPath) return Response.json({ runtime_provider: runtime, runtime_source: 'environment', management_only: true,
      validation_mode: 'offline_static', latest_revision: records[0] || null, database_active_revision: records.find((r) => r.status === 'active') || null })
    if (path.startsWith(settings + '?')) {
      const url = new URL(path, 'http://localhost'), before = Number(url.searchParams.get('before_version'))
      const list = records.filter((r) => !before || r.configuration_version < before).slice(0, 20)
      return Response.json({ revisions: list, next_before_version: list.length === 20 ? list.at(-1)!.configuration_version : 0 })
    }
    if (path === settings && method === 'POST') {
      const body = JSON.parse(init!.body as string)
      if (body.expected_latest_version !== (records[0]?.configuration_version || 0)) return Response.json({}, { status: 409 })
      const r = revision({ id: '33333333-3333-4333-8333-333333333333', configuration_version: body.expected_latest_version + 1,
        provider: body.provider, issuer_url: body.issuer_url || '', client_id: body.client_id || '', redirect_uri: body.redirect_uri || '',
        iap_audience: body.iap_audience || '', allow_http_development: body.allow_http_development || false, has_secret: Boolean(body.client_secret) })
      records.unshift(r)
      return Response.json(r, { status: 201 })
    }
    const [, , , , , id, action] = path.split('/')
    const r = records.find((r) => r.id === id)
    if (r && method === 'GET' && !action) return Response.json(r)
    if (r && method === 'POST' && ['validate', 'approve'].includes(action)) {
      const body = JSON.parse(init!.body as string)
      if (body.expected_generation !== r.generation) return Response.json({}, { status: 409 })
      r.generation++
      r.status = action === 'validate' ? 'validated' : 'approved'
      if (action === 'validate') { r.validated_at = stamp; r.validation = { check: 'static', version: 1 } }
      else r.approved_at = stamp
      return Response.json(r)
    }
    throw new Error(`Unexpected authentication management request: ${method} ${path}`)
  })
  return { ...fixture, records, failures }
}
function mount() {
  const instance = createI18n('en')
  render(<I18nextProvider i18n={instance}><LanguageProvider><MemoryRouter initialEntries={['/settings']}><App /></MemoryRouter></LanguageProvider></I18nextProvider>)
  return instance
}
async function openAuth() {
  await userEvent.click(await screen.findByRole('tab', { name: en.title }))
  await screen.findByRole('heading', { name: en.runtimeTitle })
  await waitFor(() => expect(screen.queryByRole('progressbar')).toBeNull())
}
const writes = (fetcher: ReturnType<typeof mockAPI>['fetcher']) => fetcher.mock.calls.filter(([path, init]) => path.startsWith('/api/admin/auth/') && init?.method === 'POST')
async function fillOIDC(secret = 'synthetic-test-secret') {
  fireEvent.change(screen.getByLabelText(en.issuerURL + ' *'), { target: { value: 'https://issuer.example.test' } })
  fireEvent.change(screen.getByLabelText(en.clientID + ' *'), { target: { value: 'test-client' } })
  fireEvent.change(screen.getByLabelText(en.clientSecret + ' *'), { target: { value: secret } })
  fireEvent.change(screen.getByLabelText(en.redirectURI + ' *'), { target: { value: 'https://app.example.test/api/auth/callback' } })
}
async function chooseProvider(name: string) {
  await userEvent.click(screen.getByRole('combobox', { name: en.provider }))
  await userEvent.click(screen.getByRole('option', { name }))
}
async function view(version = 1) {
  await userEvent.click(await screen.findByRole('button', { name: `View revision ${version}` }))
  return await screen.findByRole('region', { name: en.revisionMetadata })
}

it('keeps runtime environment authentication separate from approved and database-active revisions', async () => {
  const approved = revision({ status: 'approved', configuration_version: 2, approved_at: stamp })
  const active = revision({ id: '44444444-4444-4444-8444-444444444444', provider: 'google_iap', status: 'active', has_secret: false })
  const { fetcher } = authAPI([approved, active]); mount(); await openAuth()
  const runtime = screen.getByRole('region', { name: en.runtimeTitle })
  expect(runtime.textContent).toContain('Current runtime provider: local_dev')
  expect(runtime.textContent).toContain('Latest database revision: Revision 2 · oidc · Approved')
  expect(runtime.textContent).toContain('Database active revision (separate from runtime): Revision 1 · google_iap · Active in database')
  expect(within(runtime).getByText(en.managementOnly)).toBeTruthy()
  expect(runtime.textContent).toContain(en.sourceEnvironment)
  expect(runtime.textContent).toContain(en.offlineValidation)
  const detail = await view(2)
  expect(detail.textContent).toContain(approved.created_by)
  expect(detail.textContent).toContain(en.secretPresent)
  expect(screen.queryByRole('button', { name: en.approveRevision })).toBeNull()
  expect(fetcher.mock.calls.some(([path]) => path === `${settings}/${approved.id}`)).toBe(true)
  expect(fetcher.mock.calls.filter(([path]) => path.startsWith(statusPath)).every(([path]) => path === statusPath)).toBe(true)
})

it('shows empty history and future capability explanations without nonfunctional controls', async () => {
  const { fetcher } = authAPI(); mount(); await openAuth()
  expect(screen.getByText(en.emptyHistory)).toBeTruthy()
  expect(screen.getByText((text) => text.includes(en.futureCapabilities))).toBeTruthy()
  expect(screen.queryByRole('button', { name: /activate|test connection|rollback/i })).toBeNull()
  expect(writes(fetcher)).toHaveLength(0)
})

it('requires complete OIDC settings and a fresh secret; clears secrets after submission and never persists them', async () => {
  const { fetcher, records } = authAPI(); mount(); await openAuth()
  await userEvent.click(screen.getByRole('button', { name: en.createDraft }))
  expect(writes(fetcher)).toHaveLength(0)
  await fillOIDC('synthetic-secret-not-real')
  const secret = screen.getByLabelText(en.clientSecret + ' *') as HTMLInputElement
  expect(secret.type).toBe('password')
  await userEvent.click(screen.getByRole('button', { name: en.showSecret }))
  expect(secret.type).toBe('text')
  await userEvent.click(screen.getByRole('button', { name: en.hideSecret }))
  expect(secret.type).toBe('password')
  await userEvent.click(screen.getByRole('button', { name: en.createDraft }))
  const toast = await screen.findByRole('status')
  expect(toast.textContent).toContain(en.draftCreated)
  expect(writes(fetcher)).toHaveLength(1)
  expect(JSON.parse(writes(fetcher)[0][1]!.body as string)).toEqual({ expected_latest_version: 0, provider: 'oidc', issuer_url: 'https://issuer.example.test', client_id: 'test-client', client_secret: 'synthetic-secret-not-real', redirect_uri: 'https://app.example.test/api/auth/callback', allow_http_development: false })
  expect((screen.getByLabelText(en.clientSecret + ' *') as HTMLInputElement).value).toBe('')
  expect(JSON.stringify(records)).not.toContain('synthetic-secret-not-real')
  expect(JSON.stringify(localStorage) + JSON.stringify(sessionStorage) + document.body.innerHTML).not.toContain('synthetic-secret-not-real')
  await userEvent.click(within(toast).getByRole('button', { name: 'Close' }))
  await waitFor(() => expect(screen.queryByRole('status')).toBeNull())
  await fillOIDC('')
  await userEvent.click(screen.getByRole('button', { name: en.createDraft }))
  expect(writes(fetcher)).toHaveLength(1)
})

it.each(['http://issuer.example.test', 'https://user:password@issuer.test'])('rejects invalid OIDC issuer %s without sending a secret', async (issuer) => {
  const { fetcher } = authAPI(); mount(); await openAuth(); await fillOIDC()
  fireEvent.change(screen.getByLabelText(en.issuerURL + ' *'), { target: { value: issuer } })
  await userEvent.click(screen.getByRole('button', { name: en.createDraft }))
  expect(writes(fetcher)).toHaveLength(0)
})

it('permits HTTP callbacks only with explicit development allowance and a loopback address', async () => {
  const { fetcher } = authAPI(); mount(); await openAuth(); await fillOIDC()
  const redirect = screen.getByLabelText(en.redirectURI + ' *')
  fireEvent.change(redirect, { target: { value: 'http://localhost:8080/api/auth/callback' } })
  await userEvent.click(screen.getByRole('button', { name: en.createDraft })); expect(writes(fetcher)).toHaveLength(0)
  await userEvent.click(screen.getByRole('checkbox', { name: en.allowHTTP }))
  fireEvent.change(redirect, { target: { value: 'http://app.example.test/api/auth/callback' } })
  await userEvent.click(screen.getByRole('button', { name: en.createDraft })); expect(writes(fetcher)).toHaveLength(0)
  fireEvent.change(redirect, { target: { value: 'http://localhost:8080/api/auth/callback' } })
  await userEvent.click(screen.getByRole('button', { name: en.createDraft })); await screen.findByRole('status')
  expect(JSON.parse(writes(fetcher)[0][1]!.body as string).allow_http_development).toBe(true)
})

it('validates IAP audiences and sends only provider-specific settings', async () => {
  const { fetcher } = authAPI(); mount(); await openAuth(); await fillOIDC()
  await chooseProvider(en.providerIap)
  expect(screen.getByText(en.iapHelp)).toBeTruthy()
  fireEvent.change(screen.getByLabelText(en.iapAudience + ' *'), { target: { value: 'https://wrong.example.test' } })
  await userEvent.click(screen.getByRole('button', { name: en.createDraft })); expect(writes(fetcher)).toHaveLength(0)
  fireEvent.change(screen.getByLabelText(en.iapAudience + ' *'), { target: { value: '/projects/123/global/backendServices/456' } })
  await userEvent.click(screen.getByRole('button', { name: en.createDraft })); await screen.findByRole('status')
  expect(JSON.parse(writes(fetcher)[0][1]!.body as string)).toEqual({ provider: 'google_iap', iap_audience: '/projects/123/global/backendServices/456', expected_latest_version: 0 })
})

it('allows Local DEV only when development is confirmed and explains that it never changes runtime', async () => {
  const { fetcher } = authAPI(); mount(); await openAuth(); await chooseProvider(en.providerLocal)
  expect(screen.getByText(en.localHelp)).toBeTruthy()
  await userEvent.click(screen.getByRole('button', { name: en.createDraft })); await screen.findByRole('status')
  expect(JSON.parse(writes(fetcher)[0][1]!.body as string)).toEqual({ provider: 'local_dev', expected_latest_version: 0 })
})

it.each(['production', 'test', 'unknown'] as const)('disables development-only options for %s environments', async (environment) => {
  authAPI(environment === 'unknown' ? [] : [revision({ environment })], 'oidc'); mount(); await openAuth()
  expect(screen.queryByRole('checkbox', { name: en.allowHTTP })).toBeNull()
  expect(screen.getByText(en.developmentUnavailable)).toBeTruthy()
  await userEvent.click(screen.getByRole('combobox', { name: en.provider }))
  expect(screen.getByRole('option', { name: en.providerLocal }).getAttribute('aria-disabled')).toBe('true')
})

it('validates offline using the current generation, then requires explicit confirmation for approval', async () => {
  const { fetcher, records } = authAPI([revision()]); mount(); await openAuth(); await view()
  expect(screen.queryByRole('button', { name: en.approveRevision })).toBeNull()
  await userEvent.click(screen.getByRole('button', { name: en.validateSettings }))
  const toast = await screen.findByRole('status'); expect(toast.textContent).toContain(en.validationSaved)
  expect(JSON.parse(writes(fetcher)[0][1]!.body as string)).toEqual({ expected_generation: 1 })
  await userEvent.click(within(toast).getByRole('button', { name: 'Close' }))
  await userEvent.click(await screen.findByRole('button', { name: en.approveRevision }))
  expect(writes(fetcher)).toHaveLength(1)
  expect(within(screen.getByRole('dialog')).getByText(en.approveHelp)).toBeTruthy()
  await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  expect(writes(fetcher)).toHaveLength(1)
  await userEvent.click(screen.getByRole('button', { name: en.approveRevision }))
  await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Confirm' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  expect((await screen.findByRole('status')).textContent).toContain(en.approvalSaved)
  expect(JSON.parse(writes(fetcher)[1][1]!.body as string)).toEqual({ expected_generation: 2 })
  expect(records[0].status).toBe('approved')
  expect(writes(fetcher).map(([path]) => path)).toEqual([`${settings}/${records[0].id}/validate`, `${settings}/${records[0].id}/approve`])
  expect(fetcher.mock.calls.every(([path]) => !/\/test(?:\?|$)|\/activate|\/rollback/.test(path))).toBe(true)
})

it.each(['draft', 'validate', 'approve'])('refreshes metadata after a %s conflict without retrying the write', async (operation) => {
  const { fetcher, records } = authAPI([revision({ status: operation === 'approve' ? 'validated' : 'draft' })]); mount(); await openAuth()
  if (operation === 'draft') {
    await fillOIDC(); records[0].configuration_version = 2
    await userEvent.click(screen.getByRole('button', { name: en.createDraft }))
  } else {
    await view(); records[0].generation = 9
    await userEvent.click(screen.getByRole('button', { name: operation === 'validate' ? en.validateSettings : en.approveRevision }))
    if (operation === 'approve') await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Confirm' }))
  }
  await waitFor(() => expect(screen.getAllByText(en.revisionConflict).length).toBe(2)) // inline + one shared Snackbar
  expect(writes(fetcher)).toHaveLength(1)
  await waitFor(() => expect(fetcher.mock.calls.filter(([path]) => path === statusPath).length).toBe(2))
  if (operation !== 'draft') expect(fetcher.mock.calls.filter(([path, init]) => path === `${settings}/${records[0].id}` && init?.method === 'GET')).toHaveLength(2)
  expect(document.body.textContent).not.toContain('UNTRUSTED SERVER DETAILS')
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
})

it('reports unavailable management service with one localized dismissible Snackbar and no raw errors', async () => {
  const { failures } = authAPI(); failures.set(`GET ${statusPath}`, 503); mount()
  await userEvent.click(await screen.findByRole('tab', { name: en.title }))
  await waitFor(() => expect(screen.getAllByText(en.settingsUnavailable)).toHaveLength(2))
  expect(screen.queryByRole('button', { name: en.createDraft })).toBeNull()
  const toast = screen.getAllByRole('alert').find((alert) => within(alert).queryByRole('button', { name: 'Close' }))!
  await userEvent.click(within(toast).getByRole('button', { name: 'Close' }))
  await waitFor(() => expect(screen.getAllByText(en.settingsUnavailable)).toHaveLength(1))
  expect(document.body.textContent).not.toContain('UNTRUSTED SERVER DETAILS')
})

it('pages revision history with the server cursor and fetches selected historical metadata', async () => {
  const records = Array.from({ length: 21 }, (_, i) => revision({ id: `revision-${21 - i}`, configuration_version: 21 - i }))
  const { fetcher } = authAPI(records); mount(); await openAuth()
  await userEvent.click(screen.getByRole('button', { name: 'Next page' }))
  await view(1)
  expect(fetcher.mock.calls.some(([path]) => path === `${settings}?limit=20&before_version=2`)).toBe(true)
  expect(fetcher.mock.calls.some(([path]) => path === `${settings}/revision-1`)).toBe(true)
  await userEvent.click(screen.getByRole('button', { name: 'Previous page' }))
  expect(await screen.findByRole('button', { name: 'View revision 21' })).toBeTruthy()
})

it('preserves form edits across Arabic/mobile/theme rendering without refetching, and discards secrets when leaving the tab', async () => {
  mockMedia(false); const { fetcher } = authAPI(); const instance = mount(); await openAuth(); await fillOIDC()
  const calls = fetcher.mock.calls.length
  await act(async () => { await instance.changeLanguage('ar') })
  expect(document.documentElement.dir).toBe('rtl')
  expect((screen.getByLabelText(resources.ar.auth.clientID + ' *') as HTMLInputElement).value).toBe('test-client')
  expect(fetcher.mock.calls).toHaveLength(calls)
  const history = screen.getByRole('region', { name: resources.ar.auth.history })
  expect(getComputedStyle(history).overflowX).toBe('auto')
  await userEvent.click(screen.getByRole('tab', { name: resources.ar.admin.rolesPermissions }))
  await userEvent.click(screen.getByRole('tab', { name: resources.ar.auth.title }))
  expect((screen.getByLabelText(resources.ar.auth.clientSecret + ' *') as HTMLInputElement).value).toBe('')
})

it.each(['User', 'Viewer', 'unauthenticated'])('blocks %s without requesting authentication management APIs', async (role) => {
  const { fetcher } = mockAPI(role === 'unauthenticated' ? { authenticated: false } : { user: { ...bob, roles: [role] } }); mount()
  if (role === 'unauthenticated') await screen.findByRole('link', { name: 'Sign in' })
  else await screen.findByRole('heading', { name: 'Access denied' })
  expect(screen.queryByRole('tab', { name: en.title })).toBeNull()
  expect(fetcher.mock.calls.some(([path]) => path.startsWith('/api/admin/auth/'))).toBe(false)
})

it.each([400, 403, 503])('handles draft failure HTTP %s without leaking the submitted secret or server message', async (status) => {
  const { failures, fetcher } = authAPI(); failures.set(`POST ${settings}`, status)
  mount(); await openAuth(); await fillOIDC('synthetic-failed-secret')
  await userEvent.click(screen.getByRole('button', { name: en.createDraft }))
  const message = status === 400 ? resources.en.admin.errorInvalid : status === 403 ? resources.en.admin.errorForbidden : en.settingsUnavailable
  await waitFor(() => expect(screen.getAllByText(message)).toHaveLength(2))
  expect(writes(fetcher)).toHaveLength(1)
  expect((screen.getByLabelText(en.clientSecret + ' *') as HTMLInputElement).value).toBe('')
  expect(document.body.innerHTML).not.toContain('synthetic-failed-secret')
  expect(document.body.textContent).not.toContain('UNTRUSTED SERVER DETAILS')
})

it('uses theme paper colors in dark mode and supports keyboard tab navigation', async () => {
  localStorage.setItem('gwf.appearance', 'dark')
  authAPI(); mount(); await openAuth()
  const panel = screen.getByRole('region', { name: en.runtimeTitle })
  expect(getComputedStyle(panel).backgroundColor).toBe('rgb(18, 18, 18)')
  const tab = screen.getByRole('tab', { name: en.title })
  act(() => tab.focus())
  await userEvent.keyboard('{ArrowLeft}{Enter}')
  expect(screen.getByRole('tab', { name: resources.en.admin.rolesPermissions }).getAttribute('aria-selected')).toBe('true')
  await userEvent.keyboard('{ArrowRight}{Enter}')
  expect(screen.getByRole('tab', { name: en.title }).getAttribute('aria-selected')).toBe('true')
})
