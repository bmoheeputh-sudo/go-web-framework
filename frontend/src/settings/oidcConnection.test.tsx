import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { I18nextProvider } from 'react-i18next'
import LanguageProvider from '../LanguageProvider'
import { createI18n, resources } from '../i18n'
import NotificationProvider from '../notifications/NotificationProvider'
import QueryProvider from '../api/QueryProvider'
import { SessionContext } from '../auth/session'
import type { Session } from '../auth/session'
import { admin, identity, mockMedia } from '../test/fixtures'
import OIDCConnectionTest from './OIDCConnectionTest'
import type { AuthRevision, ConnectionTest } from '../api/authConfiguration'

const en = resources.en.auth
const revision: AuthRevision = {
  id: 'revision-1', configuration_version: 7, generation: 3, status: 'approved', provider: 'oidc',
  issuer_url: 'https://issuer.example.test', client_id: 'public-client', redirect_uri: 'http://localhost:8080/api/auth/callback',
  iap_audience: '', allow_http_development: true, deployment_id: 'local-dev', environment: 'development',
  created_by: 'admin-1', created_at: '', updated_by: 'admin-1', updated_at: '', validation: {}, has_secret: true,
}
beforeEach(() => { mockMedia(); localStorage.clear(); vi.useFakeTimers() })
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals() })
function setup(options: { status?: ConnectionTest['status']; blocked?: boolean; httpError?: number } = {}) {
  const popup = { closed: false, opener: window, location: { replace: vi.fn() }, close: vi.fn(() => { popup.closed = true }) }
  vi.spyOn(window, 'open').mockReturnValue(options.blocked ? null : popup as unknown as Window)
  const result: ConnectionTest = { id: 'test-1', revision_id: revision.id, configuration_version: 7, generation: 3,
    status: options.status || 'pending', callback_uri: 'http://localhost:5173/api/auth/test/callback', expires_at: new Date(Date.now() + 300_000).toISOString() }
  const fetcher = vi.fn(async (path: string, init?: RequestInit) => {
    if (options.httpError) return Response.json({ error: 'PRIVATE PROVIDER RESPONSE' }, { status: options.httpError })
    if (path === '/api/admin/auth/settings/revision-1/test') return Response.json({ ...result, authorization_url: 'https://issuer.example.test/authorize?state=synthetic-state&nonce=synthetic-nonce' }, { status: 201 })
    if (path === '/api/admin/auth/tests/test-1/cancel') { result.status = 'cancelled'; return Response.json(result) }
    if (path === '/api/admin/auth/tests/test-1' && init?.method === 'GET') return Response.json(result)
    throw new Error('unexpected endpoint')
  })
  vi.stubGlobal('fetch', fetcher)
  const session: Session = { authentication: { status: 'authenticated', identity }, access: { loading: false, user: admin, error: '' },
    health: 'ok', oidcEnabled: false, loggingOut: false, logoutFailed: false, loginFailed: false, logout: vi.fn(), expire: vi.fn(), refreshAccess: vi.fn() }
  const instance = createI18n('en')
  const view = render(<I18nextProvider i18n={instance}><LanguageProvider><NotificationProvider><SessionContext.Provider value={session}><QueryProvider>
    <OIDCConnectionTest revision={revision} disabled={false} />
  </QueryProvider></SessionContext.Provider></NotificationProvider></LanguageProvider></I18nextProvider>)
  return { ...view, popup, result, fetcher, instance, session }
}
async function start() { await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.testConnection })) }) }
async function tick(ms = 2000) { await act(async () => { await vi.advanceTimersByTimeAsync(ms) }) }

it('starts only on explicit click, binds the generation, and reports verified identity without activation', async () => {
  const { result, popup, fetcher } = setup()
  expect(fetcher).not.toHaveBeenCalled()
  await start()
  expect(popup.opener).toBeNull()
  expect(popup.location.replace).toHaveBeenCalledWith(expect.stringContaining('https://issuer.example.test/authorize'))
  expect(JSON.parse(fetcher.mock.calls[0][1]!.body as string)).toEqual({ expected_generation: 3 })
  expect(screen.getByText(en.testInProgress)).toBeTruthy()
  expect(document.body.innerHTML).not.toContain('synthetic-state')
  result.status = 'succeeded'; result.tested_identity = { ...identity, subject: 'test-subject' }
  await tick()
  expect(popup.close).toHaveBeenCalled()
  expect(screen.getByText(en.testIdentity)).toBeTruthy()
  expect(screen.getByText('test-subject')).toBeTruthy()
  expect(screen.getByText(/Revision 7/)).toBeTruthy()
  const toast = screen.getByRole('status')
  expect(toast.textContent).toContain(en.test_succeeded)
  fireEvent.click(within(toast).getByRole('button', { name: 'Close' }))
  await tick(300)
  expect(screen.queryByRole('status')).toBeNull()
  expect(fetcher.mock.calls.map(([path]) => path)).toEqual(['/api/admin/auth/settings/revision-1/test', '/api/admin/auth/tests/test-1'])
  expect(screen.queryByRole('button', { name: /activate/i })).toBeNull()
})
it('does not start a server operation when popups are blocked', async () => {
  const { fetcher } = setup({ blocked: true }); await start()
  expect(fetcher).not.toHaveBeenCalled(); expect(screen.getByText(en.testPopupBlocked)).toBeTruthy()
})
it('records cancellation when the popup is closed and stops polling', async () => {
  const { popup, fetcher } = setup(); await start(); popup.closed = true; await tick()
  expect(fetcher.mock.calls.at(-1)?.[0]).toBe('/api/admin/auth/tests/test-1/cancel')
  expect(screen.getAllByRole('alert').some((alert) => alert.textContent?.includes(en.test_cancelled))).toBe(true)
  const calls = fetcher.mock.calls.length; await tick(10_000); expect(fetcher.mock.calls).toHaveLength(calls)
})
it('supports explicit cancellation and cancellation when leaving the panel', async () => {
  const { fetcher, unmount } = setup(); await start()
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: en.testCancel })) })
  expect(fetcher.mock.calls.at(-1)?.[0]).toBe('/api/admin/auth/tests/test-1/cancel')
  unmount()
  expect(fetcher.mock.calls.filter(([path]) => path.endsWith('/cancel'))).toHaveLength(1)
})
it('cancels a pending test on unmount', async () => {
  const { fetcher, unmount, popup } = setup(); await start()
  await act(async () => unmount())
  expect(popup.closed).toBe(true)
  expect(fetcher.mock.calls.at(-1)?.[0]).toBe('/api/admin/auth/tests/test-1/cancel')
})
it.each(['failed', 'expired'] as const)('displays %s without trusting provider messages or continuing the flow', async (status) => {
  const { result, popup } = setup(); await start(); result.status = status; result.reason = 'PRIVATE PROVIDER RESPONSE'
  await tick()
  expect(screen.getAllByRole('alert').some((alert) => alert.textContent?.includes(en[`test_${status}`]))).toBe(true)
  expect(document.body.textContent).not.toContain('PRIVATE PROVIDER RESPONSE')
  expect(popup.closed).toBe(true)
})
it('reports discovery failure without navigating the popup', async () => {
  const { popup } = setup({ status: 'failed' }); await start()
  expect(popup.location.replace).not.toHaveBeenCalled()
  expect(screen.getAllByRole('alert').some((alert) => alert.textContent?.includes(en.test_failed))).toBe(true)
})
it.each([401, 409, 503])('handles HTTP %s with existing session and notification infrastructure', async (httpError) => {
  const { session, popup } = setup({ httpError }); await start()
  expect(popup.closed).toBe(true)
  if (httpError === 401) expect(session.expire).toHaveBeenCalledOnce()
  expect(document.body.textContent).not.toContain('PRIVATE PROVIDER RESPONSE')
  expect(screen.getAllByRole('alert').some((alert) => alert.textContent?.includes(httpError === 409 ? en.revisionConflict : en.testUnavailable))).toBe(true)
})
it('bounds an unresponsive start request', async () => {
  const { fetcher, popup } = setup()
  fetcher.mockImplementation((_path, init) => new Promise((_resolve, reject) => init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))))
  await start(); await tick(25_000)
  expect(popup.closed).toBe(true)
  expect(screen.getAllByText(en.testUnavailable)).toHaveLength(2)
})
it('preserves active tests during Arabic/mobile rendering and never restarts on language changes', async () => {
  mockMedia(false); const { instance, fetcher, result } = setup(); await start()
  await act(async () => { await instance.changeLanguage('ar') })
  expect(document.documentElement.dir).toBe('rtl')
  expect(screen.getByText(resources.ar.auth.testInProgress)).toBeTruthy()
  expect(fetcher).toHaveBeenCalledOnce()
  result.status = 'succeeded'; await tick()
  expect(screen.getByRole('status').textContent).toContain(resources.ar.auth.test_succeeded)
})
