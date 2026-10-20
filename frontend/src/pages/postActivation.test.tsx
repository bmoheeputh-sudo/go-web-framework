import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import { I18nextProvider } from 'react-i18next'
import { MemoryRouter } from 'react-router-dom'
import App from '../App'
import LanguageProvider from '../LanguageProvider'
import { createI18n, resources } from '../i18n'
import type { Language } from '../i18n'
import { admin, mockAPI, mockMedia } from '../test/fixtures'
import type { User } from '../api/client'

beforeEach(() => { localStorage.clear(); mockMedia() })
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function mount(path: string, language: Language = 'en') {
  render(<I18nextProvider i18n={createI18n(language)}><LanguageProvider><MemoryRouter initialEntries={[path]}><App /></MemoryRouter></LanguageProvider></I18nextProvider>)
}

const localUser: User = {
  ...admin, id: 'local-user', issuer: 'urn:go-web-framework:local-dev', subject: 'developer',
  display_name: 'Local Developer', provider: 'local_dev', roles: ['Admin'],
}
const retiredOIDCUser: User = {
  ...admin, id: 'retired-oidc-user', issuer: 'https://retired.example.test/', subject: 'old-subject',
  display_name: 'Retired OIDC User', provider: 'oidc', roles: ['Viewer'],
}
const historicalIAPUser: User = {
  ...admin, id: 'historical-iap-user', issuer: 'https://cloud.google.com/iap', subject: 'historical-subject',
  display_name: 'Historical IAP User', provider: 'google_iap', roles: ['Viewer'],
}

it('removes the dashboard backend card while retaining health monitoring and the signed-out OIDC action', async () => {
  const { fetcher } = mockAPI({ authenticated: false, provider: 'oidc' })
  mount('/')
  const signIn = await screen.findByRole('link', { name: resources.en.auth.signIn })
  expect(signIn.getAttribute('href')).toBe('/api/auth/login')
  expect(screen.queryByText(resources.en.common.backendStatus)).toBeNull()
  await waitFor(() => expect(fetcher.mock.calls.filter(([path]) => path === '/api/health')).toHaveLength(1))
})

it('separates stored user activity from current provider and exact OIDC issuer', async () => {
  const { fetcher } = mockAPI()
  const original = fetcher.getMockImplementation()!
  fetcher.mockImplementation((path, init) => path === '/api/admin/users?offset=0'
    ? Promise.resolve(Response.json([admin, localUser, retiredOIDCUser, historicalIAPUser])) : original(path, init))
  mount('/users')
  const localRow = (await screen.findByRole('button', { name: 'Select user: Local Developer' })).closest('tr')!
  await waitFor(() => expect(within(localRow).getByText(resources.en.admin.providerUnavailable)).toBeTruthy())
  expect(within(localRow).getByText(resources.en.common.statusActive)).toBeTruthy()
  expect(within(localRow).getByText(resources.en.auth.providerLocal)).toBeTruthy()
  const retiredRow = screen.getByRole('button', { name: 'Select user: Retired OIDC User' }).closest('tr')!
  expect(within(retiredRow).getByText(resources.en.admin.providerUnavailable)).toBeTruthy()
  const historicalRow = screen.getByRole('button', { name: 'Select user: Historical IAP User' }).closest('tr')!
  expect(within(historicalRow).getByText(resources.en.auth.providerIap)).toBeTruthy()
  expect(within(historicalRow).getByText(resources.en.admin.providerUnavailable)).toBeTruthy()
  const currentRow = screen.getByRole('button', { name: 'Select user: Alice' }).closest('tr')!
  expect(within(currentRow).getByText(resources.en.admin.providerCurrent)).toBeTruthy()
  expect(within(screen.getByRole('table', { name: 'Users' })).getByRole('columnheader', { name: resources.en.admin.userRecordStatus })).toBeTruthy()
  expect(fetcher.mock.calls.filter(([path]) => path === '/api/admin/auth/status')).toHaveLength(1)
})

it('does not claim sign-in availability when runtime status is unavailable', async () => {
  const { responses } = mockAPI()
  responses.set('/api/admin/auth/status', 503)
  mount('/users', 'ar')
  const row = (await screen.findByRole('button', { name: resources.ar.admin.selectUser.replace('{{name}}', 'Alice') })).closest('tr')!
  expect(await within(row).findByText(resources.ar.admin.providerStatusUnknown)).toBeTruthy()
  expect(within(row).queryByText(resources.ar.admin.providerCurrent)).toBeNull()
  expect(document.documentElement.dir).toBe('rtl')
})
