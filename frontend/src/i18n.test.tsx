import { chooseLanguage } from './test/menuActions'
import type { Language } from './i18n'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { I18nextProvider } from 'react-i18next'
import type { i18n } from 'i18next'
import { Box } from '@mui/material'
import { useTheme } from '@mui/material/styles'
import App from './App'
import { BrowserRouter } from 'react-router-dom'
import { mockAPI, mockMedia } from './test/fixtures'
import LanguageProvider from './LanguageProvider'
import LanguageSelector from './LanguageSelector'
import {
  actionKeys, createI18n, detectLanguage, direction, formatDate, formatNumber,
  languages, languageStorageKey, namespaces, permissionKeys, resources, roleKeys,
} from './i18n'

const jsonFiles = import.meta.glob<string>('./locales/*/*.json', { eager: true, query: '?raw', import: 'default' })
const placeholders = (value: string) => [...value.matchAll(/{{\s*([^}]+)\s*}}/g)].map((match) => match[1].trim()).sort()

beforeEach(() => {
  mockMedia()
  localStorage.clear()
  window.history.replaceState(null, '', '/')
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('translation resources', () => {
  it('contains exactly twelve languages and three namespaces each', () => {
    expect(Object.keys(jsonFiles)).toHaveLength(36)
    expect(Object.keys(resources).sort()).toEqual(Object.keys(languages).sort())
  })
  for (const language of Object.keys(languages)) {
    it(`${language}: valid JSON, complete keys, nonempty strings, and matching interpolation placeholders`, () => {
      expect(Object.keys(resources[language]).sort()).toEqual([...namespaces].sort())
      for (const namespace of namespaces) {
        const entries = JSON.parse(jsonFiles[`./locales/${language}/${namespace}.json`])
        const english = resources.en[namespace]
        expect(Object.keys(entries).sort()).toEqual(Object.keys(english).sort())
        for (const [key, value] of Object.entries(entries)) {
          expect(typeof value, `${namespace}.${key}`).toBe('string')
          expect((value as string).trim()).not.toBe('')
          expect(placeholders(value as string), `${namespace}.${key}`).toEqual(placeholders(english[key]))
        }
      }
    })
  }
  it('provides display labels for every existing role, permission, and audit action', () => {
    for (const key of [...Object.values(roleKeys), ...Object.values(permissionKeys), ...Object.values(actionKeys)]) {
      expect(resources.en.admin[key]).toBeTruthy()
    }
  })
  it('falls back to English in all three namespaces without losing interpolation', () => {
    const incomplete = structuredClone(resources)
    delete incomplete.fr.common.page
    delete incomplete.fr.auth.signIn
    delete incomplete.fr.admin.grantAdmin
    const instance = createI18n('fr', incomplete)
    expect(instance.t('page', { page: '2' })).toBe('Page 2')
    expect(instance.t('auth:signIn')).toBe('Sign in')
    expect(instance.t('admin:grantAdmin', { issuer: 'https://issuer.test', subject: 'user-123' }))
      .toBe('Grant Admin to issuer https://issuer.test, subject user-123?')
  })
  it('formats dates and numbers in the selected locale', () => {
    const date = '2026-06-12T14:30:00Z'
    expect(formatNumber(1234567.89, 'fr')).toBe(new Intl.NumberFormat('fr').format(1234567.89))
    expect(formatNumber(1234567.89, 'hi')).toBe('12,34,567.89')
    // Arabic's default numbering system varies across browser/ICU versions.
    expect(formatNumber(123, 'ar')).toBe(new Intl.NumberFormat('ar').format(123))
    expect(formatDate(date, 'nl')).toBe(new Intl.DateTimeFormat('nl', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(date)))
    expect(formatDate(date, 'en')).not.toBe(formatDate(date, 'ar'))
  })
})

describe('language detection', () => {
  it.each([
    [['de-DE', 'fr-CA'], 'fr'], [['nl-BE'], 'nl'], [['pt-PT'], 'pt-BR'],
    [['zh-Hans-CN'], 'zh-CN'], [['ar-SA'], 'ar'], [['de-DE'], 'en'], [[], 'en'],
  ])('matches browser preferences %j to %s', (browserLanguages, expected) => {
    expect(detectLanguage(localStorage, browserLanguages as string[])).toBe(expected)
  })
  it('prefers a saved selection over the browser, and ignores invalid stored values', () => {
    localStorage.setItem(languageStorageKey, 'es')
    expect(detectLanguage(localStorage, ['fr'])).toBe('es')
    localStorage.setItem(languageStorageKey, 'invalid')
    expect(detectLanguage(localStorage, ['fr'])).toBe('fr')
  })
  it('works when local storage is unavailable or blocked', () => {
    expect(detectLanguage(undefined, ['nl'])).toBe('nl')
    expect(detectLanguage({ getItem() { throw new Error('Storage blocked') } }, ['ms'])).toBe('ms')
  })
})

function renderApp(instance: i18n = createI18n('en')) {
  return render(<I18nextProvider i18n={instance}><LanguageProvider><BrowserRouter><App /></BrowserRouter></LanguageProvider></I18nextProvider>)
}
function mockUnauthenticated() {
  const fetcher = vi.fn(async (path: string) => {
    if (path === '/api/auth/config') return Response.json({ provider: 'oidc' })
    if (path === '/api/health') return Response.json({ status: 'ok' })
    if (path === '/api/auth/me') return Response.json({ error: 'unauthenticated' }, { status: 401 })
    throw new Error(`Unexpected request: ${path}`)
  })
  vi.stubGlobal('fetch', fetcher)
  return fetcher
}

describe('language selection and dashboard', () => {
  it('renders a missing translation in English while keeping the selected language', async () => {
    mockUnauthenticated()
    const incomplete = structuredClone(resources)
    delete incomplete.fr.auth.signIn
    renderApp(createI18n('fr', incomplete))
    expect((await screen.findByRole('link', { name: 'Sign in' })).getAttribute('href')).toBe('/api/auth/login')
    expect(screen.getByRole('heading', { name: 'Tableau de bord' })).toBeTruthy()
    expect(document.getElementById('language-selector')!.textContent).toBe('FR')
  })
  it('switches between all twelve languages without repeating authentication requests', async () => {
    const fetcher = mockUnauthenticated()
    renderApp()
    await screen.findByRole('link', { name: 'Sign in' })
    const requestCount = fetcher.mock.calls.length
    for (const language of Object.keys(languages)) {
      await chooseLanguage(language as Language)
      expect(screen.getByRole('heading', { name: resources[language].common.dashboard })).toBeTruthy()
      expect(screen.getByRole('link', { name: resources[language].auth.signIn }).getAttribute('href')).toBe('/api/auth/login')
      expect(screen.queryByText(resources[language].common.backendStatus)).toBeNull()
      expect(document.documentElement.lang).toBe(language)
      expect(document.documentElement.dir).toBe(direction(language))
    }
    expect(fetcher.mock.calls).toHaveLength(requestCount)
  }, 10000)
  it('persists only the language and restores it on the next application mount', async () => {
    mockUnauthenticated()
    const view = renderApp()
    await screen.findByRole('link', { name: 'Sign in' })
    await chooseLanguage('nl')
    expect(localStorage.getItem(languageStorageKey)).toBe('nl')
    expect(localStorage.length).toBe(1)
    view.unmount()
    renderApp(createI18n(detectLanguage(localStorage, ['en-US'])))
    expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeTruthy()
    expect(document.getElementById('language-selector')!.textContent).toBe('NL')
    await screen.findByRole('link', { name: 'Aanmelden' })
  })
  it('still switches language if saving the preference fails', async () => {
    mockUnauthenticated()
    renderApp()
    await screen.findByRole('link', { name: 'Sign in' })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('Storage blocked') })
    await chooseLanguage('fr')
    expect(screen.getByRole('link', { name: 'Se connecter' })).toBeTruthy()
  })
  it('localizes callback errors and removes the error marker from the URL', async () => {
    window.history.replaceState(null, '', '/?auth_error=login_failed')
    mockUnauthenticated()
    renderApp(createI18n('es'))
    await screen.findByRole('link', { name: 'Iniciar sesión' })
    expect(screen.getByText(resources.es.auth.loginFailed)).toBeTruthy()
    expect(window.location.search).toBe('')
  })
  it('preserves OIDC logout and identity values with translated controls', async () => {
    const fetcher = vi.fn(async (path: string) => {
      if (path === '/api/auth/config') return Response.json({ provider: 'oidc' })
      if (path === '/api/health') return Response.json({ status: 'ok' })
      if (path === '/api/auth/me') return Response.json({ issuer: 'https://issuer.test', subject: 's1', display_name: 'Alice', email: 'alice@example.test', email_verified: true, provider: 'oidc' })
      if (path === '/api/access/me') return Response.json({ id: 'u1', roles: [], permissions: [], account_ids: [] })
      if (path === '/api/auth/logout') return new Response(null, { status: 204 })
      throw new Error(`Unexpected request: ${path}`)
    })
    vi.stubGlobal('fetch', fetcher)
    renderApp(createI18n('nl'))
    await userEvent.click(await screen.findByRole('button', { name: resources.nl.auth.profileMenu }))
    const logout = await screen.findByRole('menuitem', { name: 'Afmelden' })
    expect(screen.getAllByText('Alice').length).toBeGreaterThan(0)
    expect(screen.getAllByText('alice@example.test').length).toBeGreaterThan(0)
    await userEvent.click(logout)
    await screen.findByRole('link', { name: 'Aanmelden' })
    expect(fetcher).toHaveBeenCalledWith('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
    expect(screen.queryByText('Alice')).toBeNull()
    expect(localStorage.length).toBe(0)
  })
})

function DirectionProbe() {
  const theme = useTheme()
  return <Box data-testid="direction-probe" data-direction={theme.direction} sx={{ marginLeft: '13px' }}>probe</Box>
}

it('switches HTML and MUI direction and actually mirrors Emotion styles for Arabic, then restores LTR', async () => {
  const instance = createI18n('en')
  render(<I18nextProvider i18n={instance}><LanguageProvider><LanguageSelector /><DirectionProbe /></LanguageProvider></I18nextProvider>)
  expect(getComputedStyle(screen.getByTestId('direction-probe')).marginLeft).toBe('13px')
  await chooseLanguage('ar')
  expect(document.documentElement.dir).toBe('rtl')
  expect(screen.getByTestId('direction-probe').dataset.direction).toBe('rtl')
  expect(getComputedStyle(screen.getByTestId('direction-probe')).marginRight).toBe('13px')
  await chooseLanguage('en')
  expect(document.documentElement.dir).toBe('ltr')
  expect(screen.getByTestId('direction-probe').dataset.direction).toBe('ltr')
  expect(getComputedStyle(screen.getByTestId('direction-probe')).marginLeft).toBe('13px')
})

describe('account portal errors', () => {
  it.each([
    [403, 'errorForbidden'], [409, 'errorConflict'], [400, 'errorInvalid'], [503, 'errorUnavailable'],
  ])('localizes HTTP %s using status codes and retranslates existing errors', async (status, key) => {
    const { fetcher } = mockAPI({ accessStatus: status as number })
    const instance = createI18n('en')
    renderApp(instance)
    expect((await screen.findByRole('alert')).textContent).toBe(resources.en.admin[key])
    const count = fetcher.mock.calls.length
    await act(() => instance.changeLanguage('fr'))
    expect(screen.getByRole('alert').textContent).toBe(resources.fr.admin[key])
    expect(fetcher.mock.calls).toHaveLength(count)
    expect(screen.queryByText('UNTRUSTED SERVER DETAILS')).toBeNull()
  })
  it('returns to login on HTTP 401 from account access', async () => {
    mockAPI({ accessStatus: 401 })
    renderApp(createI18n('vi'))
    await screen.findByRole('link', { name: resources.vi.auth.signIn })
    expect(screen.getByRole('alert').textContent).toBe(resources.vi.auth.unauthenticated)
  })
  it('uses a translated error for network failures instead of raw exception text', async () => {
    const { fetcher } = mockAPI()
    const normal = fetcher.getMockImplementation()!
    fetcher.mockImplementation(async (path, options) => {
      if (path === '/api/access/me') throw new Error('INTERNAL NETWORK DETAILS')
      return normal(path, options)
    })
    renderApp(createI18n('vi'))
    expect((await screen.findByRole('alert')).textContent).toBe(resources.vi.admin.errorRequest)
  })
})
