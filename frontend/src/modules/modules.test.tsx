import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { I18nextProvider } from 'react-i18next'
import { BrowserRouter } from 'react-router-dom'
import App from '../App'
import LanguageProvider from '../LanguageProvider'
import { createI18n, languages, registerModuleTranslations, resources } from '../i18n'
import type { Language } from '../i18n'
import { admin, identity, mockAPI, mockMedia } from '../test/fixtures'
import { capabilityIDs, composeModules } from './registry'
import type { FrontendModule, ModuleCatalog, ModulePage } from './types'
import ModuleRoutes from './ModuleRoutes'
import { SessionContext } from '../auth/session'
import type { Session } from '../auth/session'
import { defaultNavigation } from '../navigation/NavigationRegistry'

const path = '/modules/example/items'
const moduleFiles = import.meta.glob<string>('./example/locales/*.json', { eager: true, query: '?raw', import: 'default' })
const bundles = Object.fromEntries(Object.entries(moduleFiles).map(([file, text]) => [file.match(/locales\/([^/]+)\.json$/)![1], JSON.parse(text)])) as FrontendModule['translations']
const user = { ...admin, permissions: [...admin.permissions, 'example.read'] }
const placeholders = (value: string) => [...value.matchAll(/{{\s*([^}]+)\s*}}/g)].map((match) => match[1].trim()).sort()

beforeEach(() => { mockMedia(); localStorage.clear(); window.history.replaceState(null, '', '/') })
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

function mount(language: Language = 'en') {
  const instance = createI18n(language)
  const view = render(<I18nextProvider i18n={instance}><LanguageProvider><BrowserRouter><App /></BrowserRouter></LanguageProvider></I18nextProvider>)
  return { ...view, instance }
}
function moduleCalls(fetcher: ReturnType<typeof mockAPI>['fetcher']) { return fetcher.mock.calls.filter(([path]) => path === '/api/modules') }

describe('module catalog and translations', () => {
  it('validates capability payloads and deduplicates IDs', () => {
    expect(capabilityIDs({ modules: ['example', 'example'] })).toEqual(['example'])
    for (const value of [null, [], {}, { modules: 'example' }, { modules: [5] }, { modules: ['../admin'] }]) expect(() => capabilityIDs(value)).toThrow()
  })
  it('loads only enabled compiled entries, warns for unknown IDs, and injects translations explicitly', async () => {
    const instance = createI18n('en')
    const load = vi.fn(() => import('./example'))
    const disabled = vi.fn(() => import('./example'))
    const catalog: ModuleCatalog = { example: load, disabled }
    const warning = vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect((await composeModules([], instance, catalog)).pages).toHaveLength(0)
    expect(load).not.toHaveBeenCalled()
    const composed = await composeModules(['example', 'missing', 'example'], instance, catalog)
    expect(load).toHaveBeenCalledOnce()
    expect(disabled).not.toHaveBeenCalled()
    expect(warning).toHaveBeenCalledOnce()
    expect(composed.pages.map((page) => page.path)).toEqual([path])
    expect(instance.hasResourceBundle('en', 'example')).toBe(false)
    composed.registerTranslations()
    expect(instance.t('example:navItems')).toBe('Example items')
    expect(Object.keys(resources.en).sort()).toEqual(['admin', 'auth', 'common'])
  })
  it('rejects unsafe module page metadata', async () => {
    const page: ModulePage = { path: '/modules/example/items', labelKey: 'example:navItems', requiredPermission: 'example.read', icon: null, element: <div /> }
    for (const overrides of [
      { public: true }, { requiredPermission: '' }, { requiredPermission: 'admin.manage' },
      { requiredPermission: 'other.read' }, { path: '/users' }, { labelKey: 'common:navDashboard' },
    ]) {
      const catalog: ModuleCatalog = { example: async () => ({ default: { id: 'example', pages: [{ ...page, ...overrides } as ModulePage], translations: bundles } }) }
      await expect(composeModules(['example'], createI18n('en'), catalog)).rejects.toThrow()
    }
    const mismatch: ModuleCatalog = { example: async () => ({ default: { id: 'other', pages: [page], translations: bundles } }) }
    await expect(composeModules(['example'], createI18n('en'), mismatch)).rejects.toThrow()
  })
  it('rejects duplicate page paths and protects core namespaces', async () => {
    const { default: example } = await import('./example')
    await expect(composeModules(['example'], createI18n('en'), { example: async () => ({ default: { ...example, pages: [...example.pages, ...example.pages] } }) })).rejects.toThrow()
    for (const namespace of ['common', 'auth', 'admin']) expect(() => registerModuleTranslations(createI18n('en'), namespace, bundles)).toThrow()
  })
  it.each(Object.keys(languages) as Language[])('%s has valid JSON, symmetric nonempty keys, and matching placeholders', (language) => {
    expect(Object.keys(moduleFiles)).toHaveLength(12)
    expect(Object.keys(bundles[language]).sort()).toEqual(Object.keys(bundles.en).sort())
    for (const [key, value] of Object.entries(bundles[language])) {
      expect(typeof value).toBe('string')
      expect(value.trim()).not.toBe('')
      expect(placeholders(value)).toEqual(placeholders(bundles.en[key]))
    }
  })
  it('falls back to English for a missing localized module key', () => {
    const incomplete = structuredClone(bundles)
    delete incomplete.fr.description
    const instance = createI18n('fr')
    registerModuleTranslations(instance, 'example', incomplete)
    expect(instance.t('example:description')).toBe(bundles.en.description)
    expect(instance.t('example:navItems')).toBe(bundles.fr.navItems)
  })
})

describe('session-bound module navigation', () => {
  it('shows enabled pages only with explicit permission, supports direct URLs and avoids refetching on navigation/language changes', async () => {
    const { fetcher } = mockAPI({ user, modules: ['example'] })
    window.history.replaceState(null, '', path)
    const { instance } = mount()
    expect(await screen.findByRole('heading', { level: 2, name: 'Items' })).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Example items' })).toBeTruthy()
    expect(moduleCalls(fetcher)).toHaveLength(1)
    expect(fetcher.mock.calls.findIndex(([path]) => path === '/api/auth/me')).toBeLessThan(fetcher.mock.calls.findIndex(([path]) => path === '/api/modules'))
    await userEvent.click(screen.getByRole('link', { name: 'Users' }))
    await screen.findByRole('heading', { level: 1, name: 'Users' })
    await act(async () => { await instance.changeLanguage('ar') })
    await userEvent.click(screen.getByRole('link', { name: bundles.ar.navItems }))
    expect(await screen.findByRole('heading', { level: 2, name: bundles.ar.itemsTitle })).toBeTruthy()
    expect(document.documentElement.dir).toBe('rtl')
    expect(moduleCalls(fetcher)).toHaveLength(1)
  })
  it('hides navigation and blocks a direct URL even for Admin without example.read', async () => {
    mockAPI({ modules: ['example'] })
    window.history.replaceState(null, '', path)
    mount()
    expect(await screen.findByRole('heading', { name: 'Access denied' })).toBeTruthy()
    expect(screen.queryByRole('link', { name: 'Example items' })).toBeNull()
    expect(screen.queryByRole('heading', { level: 2, name: 'Items' })).toBeNull()
  })
  it('does not register disabled routes or their translations despite explicit permission', async () => {
    const { fetcher } = mockAPI({ user })
    window.history.replaceState(null, '', path)
    const { instance } = mount()
    await waitFor(() => expect(moduleCalls(fetcher)).toHaveLength(1))
    expect(await screen.findByRole('heading', { level: 2, name: resources.en.common.pageNotFound })).toBeTruthy()
    expect(screen.queryByRole('link', { name: 'Example items' })).toBeNull()
    expect(instance.hasResourceBundle('en', 'example')).toBe(false)
  })
  it.each(['network', 'http', 'malformed'] as const)('keeps core routes with a localized warning on %s failure and never enables catalog-only routes', async (failure) => {
    const { fetcher } = mockAPI({ user, modules: ['example'] })
    const original = fetcher.getMockImplementation()!
    fetcher.mockImplementation(async (path, init) => {
      if (path !== '/api/modules') return original(path, init)
      if (failure === 'network') throw new Error('private server details')
      return failure === 'http' ? new Response('private server details', { status: 503 }) : Response.json({ modules: ['../admin'] })
    })
    window.history.replaceState(null, '', path)
    const { instance } = mount('fr')
    expect(await screen.findByText(resources.fr.common.modulesUnavailable)).toBeTruthy()
    expect(screen.getByRole('link', { name: resources.fr.common.navUsers })).toBeTruthy()
    expect(screen.queryByRole('link', { name: bundles.fr.navItems })).toBeNull()
    expect(instance.hasResourceBundle('en', 'example')).toBe(false)
    expect(document.body.textContent).not.toContain('private server details')
    await userEvent.click(screen.getByRole('link', { name: resources.fr.common.navUsers }))
    expect(await screen.findByRole('heading', { level: 1, name: resources.fr.common.navUsers })).toBeTruthy()
  })
  it('ignores unknown bundled IDs while retaining confirmed known modules', async () => {
    const warning = vi.spyOn(console, 'warn').mockImplementation(() => {})
    mockAPI({ user, modules: ['example', 'unbundled'] })
    mount()
    expect(await screen.findByRole('link', { name: 'Example items' })).toBeTruthy()
    expect(warning).toHaveBeenCalledOnce()
  })
  it('does not fetch capabilities before authentication', async () => {
    const { fetcher } = mockAPI({ authenticated: false, modules: ['example'] })
    mount()
    await screen.findByRole('link', { name: 'Sign in' })
    expect(moduleCalls(fetcher)).toHaveLength(0)
  })
  it('clears module routes on OIDC logout', async () => {
    mockAPI({ user, modules: ['example'] })
    mount()
    await screen.findByRole('link', { name: 'Example items' })
    await userEvent.click(screen.getByRole('button', { name: 'User profile' }))
    await userEvent.click(screen.getByRole('menuitem', { name: 'Sign out' }))
    await screen.findByRole('link', { name: 'Sign in' })
    expect(screen.queryByRole('link', { name: 'Example items' })).toBeNull()
  })
  it('treats capability 401 as session expiration', async () => {
    const { responses } = mockAPI({ user, modules: ['example'] })
    responses.set('/api/modules', 401)
    mount()
    await screen.findByRole('link', { name: 'Sign in' })
    expect(screen.queryByRole('link', { name: 'Example items' })).toBeNull()
  })
  it('ignores delayed responses from a previous identity and fetches again after sign-in', async () => {
    let finishOld: (response: Response) => void = () => {}
    const fetcher = vi.fn().mockImplementationOnce(() => new Promise<Response>((resolve) => { finishOld = resolve }))
      .mockResolvedValueOnce(Response.json({ modules: [] }))
      .mockResolvedValueOnce(Response.json({ modules: ['example'] }))
    vi.stubGlobal('fetch', fetcher)
    const instance = createI18n('en')
    const session: Session = { authentication: { status: 'authenticated', identity }, access: { loading: false, user, error: '' }, health: 'connected', oidcEnabled: true, loggingOut: false, logoutFailed: false, loginFailed: false, logout: async () => {}, expire: vi.fn(), refreshAccess: vi.fn() }
    function content(value: Session) { return <I18nextProvider i18n={instance}><LanguageProvider><BrowserRouter><SessionContext.Provider value={value}><ModuleRoutes core={defaultNavigation} /></SessionContext.Provider></BrowserRouter></LanguageProvider></I18nextProvider> }
    window.history.replaceState(null, '', path)
    const view = render(content(session))
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1))
    view.rerender(content({ ...session, authentication: { status: 'unauthenticated' } }))
    expect(fetcher.mock.calls[0][1].signal.aborted).toBe(true)
    await act(async () => { finishOld(Response.json({ modules: ['example'] })) })
    expect(instance.hasResourceBundle('en', 'example')).toBe(false)
    const nextSession: Session = { ...session, authentication: { status: 'authenticated', identity: { ...identity, subject: 'next-user' } } }
    view.rerender(content(nextSession))
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2))
    expect(screen.queryByRole('link', { name: 'Example items' })).toBeNull()
    view.rerender(content({ ...session, authentication: { status: 'authenticated', identity: { ...identity } } }))
    expect(await screen.findByRole('heading', { level: 2, name: 'Items' })).toBeTruthy()
    expect(fetcher).toHaveBeenCalledTimes(3)
  })
})
