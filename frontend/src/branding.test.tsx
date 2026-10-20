import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { I18nextProvider } from 'react-i18next'
import { MemoryRouter } from 'react-router-dom'
import App from './App'
import LanguageProvider from './LanguageProvider'
import { createI18n, resources } from './i18n'
import type { Language } from './i18n'
import { admin, bob, mockAPI, mockMedia } from './test/fixtures'

beforeEach(() => { localStorage.clear(); mockMedia(); mockAPI() })
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.unstubAllEnvs() })
function mount(language: Language = 'en', path = '/') {
  return render(<I18nextProvider i18n={createI18n(language)}><LanguageProvider><MemoryRouter initialEntries={[path]}><App /></MemoryRouter></LanguageProvider></I18nextProvider>)
}

describe('Vopak branding', () => {
  it('uses consistent application branding across all twelve languages', () => {
    for (const locale of Object.values(resources)) {
      expect(locale.common.appName).toBe('Vopak Enterprise Security')
      expect(locale.common.appShortName).toBe('Enterprise Security')
    }
  })

  it.each(['en', 'ar'] as const)('%s: preserves the logo, scrolling navigation, sidebar footer and both toggles', async (language) => {
    mount(language)
    await screen.findByRole('link', { name: resources[language].common.navUsers })
    const paper = document.querySelector('.MuiDrawer-paper') as HTMLElement
    const logo = within(paper).getByRole('img', { name: resources[language].common.brandLogoAlt })
    expect(logo.getAttribute('src')).toBe('/assets/vopak-logo.png')
    expect(getComputedStyle(logo).height).toBe('auto')
    expect(getComputedStyle(logo).objectFit).toBe('contain')
    expect(within(paper).getAllByText('Enterprise Security')).toHaveLength(2)
    const nav = screen.getByRole('navigation')
    const footer = screen.getByTestId('sidebar-brand-footer')
    expect(footer.textContent).toContain(`© ${new Date().getFullYear()} Vopak`)
    expect(nav.contains(footer)).toBe(false)
    expect(getComputedStyle(nav).overflowY).toBe('auto')
    expect(getComputedStyle(nav).flexGrow).toBe('1')
    expect(getComputedStyle(footer).flexShrink).toBe('0')
    expect(getComputedStyle(paper).width).toBe('260px')
    await userEvent.click(document.getElementById('sidebar-toggle-edge')!)
    expect(getComputedStyle(paper).width).toBe('68px')
    expect(screen.queryByTestId('sidebar-brand-footer')).toBeNull()
    expect(within(paper).queryByText('Enterprise Security')).toBeNull()
    expect(within(paper).queryByRole('img', { name: resources[language].common.brandLogoAlt })).toBeNull()
    expect(within(paper).getByRole('img', { name: 'Vopak Enterprise Security' })).toBeTruthy()
    await userEvent.click(document.getElementById('sidebar-toggle-bottom')!)
    expect(screen.getByTestId('sidebar-brand-footer')).toBeTruthy()
    await userEvent.click(screen.getByRole('link', { name: resources[language].common.navUsers }))
    expect(await screen.findByRole('heading', { level: 1, name: resources[language].common.navUsers })).toBeTruthy()
  })

  it.each(Object.keys(resources) as Language[])('%s: renders localized logo alt text under a non-root Vite base', async (language) => {
    vi.stubEnv('BASE_URL', '/enterprise/security/')
    mount(language)
    const label = resources[language].common.brandLogoAlt
    expect(label.trim()).not.toBe('')
    expect(label).not.toBe('Vopak')
    const logo = await screen.findByRole('img', { name: label })
    expect(logo.getAttribute('src')).toBe('/enterprise/security/assets/vopak-logo.png')
    expect(new URL((logo as HTMLImageElement).src).pathname).toBe('/enterprise/security/assets/vopak-logo.png')
  })

  it.each(['en', 'ar'] as const)('%s: branding and toggles preserve direct-route guards and capability permissions', async (language) => {
    const { fetcher } = mockAPI({ user: bob, modules: ['example'] })
    mount(language, '/users')
    await screen.findByRole('heading', { name: resources[language].common.accessDenied })
    expect(screen.getByRole('img', { name: resources[language].common.brandLogoAlt })).toBeTruthy()
    expect(screen.queryByRole('link', { name: resources[language].common.navUsers })).toBeNull()
    expect(fetcher.mock.calls.some(([path]) => path.startsWith('/api/admin/'))).toBe(false)
    await userEvent.click(document.getElementById('sidebar-toggle-edge')!)
    await userEvent.click(document.getElementById('sidebar-toggle-bottom')!)
    expect(fetcher.mock.calls.filter(([path]) => path === '/api/modules')).toHaveLength(1)
    expect(fetcher.mock.calls.filter(([path]) => path === '/api/auth/me')).toHaveLength(1)
    expect(document.querySelector('nav a[href="/modules/example/items"]')).toBeNull()
  })

  it('branding never grants Admin a module permission or enables a disabled module', async () => {
    const { fetcher } = mockAPI({ user: admin, modules: ['example'] })
    mount('en', '/modules/example/items')
    await screen.findByRole('heading', { name: 'Access denied' })
    expect(screen.getByRole('img', { name: resources.en.common.brandLogoAlt })).toBeTruthy()
    expect(screen.queryByRole('link', { name: 'Example items' })).toBeNull()
    expect(fetcher.mock.calls.filter(([path]) => path === '/api/modules')).toHaveLength(1)
    cleanup()
    mockAPI({ user: { ...admin, permissions: [...admin.permissions, 'example.read'] }, modules: [] })
    mount('en', '/modules/example/items')
    await screen.findByRole('heading', { level: 2, name: resources.en.common.pageNotFound })
    expect(screen.queryByRole('link', { name: 'Example items' })).toBeNull()
  })

  it('places the compact main footer after content in normal document flow', async () => {
    mount()
    await screen.findByRole('link', { name: 'Users' })
    const main = screen.getByRole('main')
    const footer = screen.getByRole('contentinfo')
    expect(main.nextElementSibling).toBe(footer)
    expect(footer.textContent).toBe(`© ${new Date().getFullYear()} Vopak · Enterprise Security`)
    expect(['fixed', 'absolute', 'sticky']).not.toContain(getComputedStyle(footer).position)
    expect(getComputedStyle(main).flexGrow).toBe('1')
    expect(getComputedStyle(main.parentElement!).flexDirection).toBe('column')
  })

  it.each(['en', 'ar'] as const)('%s: keeps mobile branding compact and closes the drawer after navigation', async (language) => {
    mockMedia(false)
    mount(language)
    await screen.findByText('Original account name')
    await userEvent.click(await screen.findByRole('button', { name: resources[language].common.openMenu }))
    await screen.findByRole('navigation')
    const paper = document.querySelector('.MuiDrawer-paper') as HTMLElement
    expect(within(paper).getByRole('img', { name: resources[language].common.brandLogoAlt })).toBeTruthy()
    expect(within(paper).getAllByText('Enterprise Security')).toHaveLength(1)
    expect(screen.getByTestId('sidebar-brand-footer').textContent).toBe(`© ${new Date().getFullYear()} Vopak`)
    expect(document.getElementById('sidebar-toggle-bottom')).toBeNull()
    await userEvent.click(await screen.findByRole('link', { name: resources[language].common.navUsers }))
    await waitFor(() => expect(document.querySelector('.MuiDrawer-paper')).toBeNull())
    expect(await screen.findByRole('heading', { level: 1, name: resources[language].common.navUsers })).toBeTruthy()
  })
})
