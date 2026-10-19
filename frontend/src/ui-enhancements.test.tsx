import { chooseLanguage, chooseAppearance } from './test/menuActions'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { I18nextProvider } from 'react-i18next'
import { useTheme } from '@mui/material/styles'
import type { AlertColor } from '@mui/material/Alert'
import App from './App'
import LanguageProvider from './LanguageProvider'
import ThemeSelector from './appearance/ThemeSelector'
import { appearanceStorageKey } from './appearance/appearance'
import NotificationProvider from './notifications/NotificationProvider'
import { useNotifications } from './notifications/notifications'
import { createI18n, resources } from './i18n'
import type { Language } from './i18n'
import { identity, mockAPI, mockMedia } from './test/fixtures'

beforeEach(() => { localStorage.clear(); mockMedia() })
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function ThemeProbe() {
  const theme = useTheme()
  return <output data-testid="theme">{theme.palette.mode}:{theme.direction}:{theme.palette.background.paper}</output>
}
function mount(path = '/', language: Language = 'en') {
  const instance = createI18n(language)
  return { instance, ...render(<I18nextProvider i18n={instance}><LanguageProvider><ThemeProbe />
    <MemoryRouter initialEntries={[path]}><App /></MemoryRouter>
  </LanguageProvider></I18nextProvider>) }
}
function systemMedia(initialDark: boolean) {
  let dark = initialDark
  const listeners = new Set<() => void>()
  vi.stubGlobal('matchMedia', vi.fn((query: string) => ({
    media: query, get matches() { return query.includes('prefers-color-scheme') ? dark : true },
    addEventListener: (_: string, callback: () => void) => listeners.add(callback),
    removeEventListener: (_: string, callback: () => void) => listeners.delete(callback),
  })))
  return (value: boolean) => act(() => { dark = value; listeners.forEach((callback) => callback()) })
}

describe('appearance preferences', () => {
  it('follows live system changes, honors overrides, persists across remounts, and retains RTL', async () => {
    const changeSystem = systemMedia(true)
    const { fetcher } = mockAPI()
    const view = mount('/roles')
    await screen.findByText(/Manage administration/)
    const count = fetcher.mock.calls.length
    const selector = screen.getByRole('button', { name: 'Appearance' })
    expect(selector.getAttribute('aria-description')).toBe('System')
    expect(screen.getByTestId('theme').textContent).toContain('dark:ltr')
    changeSystem(false)
    expect(screen.getByTestId('theme').textContent).toContain('light:ltr')
    await chooseAppearance('dark')
    changeSystem(true); changeSystem(false)
    expect(screen.getByTestId('theme').textContent).toContain('dark:ltr')
    expect(localStorage.getItem(appearanceStorageKey)).toBe('dark')
    await chooseLanguage('ar')
    expect(screen.getByTestId('theme').textContent).toContain('dark:rtl')
    expect(document.documentElement.dir).toBe('rtl')
    expect(document.querySelector('.MuiDrawer-anchorRight')).toBeTruthy()
    expect(fetcher.mock.calls).toHaveLength(count)
    view.unmount()
    mount('/roles', 'ar')
    await screen.findByText(new RegExp(resources.ar.admin.permissionAdmin))
    expect(screen.getByTestId('theme').textContent).toContain('dark:rtl')
    await chooseAppearance('light')
    changeSystem(true)
    expect(screen.getByTestId('theme').textContent).toContain('light:rtl')
    await chooseAppearance('system')
    expect(screen.getByTestId('theme').textContent).toContain('dark:rtl')
    expect(localStorage.getItem(appearanceStorageKey)).toBe('system')
    expect(Object.keys(localStorage).sort()).toEqual(['gwf.appearance', 'gwf.language'])
  })
  it.each(['invalid', 'blocked'])('defaults safely with %s storage and supports changes', async (storage) => {
    systemMedia(true)
    if (storage === 'invalid') localStorage.setItem(appearanceStorageKey, 'not-a-mode')
    else {
      vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked') })
      vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('blocked') })
    }
    render(<I18nextProvider i18n={createI18n('en')}><LanguageProvider><ThemeProbe /><ThemeSelector /></LanguageProvider></I18nextProvider>)
    expect(screen.getByTestId('theme').textContent).toContain('dark:ltr')
    await chooseAppearance('light')
    expect(screen.getByTestId('theme').textContent).toContain('light:ltr')
  })
})

describe('profile menu', () => {
  it.each(['oidc', 'google_iap', 'local_dev'] as const)('displays only identity fields and appropriate %s actions', async (provider) => {
    const { fetcher } = mockAPI({ provider })
    const original = fetcher.getMockImplementation()!
    fetcher.mockImplementation((path, options) => path === '/api/auth/me'
      ? Promise.resolve(Response.json({ ...identity, provider, access_token: 'SECRET_ACCESS', id_token: 'SECRET_ID', client_secret: 'SECRET_CLIENT' }))
      : original(path, options))
    mount('/roles')
    const button = await screen.findByRole('button', { name: 'User profile' })
    expect(button.querySelector('.MuiAvatar-root')?.textContent).toBe('A')
    expect(button.getAttribute('aria-expanded')).toBe('false')
    await userEvent.click(button)
    const menu = await screen.findByRole('menu', { name: 'User profile' })
    expect(button.getAttribute('aria-expanded')).toBe('true')
    for (const value of ['Alice', 'alice@example.test', identity.issuer, identity.subject, { oidc: 'OIDC', google_iap: 'Google IAP', local_dev: 'Local DEV' }[provider]]) {
      expect(within(menu).getByText(value)).toBeTruthy()
    }
    expect(document.body.textContent).not.toMatch(/SECRET_ACCESS|SECRET_ID|SECRET_CLIENT/)
    if (provider === 'oidc') expect(within(menu).getByRole('menuitem', { name: 'Sign out' })).toBeTruthy()
    else {
      expect(within(menu).queryByRole('menuitem')).toBeNull()
      expect(within(menu).getByText(resources.en.auth[provider === 'google_iap' ? 'iapSignOutManaged' : 'localDevIdentity'])).toBeTruthy()
    }
    await userEvent.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull())
    expect(fetcher.mock.calls.some(([path]) => path === '/api/auth/logout')).toBe(false)
    expect(localStorage.length).toBe(0)
  })
})

function NotificationControls() {
  const notify = useNotifications()
  return <>{(['success', 'error', 'warning', 'info'] as AlertColor[]).map((severity) => <button key={severity}
    onClick={() => notify({ severity, messageKey: 'admin:changesSaved' })}>{severity}</button>)}</>
}

describe('global notifications', () => {
  it('supports all severities, queues once per message, translates open messages and dismisses accessibly', async () => {
    const instance = createI18n('en')
    render(<I18nextProvider i18n={instance}><LanguageProvider><NotificationProvider><NotificationControls /></NotificationProvider></LanguageProvider></I18nextProvider>)
    // Click without waiting for transitions: two identical requests enqueue once.
    fireEvent.click(screen.getByRole('button', { name: 'success' }))
    fireEvent.click(screen.getByRole('button', { name: 'success' }))
    for (const severity of ['error', 'warning', 'info']) fireEvent.click(screen.getByRole('button', { name: severity }))
    expect(document.querySelectorAll('.MuiSnackbar-root')).toHaveLength(1)
    await act(() => instance.changeLanguage('ar'))
    expect(screen.getByRole('status').textContent).toContain(resources.ar.admin.changesSaved)
    for (const severity of ['success', 'error', 'warning', 'info']) {
      expect(document.querySelector(`.MuiAlert-color${severity[0].toUpperCase()}${severity.slice(1)}`)).toBeTruthy()
      expect(document.querySelectorAll('.MuiSnackbar-root')).toHaveLength(1)
      await userEvent.click(screen.getByRole('button', { name: resources.ar.common.close }))
    }
    expect(document.querySelector('.MuiSnackbar-root')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'success' }))
    expect(screen.getByRole('status')).toBeTruthy()
  })
  it.each([204, 403])('notifies once for a mutation with HTTP %s while preserving the error and records', async (status) => {
    const { accounts, fetcher } = mockAPI({ writeStatus: status === 403 ? status : undefined })
    const before = JSON.stringify(accounts)
    mount('/accounts')
    const edit = await screen.findByRole('button', { name: 'Edit account: Original account name' })
    await userEvent.click(edit)
    const input = screen.getByRole('textbox', { name: 'Account name' })
    await userEvent.clear(input); await userEvent.type(input, 'Updated')
    await userEvent.click(screen.getByRole('button', { name: 'Save account' }))
    await waitFor(() => expect(document.querySelector('.MuiSnackbar-root')).toBeTruthy())
    const snackbar = document.querySelector('.MuiSnackbar-root') as HTMLElement
    expect(within(snackbar).getByText(resources.en.admin[status === 403 ? 'errorForbidden' : 'changesSaved'])).toBeTruthy()
    expect(document.querySelectorAll('.MuiSnackbar-root')).toHaveLength(1)
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'PUT')).toHaveLength(1)
    if (status === 403) {
      expect(JSON.stringify(accounts)).toBe(before)
      expect(within(screen.getByRole('main')).getByRole('alert').textContent).toBe(resources.en.admin.errorForbidden)
    } else expect(accounts[0].name).toBe('Updated')
  })
})

describe('compact tables and navigation', () => {
  it.each([
    ['/users', 'usersEmpty', 'navUsers'], ['/accounts', 'accountsEmpty', 'navAccounts'],
    ['/roles', 'rolesEmpty', 'navRoles'], ['/audit', 'auditEmpty', 'navAudit'],
  ] as const)('shows a translated empty table for %s without disabling account creation', async (path, emptyKey, titleKey) => {
    const { fetcher } = mockAPI()
    const original = fetcher.getMockImplementation()!
    fetcher.mockImplementation((url, options) => url.startsWith('/api/admin/') ? Promise.resolve(Response.json([])) : original(url, options))
    mount(path, 'ar')
    expect(await screen.findByText(resources.ar.admin[emptyKey])).toBeTruthy()
    const table = screen.getByRole('table', { name: resources.ar.common[titleKey] })
    expect(table.querySelectorAll('th.MuiTableCell-sizeSmall').length).toBeGreaterThan(0)
    expect(getComputedStyle(table.parentElement!).overflowX).toBe('auto')
    expect(table.parentElement!.getAttribute('tabindex')).toBe('0')
    if (path === '/accounts') expect((screen.getByRole('textbox', { name: resources.ar.admin.accountName }) as HTMLInputElement).disabled).toBe(false)
  })
  it.each(['en', 'ar'] as const)('%s: all collapsed navigation icons have translated directional tooltips', async (language) => {
    mockAPI()
    localStorage.setItem('gwf.sidebar.expanded', 'false')
    mount('/', language)
    await screen.findByRole('link', { name: resources[language].common.navUsers })
    for (const key of ['navDashboard', 'navUsers', 'navAccounts', 'navRoles', 'navAudit'] as const) {
      const item = await screen.findByRole('link', { name: resources[language].common[key] })
      await userEvent.hover(item)
      const tooltip = await screen.findByRole('tooltip')
      expect(tooltip.textContent).toBe(resources[language].common[key])
      expect(tooltip.getAttribute('data-popper-placement')).toBe(language === 'ar' ? 'left' : 'right')
      await userEvent.unhover(item)
      await waitFor(() => expect(screen.queryByRole('tooltip')).toBeNull())
    }
  })
})
