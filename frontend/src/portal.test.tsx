import { chooseLanguage } from './test/menuActions'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { StrictMode } from 'react'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { BrowserRouter, MemoryRouter, useNavigate } from 'react-router-dom'
import { I18nextProvider } from 'react-i18next'
import { Button } from '@mui/material'
import App from './App'
import LanguageProvider from './LanguageProvider'
import { createI18n, formatDate, resources } from './i18n'
import type { Language } from './i18n'
import { createNavigationRegistry, defaultNavigation } from './navigation/NavigationRegistry'
import type { NavItem } from './navigation/NavigationRegistry'
import { canAccess } from './navigation/authorization'
import { admin, auditEvent, bob, mockAPI, mockMedia } from './test/fixtures'

beforeEach(() => { localStorage.clear(); window.history.replaceState(null, '', '/'); mockMedia() })
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function HistoryControls() {
  const navigate = useNavigate()
  return <><Button onClick={() => navigate(-1)}>Test back</Button><Button onClick={() => navigate(1)}>Test forward</Button></>
}
function mount({ path = '/', language = 'en', navigation = defaultNavigation, browser = false }: { path?: string; language?: Language; navigation?: readonly NavItem[]; browser?: boolean } = {}) {
  const instance = createI18n(language)
  if (browser) window.history.replaceState(null, '', path)
  const content = <><App navigation={navigation} /><HistoryControls /></>
  const view = render(<I18nextProvider i18n={instance}><LanguageProvider>
    {browser ? <BrowserRouter>{content}</BrowserRouter> : <MemoryRouter initialEntries={[path]}>{content}</MemoryRouter>}
  </LanguageProvider></I18nextProvider>)
  return { ...view, instance }
}
async function link(name: string) { await userEvent.click(await screen.findByRole('link', { name })) }
async function select(label: string, option: string) {
  if (label === 'User' || label === 'Utilisateur' || label === 'Account to edit') {
    const key = label === 'Account to edit' ? resources.en.admin.editAccount : resources[label === 'Utilisateur' ? 'fr' : 'en'].admin.selectUser
    const control = await screen.findByRole('button', { name: key.replace('{{name}}', option.split(' — ')[0]) })
    await waitFor(() => expect((control as HTMLButtonElement).disabled).toBe(false))
    await userEvent.click(control)
    return
  }
  const control = await screen.findByRole('combobox', { name: label })
  await waitFor(() => expect(control.getAttribute('aria-disabled')).not.toBe('true'))
  fireEvent.mouseDown(control)
  await userEvent.click(await screen.findByRole('option', { name: option }))
}
const writes = (fetcher: ReturnType<typeof mockAPI>['fetcher']) => fetcher.mock.calls.filter(([, options]) => ['PUT', 'POST'].includes(options?.method || ''))

// Route definitions are application-owned, never supplied by an end user.
describe('navigation registry and route authorization', () => {
  const reports: NavItem = { path: '/reports/daily', labelKey: 'common:reports', icon: <span>R</span>, element: <div>Custom report page</div>, requiredRole: 'Viewer', requiredPermission: 'accounts.read' }
  it('registers an additional nested URL and renders it through the reusable layout', async () => {
    mockAPI({ user: { ...bob, active: true } })
    const { instance } = mount({ path: '/reports/daily', navigation: createNavigationRegistry([reports]) })
    instance.addResource('en', 'common', 'reports', 'Reports')
    expect(await screen.findByText('Custom report page')).toBeTruthy()
    expect(screen.getByRole('navigation').querySelector('a[href="/reports/daily"]')).toBeTruthy()
    expect(screen.getByRole('heading', { level: 1 }).textContent).toBe('Reports')
  })
  it('rejects duplicate, external, API, and contradictory public definitions', () => {
    expect(() => createNavigationRegistry([{ ...reports, path: '/users' }])).toThrow('Duplicate')
    expect(() => createNavigationRegistry([{ ...reports, path: '//example.test' }])).toThrow('static application paths')
    expect(() => createNavigationRegistry([{ ...reports, path: '/api/auth/login' }])).toThrow('outside /api')
    expect(() => createNavigationRegistry([{ ...reports, public: true }])).toThrow('Public navigation')
  })
  it('requires both role and permission and an active authenticated user', () => {
    expect(canAccess(reports, bob)).toBe(true)
    expect(canAccess(reports, { ...bob, permissions: [] })).toBe(false)
    expect(canAccess(reports, { ...bob, roles: [] })).toBe(false)
    expect(canAccess(reports, { ...bob, active: false })).toBe(false)
    expect(canAccess(reports, null)).toBe(false)
  })
  it.each(['User', 'Viewer', 'none'])('filters admin links and denies direct access for %s', async (role) => {
    const { fetcher } = mockAPI({ user: { ...bob, roles: role === 'none' ? [] : [role], permissions: role === 'none' ? [] : ['accounts.read'] } })
    mount({ path: '/users' })
    expect(await screen.findByRole('heading', { name: 'Access denied' })).toBeTruthy()
    expect(screen.queryByRole('link', { name: 'Users' })).toBeNull()
    expect(screen.getAllByRole('link').map((node) => node.getAttribute('href'))).toEqual(['/'])
    expect(fetcher.mock.calls.some(([path]) => path.startsWith('/api/admin/'))).toBe(false)
    expect(screen.queryByRole('table', { name: 'Users' })).toBeNull()
  })
  it('does not grant access from the Admin role alone without its required permission', async () => {
    mockAPI({ user: { ...admin, permissions: [] } })
    mount({ path: '/roles', language: 'fr' })
    await screen.findByRole('heading', { name: 'Accès refusé' })
    expect(screen.queryByRole('link', { name: 'Rôles' })).toBeNull()
  })
  it.each(['/users', '/accounts', '/roles', '/audit'])('guards direct Viewer access to %s before loading its data', async (path) => {
    const { fetcher } = mockAPI({ user: bob })
    mount({ path })
    await screen.findByRole('heading', { name: 'Access denied' })
    expect(fetcher.mock.calls.some(([url]) => url.startsWith('/api/admin/'))).toBe(false)
  })
  it('denies an inactive administrator even if their response contains admin permissions', async () => {
    mockAPI({ user: { ...admin, active: false } })
    mount({ path: '/accounts' })
    await screen.findByRole('heading', { name: 'Access denied' })
    expect(screen.queryByRole('textbox', { name: 'Account name' })).toBeNull()
  })
  it('shows the access-denied page when the backend refuses framework access', async () => {
    const { fetcher } = mockAPI({ accessStatus: 403 })
    mount({ path: '/users' })
    await screen.findByRole('heading', { name: 'Access denied' })
    expect(fetcher.mock.calls.some(([path]) => path.startsWith('/api/admin/'))).toBe(false)
  })
  it('loads direct URLs and supports browser back/forward without reauthenticating', async () => {
    const { fetcher } = mockAPI()
    mount({ path: '/users', browser: true })
    await screen.findByRole('button', { name: 'Select user: Bob' })
    expect(screen.getByRole('link', { name: 'Users' }).getAttribute('aria-current')).toBe('page')
    await link('Accounts')
    await screen.findByRole('textbox', { name: 'Account name' })
    expect(window.location.pathname).toBe('/accounts')
    await userEvent.click(screen.getByRole('button', { name: 'Test back' }))
    await screen.findByRole('button', { name: 'Select user: Bob' })
    expect(window.location.pathname).toBe('/users')
    await userEvent.click(screen.getByRole('button', { name: 'Test forward' }))
    await screen.findByRole('textbox', { name: 'Account name' })
    expect(window.location.pathname).toBe('/accounts')
    for (const path of ['/api/auth/me', '/api/access/me', '/api/auth/config', '/api/admin/users?offset=0', '/api/admin/accounts?offset=0']) {
      expect(fetcher.mock.calls.filter(([url]) => url === path)).toHaveLength(1)
    }
  })
  it('does not load unrelated administration data on the dashboard or roles page', async () => {
    const { fetcher } = mockAPI()
    mount()
    await screen.findByText('Original account name')
    expect(fetcher.mock.calls.some(([path]) => path.startsWith('/api/admin/'))).toBe(false)
    await link('Roles')
    await screen.findByText(/Manage administration/)
    expect(fetcher.mock.calls.filter(([path]) => path.startsWith('/api/admin/')).map(([path]) => path)).toEqual(['/api/admin/roles'])
  })
  it('shows translated 404 content and returns to the dashboard through a router link', async () => {
    mockAPI()
    mount({ path: '/missing/deep/url', language: 'ar' })
    await screen.findByRole('heading', { level: 2, name: resources.ar.common.pageNotFound })
    await screen.findByRole('link', { name: resources.ar.common.navUsers })
    await link(resources.ar.common.backDashboard)
    await screen.findByText(resources.ar.common.backendStatus)
    expect(screen.queryByText('404')).toBeNull()
  })
})

describe('responsive mini drawer', () => {
  it('persists desktop widths, hides collapsed labels, and keeps accessible links', async () => {
    mockAPI()
    const view = mount()
    await screen.findByRole('link', { name: 'Users' })
    let paper = document.querySelector('.MuiDrawer-paper')!
    expect(getComputedStyle(paper).width).toBe('260px')
    expect(getComputedStyle(paper).overflowX).toBe('hidden')
    await userEvent.click(screen.getAllByRole('button', { name: 'Collapse sidebar' })[0])
    expect(getComputedStyle(paper).width).toBe('68px')
    expect(getComputedStyle(paper).transition).toContain('width')
    expect(localStorage.getItem('gwf.sidebar.expanded')).toBe('false')
    expect(getComputedStyle(screen.getByRole('link', { name: 'Users' }).querySelector('.MuiListItemText-root')!).display).toBe('none')
    view.unmount()
    mount()
    await screen.findByRole('link', { name: 'Users' })
    paper = document.querySelector('.MuiDrawer-paper')!
    expect(getComputedStyle(paper).width).toBe('68px')
    await userEvent.click(screen.getAllByRole('button', { name: 'Expand sidebar' })[0])
    expect(getComputedStyle(paper).width).toBe('260px')
    expect(localStorage.getItem('gwf.sidebar.expanded')).toBe('true')
  })
  it('works if preference storage is blocked', async () => {
    mockAPI()
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked') })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('blocked') })
    mount()
    await screen.findByRole('link', { name: 'Users' })
    await userEvent.click(screen.getAllByRole('button', { name: 'Collapse sidebar' })[0])
    expect(getComputedStyle(document.querySelector('.MuiDrawer-paper')!).width).toBe('68px')
  })
  it.each(['en', 'ar'] as const)('%s: pins drawer to the correct edge and positions collapsed tooltips', async (language) => {
    mockAPI()
    localStorage.setItem('gwf.sidebar.expanded', 'false')
    const { instance } = mount({ language })
    const users = await screen.findByRole('link', { name: resources[language].common.navUsers })
    const paper = document.querySelector('.MuiDrawer-paper') as HTMLElement
    expect(paper.style[language === 'ar' ? 'right' : 'left']).toBe('0px')
    expect(paper.style[language === 'ar' ? 'left' : 'right']).toBe('auto')
    expect(document.querySelector(language === 'ar' ? '.MuiDrawer-anchorRight' : '.MuiDrawer-anchorLeft')).toBeTruthy()
    await userEvent.hover(users)
    const tooltip = await screen.findByRole('tooltip')
    expect(tooltip.getAttribute('data-popper-placement')).toBe(language === 'ar' ? 'left' : 'right')
    await userEvent.unhover(users)
    await act(() => instance.changeLanguage(language === 'ar' ? 'en' : 'ar'))
    expect(paper.style[language === 'ar' ? 'left' : 'right']).toBe('0px')
    await userEvent.click(screen.getAllByRole('button', { name: resources[language === 'ar' ? 'en' : 'ar'].common.expandSidebar })[0])
    expect(getComputedStyle(paper).width).toBe('260px')
  })
  it.each(['en', 'ar'] as const)('%s: opens a temporary mobile drawer, closes on navigation and Escape', async (language) => {
    mockMedia(false)
    mockAPI()
    mount({ language })
    await screen.findByText('Original account name')
    expect(screen.queryByRole('navigation')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: resources[language].common.openMenu }))
    const menu = await screen.findByRole('navigation')
    expect(menu.closest('.MuiModal-root')).toBeTruthy()
    const paper = document.querySelector('.MuiDrawer-paper') as HTMLElement
    expect(getComputedStyle(paper).maxWidth).toBe('calc(100vw - 24px)')
    expect(paper.style[language === 'ar' ? 'right' : 'left']).toBe('0px')
    await link(resources[language].common.navUsers)
    await screen.findByRole('button', { name: resources[language].admin.selectUser.replace('{{name}}', 'Bob') })
    await waitFor(() => expect(screen.queryByRole('navigation')).toBeNull())
    await userEvent.click(screen.getByRole('button', { name: resources[language].common.openMenu }))
    await screen.findByRole('navigation')
    const closingPaper = document.querySelector('.MuiDrawer-paper') as HTMLElement
    vi.spyOn(closingPaper, 'getBoundingClientRect').mockReturnValue(new DOMRect(language === 'ar' ? 100 : 0, 0, 260, 800))
    vi.spyOn(closingPaper.closest('.MuiModal-root')!, 'getBoundingClientRect').mockReturnValue(new DOMRect(0, 0, 360, 800))
    await userEvent.keyboard('{Escape}')
    expect(closingPaper.style.transform).toBe(language === 'ar' ? 'translateX(260px)' : 'translateX(-260px)')
    await waitFor(() => expect(screen.queryByRole('navigation')).toBeNull())
    expect(localStorage.getItem('gwf.sidebar.expanded')).toBeNull()
  })
  it('does not reopen the mobile drawer when returning to an earlier history entry', async () => {
    mockMedia(false)
    mockAPI()
    mount({ browser: true })
    await screen.findByText('Original account name')
    await userEvent.click(screen.getByRole('button', { name: 'Open menu' }))
    await link('Users')
    await screen.findByRole('button', { name: 'Select user: Bob' })
    await userEvent.click(screen.getByRole('button', { name: 'Open menu' }))
    await screen.findByRole('navigation')
    act(() => window.history.back())
    await waitFor(() => expect(window.location.pathname).toBe('/'))
    await waitFor(() => expect(screen.queryByRole('navigation')).toBeNull())
    act(() => window.history.forward())
    await screen.findByRole('button', { name: 'Select user: Bob' })
    expect(screen.queryByRole('navigation')).toBeNull()
  })
})

describe('administration operations', () => {
  it('retains the shell, selected user, and scroll position during a delayed AJAX refresh', async () => {
    const { fetcher } = mockAPI()
    const original = fetcher.getMockImplementation()!
    let resolveRefresh: (response: Response) => void = () => {}
    let userReads = 0
    fetcher.mockImplementation((path, init) => {
      if (path === '/api/admin/users?offset=0' && (!init || init.method === 'GET')) {
        userReads++
        if (userReads === 2) return new Promise<Response>((resolve) => { resolveRefresh = resolve })
      }
      return original(path, init)
    })
    mount({ path: '/users' })
    await select('User', 'Bob — bob@example.test')
    const main = screen.getByRole('main')
    main.scrollTop = 321
    await userEvent.click(screen.getByRole('button', { name: 'Deactivate user' }))
    await waitFor(() => expect(userReads).toBe(2))
    expect(screen.getByRole('main')).toBe(main)
    expect(main.scrollTop).toBe(321)
    expect(screen.getByText('User ID: user-2')).toBeTruthy()
    expect(screen.getByRole('table', { name: 'Users' })).toBeTruthy()
    resolveRefresh(Response.json([admin, { ...bob, active: false }]))
    await screen.findByRole('button', { name: 'Activate user' })
  })
  it('preserves Admin confirmation, role payloads, activation, and prevents self-change', async () => {
    const { fetcher, users } = mockAPI()
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    mount({ path: '/users', language: 'fr' })
    await select('Utilisateur', 'Bob — bob@example.test')
    await userEvent.click(screen.getByRole('checkbox', { name: 'Administrateur' }))
    expect(writes(fetcher)).toHaveLength(0)
    confirm.mockReturnValue(true)
    await userEvent.click(screen.getByRole('checkbox', { name: 'Administrateur' }))
    await waitFor(() => expect(users[1].roles).toEqual(['Viewer', 'Admin']))
    expect(JSON.parse(writes(fetcher)[0][1]!.body as string)).toEqual({ roles: ['Viewer', 'Admin'] })
    expect(confirm).toHaveBeenCalledWith(createI18n('fr').t('admin:grantAdmin', { issuer: bob.issuer, subject: bob.subject }))
    await userEvent.click(await screen.findByRole('button', { name: 'Désactiver l’utilisateur' }))
    await waitFor(() => expect(users[1].active).toBe(false))
    await select('Utilisateur', 'Alice — alice@example.test')
    expect((screen.getByRole('checkbox', { name: 'Administrateur' }) as HTMLInputElement).disabled).toBe(true)
    expect((screen.getByRole('button', { name: 'Désactiver l’utilisateur' }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText(resources.fr.admin.selfRestriction)).toBeTruthy()
  })
  it('links and unlinks accounts without translating payloads or account names', async () => {
    const { fetcher, users } = mockAPI()
    mount({ path: '/users' })
    await select('User', 'Bob — bob@example.test')
    await select('Account to link', 'Original account name')
    await userEvent.click(screen.getByRole('button', { name: 'Link account' }))
    await waitFor(() => expect(users[1].account_ids).toEqual(['account-1']))
    expect(JSON.parse(writes(fetcher)[0][1]!.body as string)).toEqual({ account_ids: ['account-1'] })
    const chip = (await screen.findAllByText('Original account name')).find((node) => node.closest('.MuiChip-root'))!.closest('.MuiChip-root')!
    fireEvent.click(chip.querySelector('.MuiChip-deleteIcon')!)
    await waitFor(() => expect(users[1].account_ids).toEqual([]))
    expect(JSON.parse(writes(fetcher)[1][1]!.body as string)).toEqual({ account_ids: [] })
  })
  it('creates and edits accounts with the existing endpoints', async () => {
    const { accounts, fetcher } = mockAPI()
    mount({ path: '/accounts' })
    const name = await screen.findByRole('textbox', { name: 'Account name' })
    await waitFor(() => expect((name as HTMLInputElement).disabled).toBe(false))
    await userEvent.type(name, ' New account ')
    await userEvent.click(screen.getByRole('button', { name: 'Create account' }))
    await waitFor(() => expect(accounts).toHaveLength(2))
    expect(writes(fetcher)[0][0]).toBe('/api/admin/accounts')
    expect(JSON.parse(writes(fetcher)[0][1]!.body as string)).toEqual({ name: 'New account', active: true })
    await select('Account to edit', 'New account')
    await userEvent.clear(name)
    await userEvent.type(name, 'Renamed account')
    await userEvent.click(screen.getByRole('checkbox', { name: 'Active account' }))
    await userEvent.click(screen.getByRole('button', { name: 'Save account' }))
    await waitFor(() => expect(accounts[1]).toEqual({ id: 'account-2', name: 'Renamed account', active: false }))
    expect(writes(fetcher)[1][0]).toBe('/api/admin/accounts/account-2')
  })
  it('preserves unsaved form input and avoids requests when switching language', async () => {
    const { fetcher } = mockAPI()
    mount({ path: '/accounts' })
    const name = await screen.findByRole('textbox', { name: 'Account name' })
    await waitFor(() => expect((name as HTMLInputElement).disabled).toBe(false))
    await userEvent.type(name, 'Original user-created data')
    const count = fetcher.mock.calls.length
    await chooseLanguage('ar')
    expect((screen.getByRole('textbox', { name: resources.ar.admin.accountName }) as HTMLInputElement).value).toBe('Original user-created data')
    expect(fetcher.mock.calls).toHaveLength(count)
  })
  it('links accounts beyond the first page without reloading the selected user', async () => {
    const { accounts, users, fetcher } = mockAPI()
    for (let i = 2; i <= 101; i++) accounts.push({ id: `account-${i}`, name: `Account ${i}`, active: true })
    mount({ path: '/users' })
    await select('User', 'Bob — bob@example.test')
    await userEvent.click(within(screen.getByRole('group', { name: 'Linked accounts' })).getByRole('button', { name: 'Next page' }))
    await select('Account to link', 'Account 101')
    expect(fetcher.mock.calls.filter(([path]) => path === '/api/admin/users?offset=0')).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: 'Link account' }))
    await waitFor(() => expect(users[1].account_ids).toEqual(['account-101']))
  })
  it.each([403, 409])('shows a translated HTTP %s without changing records on rejected writes', async (writeStatus) => {
    const { users, fetcher, audit } = mockAPI({ writeStatus })
    const before = JSON.stringify({ users, audit })
    mount({ path: '/users' })
    await select('User', 'Bob — bob@example.test')
    await userEvent.click(screen.getByRole('button', { name: 'Deactivate user' }))
    expect((await within(screen.getByRole('main')).findByRole('alert')).textContent).toBe(resources.en.admin[writeStatus === 403 ? 'errorForbidden' : 'errorConflict'])
    expect(JSON.stringify({ users, audit })).toBe(before)
    expect(writes(fetcher)).toHaveLength(1)
    expect(screen.queryByText('UNTRUSTED SERVER DETAILS')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Refresh administration' }))
    await waitFor(() => expect(within(screen.getByRole('main')).queryByRole('alert')).toBeNull())
  })
  it('shows localized audit events and unchanged raw JSON, paginates, and refreshes', async () => {
    const { audit, fetcher } = mockAPI()
    for (let i = 2; i <= 101; i++) audit.push({ ...auditEvent, id: String(i), details: { record: i } })
    const { instance } = mount({ path: '/audit', language: 'fr' })
    await screen.findByText(JSON.stringify(auditEvent.details))
    expect(screen.getAllByText(`${formatDate(auditEvent.created_at, 'fr')} — ${resources.fr.admin.actionRoles}`)).toHaveLength(100)
    const count = fetcher.mock.calls.length
    await act(() => instance.changeLanguage('ar'))
    expect(screen.getAllByText(`${formatDate(auditEvent.created_at, 'ar')} — ${resources.ar.admin.actionRoles}`)).toHaveLength(100)
    expect(fetcher.mock.calls).toHaveLength(count)
    await userEvent.click(screen.getByRole('button', { name: resources.ar.common.nextPage }))
    await screen.findByText('{"record":101}')
    expect(screen.getAllByRole('row').slice(1)).toHaveLength(1)
    await userEvent.click(screen.getByRole('button', { name: resources.ar.admin.refresh }))
    await waitFor(() => expect(fetcher.mock.calls.filter(([path]) => path === '/api/admin/audit?offset=100')).toHaveLength(2))
  })
  it('invalidates cached audit and account lists after a successful change', async () => {
    const { fetcher } = mockAPI()
    mount({ path: '/audit' })
    await screen.findByText(JSON.stringify(auditEvent.details))
    await link('Accounts')
    await select('Account to edit', 'Original account name')
    await userEvent.click(screen.getByRole('button', { name: 'Save account' }))
    await waitFor(() => expect(writes(fetcher)).toHaveLength(1))
    await link('Audit logs')
    await waitFor(() => expect(screen.getAllByRole('row').slice(1)).toHaveLength(2))
    expect(fetcher.mock.calls.filter(([path]) => path === '/api/admin/audit?offset=0')).toHaveLength(2)
  })
})

describe('authentication and cache boundaries', () => {
  it('loads protected pages correctly under React StrictMode effect replay', async () => {
    mockAPI()
    render(<StrictMode><I18nextProvider i18n={createI18n('en')}><LanguageProvider><MemoryRouter initialEntries={['/users']}><App /></MemoryRouter></LanguageProvider></I18nextProvider></StrictMode>)
    await select('User', 'Bob — bob@example.test')
    expect(screen.getByRole('checkbox', { name: 'Viewer' })).toBeTruthy()
  })
  it('retains the OIDC login URL on unauthenticated nested routes', async () => {
    const { fetcher } = mockAPI({ authenticated: false })
    mount({ path: '/users' })
    expect((await screen.findByRole('link', { name: 'Sign in' })).getAttribute('href')).toBe('/api/auth/login')
    expect(fetcher.mock.calls.some(([path]) => path.startsWith('/api/admin/') || path === '/api/access/me')).toBe(false)
  })
  it.each(['google_iap', 'local_dev'] as const)('preserves %s authentication without OIDC login/logout controls', async (provider) => {
    mockAPI({ provider })
    mount()
    await screen.findByText('Original account name')
    await userEvent.click(screen.getByRole('button', { name: 'User profile' }))
    await screen.findByText(resources.en.auth[provider === 'google_iap' ? 'iapSignOutManaged' : 'localDevIdentity'])
    expect(screen.queryByRole('menuitem', { name: 'Sign out' })).toBeNull()
    await userEvent.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull())
    expect(screen.queryByRole('link', { name: 'Sign in' })).toBeNull()
    await link('Users')
    await screen.findByRole('button', { name: 'Select user: Bob' })
  })
  it('clears protected content on OIDC logout, including back navigation', async () => {
    const { fetcher } = mockAPI()
    mount({ path: '/users' })
    await select('User', 'Bob — bob@example.test')
    await link('Audit logs')
    await screen.findByText(JSON.stringify(auditEvent.details))
    await userEvent.click(screen.getByRole('button', { name: 'User profile' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Sign out' }))
    await screen.findByRole('link', { name: 'Sign in' })
    expect(screen.queryByText(JSON.stringify(auditEvent.details))).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Test back' }))
    expect(screen.queryByRole('table', { name: 'Users' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'Users' })).toBeNull()
    expect(fetcher).toHaveBeenCalledWith('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
    expect(localStorage.length).toBe(0)
  })
  it('keeps the current session visible when logout fails and translates the failure', async () => {
    mockAPI({ logoutStatus: 503 })
    mount({ path: '/roles', language: 'nl' })
    await screen.findByText(new RegExp(resources.nl.admin.permissionAdmin))
    await userEvent.click(screen.getByRole('button', { name: resources.nl.auth.profileMenu }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Afmelden' }))
    expect((await screen.findByRole('alert')).textContent).toBe(resources.nl.auth.logoutFailed)
    expect(screen.getByRole('link', { name: 'Gebruikers' })).toBeTruthy()
  })
  it('expires the UI session when an API returns 401', async () => {
    const { responses } = mockAPI()
    mount()
    await screen.findByRole('link', { name: 'Users' })
    responses.set('/api/admin/users?offset=0', 401)
    await link('Users')
    await screen.findByRole('link', { name: 'Sign in' })
    expect(screen.queryByRole('table', { name: 'Users' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'Users' })).toBeNull()
  })
  it('refreshes changed access and removes revoked navigation permissions', async () => {
    const { current } = mockAPI()
    mount()
    await screen.findByRole('link', { name: 'Users' })
    current.permissions = ['accounts.read']; current.roles = ['Viewer']
    await userEvent.click(screen.getByRole('button', { name: 'Refresh access' }))
    await waitFor(() => expect(screen.queryByRole('link', { name: 'Users' })).toBeNull())
    await within(screen.getByRole('main')).findByText('Viewer')
    expect(within(screen.getByRole('navigation')).getAllByRole('link')).toHaveLength(1)
  })
})
