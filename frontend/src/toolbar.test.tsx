import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { I18nextProvider } from 'react-i18next'
import { MemoryRouter } from 'react-router-dom'
import App from './App'
import { createNavigationRegistry, defaultNavigation } from './navigation/NavigationRegistry'
import type { NavItem } from './navigation/NavigationRegistry'
import LanguageProvider from './LanguageProvider'
import LanguageSelector from './LanguageSelector'
import ThemeSelector from './appearance/ThemeSelector'
import UserProfileMenu from './layout/UserProfileMenu'
import { SessionContext } from './auth/session'
import type { Session } from './auth/session'
import { createI18n, languages, resources } from './i18n'
import type { Language } from './i18n'
import { admin, identity, mockAPI, mockMedia } from './test/fixtures'

beforeEach(() => { localStorage.clear(); mockMedia() })
afterEach(() => { cleanup(); vi.unstubAllGlobals() })
function mountControls(language: Language = 'en') {
  return render(<I18nextProvider i18n={createI18n(language)}><LanguageProvider><LanguageSelector /><ThemeSelector /></LanguageProvider></I18nextProvider>)
}
function mountApp(language: Language = 'en', navigation: readonly NavItem[] = defaultNavigation) {
  return render(<I18nextProvider i18n={createI18n(language)}><LanguageProvider><MemoryRouter initialEntries={['/roles']}><App navigation={navigation} /></MemoryRouter></LanguageProvider></I18nextProvider>)
}
function profileSession(roles = ['Admin']): Session {
  return { authentication: { status: 'authenticated', identity }, access: { loading: false, error: '', user: { ...admin, roles } },
    health: 'connected', oidcEnabled: true, loggingOut: false, logoutFailed: false, loginFailed: false,
    logout: vi.fn(async () => {}), expire: vi.fn(), refreshAccess: vi.fn() }
}
function mountProfile(session: Session, language: Language = 'en') {
  return render(<I18nextProvider i18n={createI18n(language)}><LanguageProvider><SessionContext.Provider value={session}><UserProfileMenu /></SessionContext.Provider></LanguageProvider></I18nextProvider>)
}

describe('compact toolbar menus', () => {
  it('lists all native language names and supports keyboard selection, Escape, and focus restoration', async () => {
    mountControls()
    const trigger = screen.getByRole('button', { name: 'Language' })
    act(() => trigger.focus())
    await userEvent.keyboard('{Enter}')
    const menu = await screen.findByRole('menu', { name: 'Language' })
    expect(within(menu).getAllByRole('menuitemradio').map((item) => item.textContent)).toEqual(Object.values(languages))
    expect(document.activeElement?.textContent).toBe('English')
    expect(within(menu).getByRole('menuitemradio', { name: 'English' }).getAttribute('aria-checked')).toBe('true')
    await userEvent.keyboard('{ArrowDown}{Enter}')
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull())
    expect(localStorage.getItem('gwf.language')).toBe('nl')
    expect(trigger.textContent).toBe('NL')
    expect(document.activeElement).toBe(trigger)
    await userEvent.keyboard(' ')
    await screen.findByRole('menu')
    await userEvent.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull())
    expect(document.activeElement).toBe(trigger)
    await userEvent.tab()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: resources.nl.common.appearance }))
  })
  it('uses mode-specific icons and supports keyboard selection of Light, Dark, and System', async () => {
    mountControls()
    const trigger = screen.getByRole('button', { name: 'Appearance' })
    expect(within(trigger).getByTestId('SettingsBrightnessRoundedIcon')).toBeTruthy()
    for (const [keys, mode, icon] of [
      ['{Home}{Enter}', 'light', 'LightModeRoundedIcon'],
      ['{Home}{ArrowDown}{Enter}', 'dark', 'DarkModeRoundedIcon'],
      ['{End}{Enter}', 'system', 'SettingsBrightnessRoundedIcon'],
    ]) {
      act(() => trigger.focus())
      await userEvent.keyboard('{Enter}')
      const menu = await screen.findByRole('menu', { name: 'Appearance' })
      expect(within(menu).getAllByRole('menuitemradio')).toHaveLength(3)
      await userEvent.keyboard(keys)
      await waitFor(() => expect(screen.queryByRole('menu')).toBeNull())
      expect(localStorage.getItem('gwf.appearance')).toBe(mode)
      expect(within(trigger).getByTestId(icon)).toBeTruthy()
      expect(document.activeElement).toBe(trigger)
    }
    await userEvent.hover(trigger)
    expect((await screen.findByRole('tooltip')).textContent).toBe('Appearance: System')
  })
  it.each(['en', 'ar'] as const)('%s: aligns menu origins with the reading direction', async (language) => {
    mountControls(language)
    // Give Popover actual dimensions, which jsdom cannot measure itself.
    vi.spyOn(HTMLElement.prototype, 'offsetWidth', 'get').mockReturnValue(200)
    vi.spyOn(HTMLElement.prototype, 'offsetHeight', 'get').mockReturnValue(100)
    for (const label of [resources[language].common.language, resources[language].common.appearance]) {
      const trigger = screen.getByRole('button', { name: label })
      vi.spyOn(trigger, 'getBoundingClientRect').mockReturnValue(new DOMRect(300, 20, 60, 40))
      await userEvent.click(trigger)
      const menu = await screen.findByRole('menu', { name: label })
      const paper = menu.closest('.MuiPaper-root') as HTMLElement
      expect(paper.dir).toBe(language === 'ar' ? 'rtl' : 'ltr')
      await waitFor(() => expect(paper.style.left).toBe(language === 'ar' ? '300px' : '160px'))
      expect(paper.style.transformOrigin).toBe(language === 'ar' ? '0px 0px' : '200px 0px')
      await userEvent.keyboard('{Escape}')
      await waitFor(() => expect(screen.queryByRole('menu')).toBeNull())
    }
  })
})

describe('responsive identity button', () => {
  it.each(Object.keys(languages) as Language[])('%s: shows the authenticated name, localized primary role and chevron', async (language) => {
    mountProfile(profileSession(['Viewer', 'User', 'Admin']), language)
    const trigger = screen.getByRole('button', { name: resources[language].auth.profileMenu })
    expect(within(trigger).getByText('Alice')).toBeTruthy()
    expect(within(trigger).getByText(resources[language].admin.roleAdmin)).toBeTruthy()
    expect(within(trigger).getByTestId('ExpandMoreRoundedIcon')).toBeTruthy()
    const description = document.getElementById(trigger.getAttribute('aria-describedby')!)!
    expect(description.textContent).toBe('Alice' + resources[language].admin.roleAdmin)
    await userEvent.click(within(trigger).getByText('Alice'))
    await screen.findByRole('menu', { name: resources[language].auth.profileMenu })
    await userEvent.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull())
    expect(document.activeElement).toBe(trigger)
  })
  it.each([
    [['Viewer', 'User'], 'User'], [['Viewer'], 'Viewer'], [[], 'None'],
  ] as [string[], string][])('displays roles %j without assuming Admin', (roles, expected) => {
    mountProfile(profileSession(roles))
    expect(within(screen.getByRole('button', { name: 'User profile' })).getByText(expected)).toBeTruthy()
  })
  it('uses the authentication API name instead of the framework user record and falls back to the authenticated email', async () => {
    const { fetcher } = mockAPI({ user: { ...admin, display_name: 'Framework record name' } })
    const original = fetcher.getMockImplementation()!
    fetcher.mockImplementation((path, options) => path === '/api/auth/me' ? Promise.resolve(Response.json({ ...identity, display_name: '  ' })) : original(path, options))
    mountApp()
    const trigger = await screen.findByRole('button', { name: 'User profile' })
    expect(within(trigger).getByText(identity.email)).toBeTruthy()
    expect(within(trigger).queryByText('Framework record name')).toBeNull()
  })
  it('truncates long names and preserves the complete name in the menu with keyboard access', async () => {
    const session = profileSession()
    const longName = 'A long authenticated display name '.repeat(10)
    session.authentication = { status: 'authenticated', identity: { ...identity, display_name: longName } }
    mountProfile(session)
    const trigger = screen.getByRole('button', { name: 'User profile' })
    const text = within(trigger).getByText(longName.trim()).closest('.MuiTypography-root')!
    expect(getComputedStyle(text).textOverflow).toBe('ellipsis')
    expect(getComputedStyle(text).whiteSpace).toBe('nowrap')
    expect(getComputedStyle(text).overflow).toBe('hidden')
    await userEvent.hover(trigger)
    expect((await screen.findByRole('tooltip')).textContent).toBe(longName.trim())
    expect(screen.getByRole('button', { name: 'User profile' })).toBe(trigger)
    await userEvent.unhover(trigger)
    act(() => trigger.focus())
    await userEvent.keyboard('{Enter}')
    const menu = await screen.findByRole('menu')
    expect(within(menu).getByText(longName.trim())).toBeTruthy()
    expect(session.logout).not.toHaveBeenCalled()
  })

  it.each(['en', 'ar'] as const)('%s: constrains long names and translated roles at tablet and desktop breakpoints', (language) => {
    const session = profileSession()
    const name = 'Long authenticated name '.repeat(12).trim()
    const role = 'A long localized administrator role '.repeat(10).trim()
    session.authentication = { status: 'authenticated', identity: { ...identity, display_name: name } }
    const instance = createI18n(language)
    instance.addResource(language, 'admin', 'roleAdmin', role)
    render(<I18nextProvider i18n={instance}><LanguageProvider><SessionContext.Provider value={session}><UserProfileMenu /></SessionContext.Provider></LanguageProvider></I18nextProvider>)
    const trigger = screen.getByRole('button', { name: resources[language].auth.profileMenu })
    const details = document.getElementById(trigger.getAttribute('aria-describedby')!)!
    expect(getComputedStyle(details).minWidth).toBe('0px')
    expect(getComputedStyle(details).overflow).toBe('hidden')
    for (const value of [name, role]) {
      const text = within(trigger).getByText(value).closest('.MuiTypography-root')!
      expect(getComputedStyle(text).textOverflow).toBe('ellipsis')
      expect(getComputedStyle(text).whiteSpace).toBe('nowrap')
      expect(getComputedStyle(text).overflow).toBe('hidden')
      expect(getComputedStyle(text).minWidth).toBe('0px')
    }
    // jsdom does not lay out media queries: verify the emitted responsive rules.
    const widths: Record<string, string> = {}
    function collect(rules: CSSRuleList, media = '') {
      for (const rule of Array.from(rules)) {
        if (rule instanceof CSSMediaRule) collect(rule.cssRules, rule.conditionText)
        else if (rule instanceof CSSStyleRule && rule.style.getPropertyValue('max-width') && !rule.selectorText.includes(':') && details.matches(rule.selectorText)) {
          const width = rule.style.getPropertyValue('max-width')
          if (width) widths[media] = width
        }
      }
    }
    for (const sheet of Array.from(document.styleSheets)) collect(sheet.cssRules)
    expect(widths['(min-width:900px)']).toBe('160px')
    expect(widths['(min-width:1200px)']).toBe('220px')
    expect(within(trigger).getByTestId('ExpandMoreRoundedIcon')).toBeTruthy()
    expect(trigger.querySelector('.MuiAvatar-root')).toBeTruthy()
  })
  it('uses the localized placeholder when both the authenticated name and email are empty', async () => {
    const session = profileSession()
    session.authentication = { status: 'authenticated', identity: { ...identity, display_name: '', email: '' } }
    mountProfile(session)
    const trigger = screen.getByRole('button', { name: 'User profile' })
    expect(within(trigger).getByText(resources.en.common.notProvided)).toBeTruthy()
    await userEvent.hover(trigger)
    expect((await screen.findByRole('tooltip')).textContent).toBe(resources.en.common.notProvided)
  })
  it.each(['en', 'ar'] as const)('%s: shows only the avatar on mobile, keeps the toolbar controls together and closes the temporary drawer', async (language) => {
    mockMedia(false)
    mockAPI()
    mountApp(language)
    const profile = await screen.findByRole('button', { name: resources[language].auth.profileMenu })
    expect(profile.querySelector('.MuiAvatar-root')).toBeTruthy()
    expect(within(profile).queryByText('Alice')).toBeNull()
    expect(within(profile).queryByTestId('ExpandMoreRoundedIcon')).toBeNull()
    const controls = profile.closest('.MuiToolbar-root')!.querySelector('#language-selector')!.parentElement!
    expect(controls.contains(profile)).toBe(true)
    expect(controls.querySelector('#appearance-selector')).toBeTruthy()
    expect(getComputedStyle(controls).display).toBe('flex')
    expect(getComputedStyle(controls).flexShrink).toBe('0')
    await userEvent.click(screen.getByRole('button', { name: resources[language].common.openMenu }))
    const paper = document.querySelector('.MuiDrawer-paper')!
    expect(screen.queryByTestId('sidebar-edge')).toBeNull()
    expect(document.getElementById('sidebar-toggle-bottom')).toBeNull()
    const close = within(paper as HTMLElement).getByRole('button', { name: resources[language].common.closeMenu })
    expect(close.closest('.MuiToolbar-root')).toBeTruthy()
    await userEvent.click(close)
    await waitFor(() => expect(screen.queryByRole('navigation')).toBeNull())
    expect(localStorage.getItem('gwf.sidebar.expanded')).toBeNull()
  })
})

describe('floating and bottom sidebar toggles', () => {
  it.each(['en', 'ar'] as const)('%s: positions the edge control on the seam and synchronizes both accessible toggles', async (language) => {
    mockAPI()
    mountApp(language)
    await screen.findByRole('link', { name: resources[language].common.navUsers })
    const rail = screen.getByTestId('sidebar-edge')
    const edge = document.getElementById('sidebar-toggle-edge')!
    const paper = document.querySelector('.MuiDrawer-paper') as HTMLElement
    const header = paper.querySelector('.MuiToolbar-root') as HTMLElement
    expect(edge.closest('.MuiDrawer-root')).toBeNull()
    expect(getComputedStyle(rail).position).toBe('fixed')
    expect(getComputedStyle(rail).overflow).toBe('visible')
    expect(getComputedStyle(rail).pointerEvents).toBe('none')
    expect(getComputedStyle(rail).height).toBe('80px')
    expect(getComputedStyle(rail).transition).toContain('width')
    expect(rail.style[language === 'ar' ? 'right' : 'left']).toBe('0px')
    expect(rail.style[language === 'ar' ? 'left' : 'right']).toBe('auto')
    expect(getComputedStyle(edge).position).toBe('absolute')
    expect(getComputedStyle(edge).width).toBe('24px')
    expect(getComputedStyle(edge).height).toBe('24px')
    expect(getComputedStyle(edge).top).toBe('calc(50% - 12px)')
    expect(getComputedStyle(edge).pointerEvents).toBe('auto')
    expect(getComputedStyle(edge).borderTopWidth).toBe('1px')
    expect(getComputedStyle(edge).boxShadow).not.toBe('none')
    expect(edge.style[language === 'ar' ? 'left' : 'right']).toBe('-12px')
    expect(edge.style[language === 'ar' ? 'right' : 'left']).toBe('auto')
    for (const expanded of [true, false, true]) {
      const label = resources[language].common[expanded ? 'collapseSidebar' : 'expandSidebar']
      const toggles = screen.getAllByRole('button', { name: label })
      expect(toggles).toHaveLength(2)
      for (const toggle of toggles) expect(toggle.getAttribute('aria-expanded')).toBe(String(expanded))
      const width = expanded ? '260px' : '68px'
      expect(getComputedStyle(rail).width).toBe(width)
      expect(getComputedStyle(paper).width).toBe(width)
      expect(getComputedStyle(header).flexWrap).toBe('nowrap')
      const chevron = (expanded !== (language === 'ar')) ? 'ChevronLeftRoundedIcon' : 'ChevronRightRoundedIcon'
      for (const toggle of toggles) expect(within(toggle).getByTestId(chevron)).toBeTruthy()
      const bottom = document.getElementById('sidebar-toggle-bottom')!
      if (expanded) {
        expect(bottom.textContent).toBe(label)
        expect(within(header).getByText(resources[language].common.appName)).toBeTruthy()
      } else {
        expect(bottom.textContent).toBe('')
        expect(header.querySelectorAll('svg')).toHaveLength(1)
        expect(header.querySelector('button')).toBeNull()
        expect(within(header).queryByText(resources[language].common.appName)).toBeNull()
      }
      // The edge collapses; the bottom control expands the same state.
      const trigger = expanded ? edge : bottom
      act(() => trigger.focus())
      await userEvent.keyboard(expanded ? '{Enter}' : ' ')
      expect(localStorage.getItem('gwf.sidebar.expanded')).toBe(String(!expanded))
    }
    // The floating button's focus ring is explicit and the translated tooltip remains accessible.
    act(() => screen.getByRole('link', { name: resources[language].common.navDashboard }).focus())
    await userEvent.tab({ shift: true })
    expect(document.activeElement).toBe(edge)
    expect(edge.classList.contains('Mui-focusVisible')).toBe(true)
    expect(getComputedStyle(edge).outlineOffset).toBe('2px')
    await userEvent.hover(edge)
    expect((await screen.findByRole('tooltip')).textContent).toBe(resources[language].common.expandSidebar)
  })
  it('keeps the footer outside the scroll region for long navigation lists', async () => {
    mockAPI()
    mountApp('en', createNavigationRegistry(Array.from({ length: 40 }, (_, index) => ({
      path: `/extra-${index}`, labelKey: 'common:navDashboard', icon: <span>R</span>, element: <div>Report</div>,
    }))))
    await screen.findByRole('link', { name: 'Users' })
    const nav = screen.getByRole('navigation')
    expect(within(nav).getAllByRole('link')).toHaveLength(45)
    const bottom = document.getElementById('sidebar-toggle-bottom')!
    const footer = bottom.parentElement!
    const paper = bottom.closest('.MuiDrawer-paper')!
    expect(getComputedStyle(nav).overflowY).toBe('auto')
    expect(getComputedStyle(nav).minHeight).toBe('0px')
    expect(getComputedStyle(footer).flexShrink).toBe('0')
    expect(getComputedStyle(paper).overflowY).toBe('hidden')
    expect(nav.contains(bottom)).toBe(false)
    nav.scrollTop = 1000
    await userEvent.click(bottom)
    expect(getComputedStyle(paper).width).toBe('68px')
    expect(document.getElementById('sidebar-toggle-edge')!.getAttribute('aria-expanded')).toBe('false')
  })
})
