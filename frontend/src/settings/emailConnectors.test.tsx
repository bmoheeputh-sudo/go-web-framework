import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { I18nextProvider } from 'react-i18next'
import { MemoryRouter } from 'react-router-dom'
import { createI18n, resources } from '../i18n'
import type { Language } from '../i18n'
import LanguageProvider from '../LanguageProvider'
import NotificationProvider from '../notifications/NotificationProvider'
import QueryProvider from '../api/QueryProvider'
import { SessionContext } from '../auth/session'
import type { Session } from '../auth/session'
import type { ConnectorStatus, EmailConnector } from '../api/emailConnectors'
import { emailConnectorsPath } from '../api/emailConnectors'
import { admin, bob, identity, mockMedia } from '../test/fixtures'
import EmailConnectors from './EmailConnectors'

const en = resources.en.admin
const id = '11111111-1111-4111-8111-111111111111'
function setup(options: { language?: Language; user?: typeof admin; status?: number; provider?: 'gmail' | 'ses'; gmailAvailable?: boolean; malformed?: boolean; readiness?: ConnectorStatus; empty?: boolean; total?: number } = {}) {
  const row: EmailConnector = { id, provider: options.provider || 'ses', sender: 'onboarding@vopak.com', region: options.provider === 'gmail' ? '' : 'eu-west-1', enabled: false, default: false, per_minute: 30, per_day: 1500, generation: 1, failure_count: 0, last_error: '', readiness: { status: options.readiness || 'ready', code: options.readiness || 'ready', quota_known: false, remaining_24_hours: 0, max_per_second: 0 }, has_authorization: false }
  const fetcher = vi.fn(async (path: string, init?: RequestInit) => {
    if (path.startsWith(emailConnectorsPath + '?')) return Response.json({ items: options.empty ? [] : [row], total: options.empty ? 0 : options.total || 1, offset: Number(new URL(path, 'https://app.test').searchParams.get('offset') || 0), limit: 20, gmail_authorization_available: options.gmailAvailable !== false, gmail_callback_url: 'https://app.test/callback', gmail_scopes: ['https://www.googleapis.com/auth/gmail.send', 'https://www.googleapis.com/auth/gmail.settings.basic'] })
    if ((init?.method || 'GET') === 'GET') return Response.json({ ...row, generation: row.generation + 1 })
    if (options.status) return Response.json({ error: 'PRIVATE PROVIDER DETAILS' }, { status: options.status })
    if (options.malformed) return Response.json({ status: 'PRIVATE INVALID RESPONSE' })
    if (path.endsWith('/gmail/authorize')) return Response.json({ authorization_url: 'https://accounts.google.com/o/oauth2/v2/auth?state=fake-state' })
    return Response.json(path === emailConnectorsPath ? { ...row, id: JSON.parse(String(init?.body)).id, readiness: { ...row.readiness, status: 'configured' } } : { ...row, generation: row.generation + 1 })
  })
  vi.stubGlobal('fetch', fetcher)
  const instance = createI18n(options.language || 'en')
  const session: Session = { authentication: { status: 'authenticated', identity }, access: { loading: false, user: options.user || admin, error: '' }, health: 'ok', oidcEnabled: true, loggingOut: false, logoutFailed: false, loginFailed: false, logout: vi.fn(), expire: vi.fn(), refreshAccess: vi.fn() }
  render(<I18nextProvider i18n={instance}><LanguageProvider><NotificationProvider><SessionContext.Provider value={session}><QueryProvider><MemoryRouter><EmailConnectors /></MemoryRouter></QueryProvider></SessionContext.Provider></NotificationProvider></LanguageProvider></I18nextProvider>)
  return { fetcher, instance, session, row }
}
beforeEach(() => { mockMedia(); localStorage.clear(); sessionStorage.clear() })
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })
const writes = (fetcher: ReturnType<typeof setup>['fetcher']) => fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')
async function loaded() { await screen.findByText('onboarding@vopak.com') }
function reason() { fireEvent.change(within(screen.getByRole('dialog')).getByLabelText(en.emailReason + ' *'), { target: { value: 'Approved connector configuration' } }) }

it('lists connectors without invoking provider tests or sending email', async () => {
  const { fetcher } = setup(); await loaded()
  expect(screen.getByText(en.emailReady)).toBeTruthy()
  expect(screen.getByText(en.emailNoDelivery)).toBeTruthy()
  expect(writes(fetcher)).toHaveLength(0)
})
it('creates a disabled SES connector using sender, region and bounded limits', async () => {
  const { fetcher } = setup(); await loaded(); await userEvent.click(screen.getByRole('button', { name: en.emailAddSES }))
  const dialog = screen.getByRole('dialog')
  fireEvent.change(within(dialog).getByLabelText(en.emailSender + ' *'), { target: { value: 'sender@vopak.com' } }); reason()
  await userEvent.click(within(dialog).getByRole('button', { name: en.emailCreate }))
  await waitFor(() => expect(writes(fetcher)).toHaveLength(1))
  const body = JSON.parse(String(writes(fetcher)[0][1]?.body))
  expect(body).toMatchObject({ provider: 'ses', sender: 'sender@vopak.com', region: 'eu-west-1', per_minute: 30, per_day: 1500 })
  expect(body).not.toHaveProperty('access_key'); expect(body).not.toHaveProperty('enabled')
})
it('requires valid fields and confirms discarding changes inside the same dialog', async () => {
  const { fetcher } = setup(); await loaded(); await userEvent.click(screen.getByRole('button', { name: en.emailAddGmail }))
  expect((within(screen.getByRole('dialog')).getByRole('button', { name: en.emailCreate }) as HTMLButtonElement).disabled).toBe(true)
  reason(); fireEvent.change(screen.getByLabelText(en.emailSender + ' *'), { target: { value: 'invalid' } })
  expect((within(screen.getByRole('dialog')).getByRole('button', { name: en.emailCreate }) as HTMLButtonElement).disabled).toBe(true)
  await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: resources.en.common.cancel }))
  expect(screen.getAllByRole('dialog')).toHaveLength(1)
  expect(screen.getByText(en.emailUnsaved)).toBeTruthy(); await userEvent.click(screen.getByRole('button', { name: en.emailDiscard }))
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull()); expect(writes(fetcher)).toHaveLength(0)
})
it('tests only the configured connector, without recipient or message fields', async () => {
  const { fetcher } = setup(); await loaded(); await userEvent.click(screen.getByRole('button', { name: en.emailTest })); reason()
  expect(screen.getByText(en.emailTestExplanation)).toBeTruthy()
  await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: en.emailTest }))
  await waitFor(() => expect(writes(fetcher)).toHaveLength(1))
  expect(writes(fetcher)[0][0]).toBe(`${emailConnectorsPath}/${id}/test`)
  expect(JSON.parse(String(writes(fetcher)[0][1]?.body))).toEqual({ expected_generation: 1, reason: 'Approved connector configuration' })
})
it('enables and selects a tested connector with generation checks', async () => {
  const { fetcher } = setup(); await loaded(); await userEvent.click(screen.getByRole('button', { name: en.emailConfigure })); reason()
  await userEvent.click(screen.getByRole('checkbox', { name: en.emailEnabled })); await userEvent.click(screen.getByRole('checkbox', { name: en.emailDefault }))
  await userEvent.click(screen.getByRole('button', { name: en.emailSave }))
  await waitFor(() => expect(writes(fetcher)).toHaveLength(1)); expect(JSON.parse(String(writes(fetcher)[0][1]?.body))).toMatchObject({ expected_generation: 1, enabled: true, default: true })
})
it('requires explicit Gmail scope consent and opens only the approved Google authorization link', async () => {
  const { fetcher } = setup({ provider: 'gmail' }); await loaded(); await userEvent.click(screen.getByRole('button', { name: en.emailAuthorize })); reason()
  expect(screen.getByText(en.emailScopeWarning)).toBeTruthy()
  expect((within(screen.getByRole('dialog')).getByRole('button', { name: en.emailAuthorize }) as HTMLButtonElement).disabled).toBe(true)
  await userEvent.click(screen.getByRole('checkbox', { name: en.emailScopeConsent })); await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: en.emailAuthorize }))
  const link = await screen.findByRole('link', { name: en.emailContinueGoogle })
  expect(link.getAttribute('href')).toContain('https://accounts.google.com/o/oauth2/v2/auth')
  expect(link.getAttribute('rel')).toContain('noopener')
  expect(JSON.parse(String(writes(fetcher)[0][1]?.body))).toMatchObject({ mailbox: 'onboarding@vopak.com', confirm_sender_settings: true })
  expect(JSON.stringify(localStorage)).not.toContain('fake-state'); expect(JSON.stringify(sessionStorage)).not.toContain('fake-state')
})
it('explains missing Gmail deployment configuration and disables authorization', async () => {
  setup({ provider: 'gmail', gmailAvailable: false }); await loaded()
  expect(screen.getByText(en.emailGmailSetup)).toBeTruthy()
  expect((screen.getByRole('button', { name: en.emailAuthorize }) as HTMLButtonElement).disabled).toBe(true)
})
it.each([409, 503])('preserves inputs and never automatically retries a %s response', async (status) => {
  const { fetcher } = setup({ status }); await loaded(); await userEvent.click(screen.getByRole('button', { name: en.emailConfigure })); reason(); await userEvent.click(screen.getByRole('button', { name: en.emailSave }))
  await screen.findAllByText(status === 409 ? en.emailConflict : en.emailUncertain)
  expect((screen.getByRole('button', { name: en.emailSave }) as HTMLButtonElement).disabled).toBe(true)
  expect((screen.getByLabelText(en.emailReason + ' *') as HTMLInputElement).value).toBe('Approved connector configuration')
  expect(writes(fetcher)).toHaveLength(1); expect(screen.queryByText('PRIVATE PROVIDER DETAILS')).toBeNull()
  await userEvent.click(screen.getByRole('button', { name: en.emailInspect })); await waitFor(() => expect((screen.getByRole('button', { name: en.emailSave }) as HTMLButtonElement).disabled).toBe(false)); expect(writes(fetcher)).toHaveLength(1)
})
it('treats malformed successful mutations as uncertain', async () => {
  const { fetcher } = setup({ malformed: true }); await loaded(); await userEvent.click(screen.getByRole('button', { name: en.emailConfigure })); reason(); await userEvent.click(screen.getByRole('button', { name: en.emailSave }))
  await screen.findAllByText(en.emailUncertain); expect(writes(fetcher)).toHaveLength(1)
})
it('does not read or mutate connector configuration for an unauthorized user', () => {
  const { fetcher } = setup({ user: bob }); expect(screen.getByText(resources.en.common.accessDenied)).toBeTruthy(); expect(fetcher).not.toHaveBeenCalled()
})
it('has all locale keys and preserves edited fields through Arabic RTL changes', async () => {
  const keys = Object.keys(en).filter((key) => key.startsWith('email'))
  for (const locale of Object.values(resources)) for (const key of keys) expect(locale.admin[key]).toBeTruthy()
  const { instance } = setup(); await loaded(); await userEvent.click(screen.getByRole('button', { name: en.emailAddSES })); reason()
  await act(async () => { await instance.changeLanguage('ar') })
  expect(document.documentElement.dir).toBe('rtl'); expect(screen.getByRole('dialog').getAttribute('aria-labelledby')).toBe('email-connector-title')
  expect((screen.getByLabelText(resources.ar.admin.emailReason + ' *') as HTMLInputElement).value).toBe('Approved connector configuration')
})
it.each(['dark', 'light'])('renders connector management in %s appearance', async (appearance) => {
  localStorage.setItem('gwf.appearance', appearance); setup(); await loaded(); expect(screen.getByRole('table', { name: en.emailConnectorsTitle })).toBeTruthy()
})

it('keeps sender addresses on one line, room for actions and no single-page pagination', async () => {
  setup(); await loaded()
  expect(getComputedStyle(screen.getByText('onboarding@vopak.com')).whiteSpace).toBe('nowrap')
  const table = screen.getByRole('table', { name: en.emailConnectorsTitle })
  expect(table.querySelectorAll('th')).toHaveLength(4)
  expect(getComputedStyle(table.querySelector('th:last-child')!).minWidth).toBe('224px')
  expect(screen.queryByRole('navigation')).toBeNull()
  expect(screen.getByText(en.emailDisabled)).toBeTruthy()
})
it.each([['configured', 'emailConfigured'], ['authentication_failed', 'emailAuthenticationFailed']] as const)('distinguishes %s readiness from disabled configuration', async (readiness, key) => {
  setup({ readiness }); await loaded()
  expect(screen.getByText(en[key])).toBeTruthy(); expect(screen.getByText(en.emailDisabled)).toBeTruthy()
  if (readiness === 'authentication_failed') expect(screen.getByText(en.nmState_failed)).toBeTruthy()
})
it('explains empty connector configuration and preserves the missing Gmail warning', async () => {
  setup({ empty: true, gmailAvailable: false }); await screen.findByText(en.emailEmptyHelp)
  expect(screen.getByText(en.emailGmailSetup)).toBeTruthy(); expect(screen.queryByRole('navigation')).toBeNull()
  expect(screen.getByRole('button', { name: en.emailAddSES })).toBeTruthy()
})
it('keeps connector pagination for multiple pages', async () => {
  const { fetcher } = setup({ total: 21 }); await loaded()
  await userEvent.click(within(screen.getByRole('navigation', { name: en.emailConnectorsTitle })).getByRole('button', { name: resources.en.common.nextPage }))
  await waitFor(() => expect(fetcher.mock.calls.some(([path]) => path.includes('offset=20'))).toBe(true))
})
it('uses full-width, wrapping labels for translated sending-limit fields', async () => {
  setup({ language: 'fr' }); await loaded(); await userEvent.click(screen.getByRole('button', { name: resources.fr.admin.emailAddSES }))
  const dialog = screen.getByRole('dialog')
  for (const key of ['emailPerMinute', 'emailPerDay'] as const) {
    const input = within(dialog).getByLabelText(resources.fr.admin[key] + ' *')
    const field = input.closest('.MuiFormControl-root')!
    expect(getComputedStyle(field.querySelector('label')!).whiteSpace).toBe('normal')
    expect(getComputedStyle(field.querySelector('label')!).position).toBe('static')
    expect(input.getAttribute('min')).toBe('1')
  }
})

it('opens compact connector actions with the keyboard in Arabic RTL', async () => {
  vi.stubGlobal('matchMedia', vi.fn((query: string) => ({ matches: query.includes('max-width:599'), media: query, onchange: null, addListener: vi.fn(), removeListener: vi.fn(), addEventListener: vi.fn(), removeEventListener: vi.fn(), dispatchEvent: vi.fn() })))
  setup({ language: 'ar', provider: 'gmail', gmailAvailable: false }); await loaded()
  expect(screen.getByRole('columnheader', { name: resources.ar.auth.actions })).toBeTruthy()
  const button = screen.getByRole('button', { name: resources.ar.admin.emailConnectorActions.replace('{{sender}}', 'onboarding@vopak.com') })
  button.focus(); await userEvent.keyboard('{Enter}')
  const menu = await screen.findByRole('menu')
  expect(document.documentElement.dir).toBe('rtl')
  expect(within(menu).getByRole('menuitem', { name: resources.ar.admin.emailAuthorize }).getAttribute('aria-disabled')).toBe('true')
  await userEvent.keyboard('{Enter}')
  await screen.findByRole('dialog')
  expect(screen.queryByRole('menu')).toBeNull()
  expect(screen.getByText(resources.ar.admin.emailImmutableSender)).toBeTruthy()
})
