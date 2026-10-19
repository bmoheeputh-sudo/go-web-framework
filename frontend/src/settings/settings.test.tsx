import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { I18nextProvider } from 'react-i18next'
import App from '../App'
import LanguageProvider from '../LanguageProvider'
import { createI18n, resources } from '../i18n'
import { bob, mockAPI, mockMedia } from '../test/fixtures'
import type { PermissionCatalog, PermissionChange } from '../api/client'

beforeEach(() => { mockMedia(); localStorage.clear() })
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

function settingsAPI(writeStatus = 0) {
  const fixture = mockAPI()
  const data: PermissionCatalog = {
    revision: 'a'.repeat(64), roles: ['Admin', 'User', 'Viewer'],
    permissions: [
      { name: 'admin.manage', description: 'Administration', module: 'framework', enabled: true, registered: true, known: true, roles: ['Admin'] },
      { name: 'accounts.read', description: 'Read accounts', module: 'framework', enabled: true, registered: true, known: true, roles: ['Viewer'] },
      { name: 'accounts.write', description: 'Write accounts', module: 'framework', enabled: true, registered: true, known: true, roles: ['User'] },
      { name: 'example.read', description: 'Read example', module: 'example', enabled: true, registered: false, known: true, roles: [] },
      { name: 'disabled.read', description: 'Disabled module', module: 'disabled', enabled: false, registered: true, known: true, roles: ['User'] },
      { name: 'legacy.read', description: 'Legacy', module: 'legacy', enabled: false, registered: true, known: false, roles: [] },
    ],
  }
  const original = fixture.fetcher.getMockImplementation()!
  fixture.fetcher.mockImplementation(async (path, init) => {
    if (path !== '/api/admin/permissions' && path !== '/api/admin/role-permissions') return original(path, init)
    if (!init?.method || init.method === 'GET') return Response.json(data)
    if (writeStatus) return Response.json({ error: 'PRIVATE SERVER DETAILS' }, { status: writeStatus })
    const body = JSON.parse(init.body as string)
    if (init.method === 'POST') data.permissions.find((p) => p.name === body.permission)!.registered = true
    else for (const change of body.changes as PermissionChange[]) {
      const permission = data.permissions.find((p) => p.name === change.permission)!
      permission.roles = change.assigned ? [...permission.roles, change.role] : permission.roles.filter((role) => role !== change.role)
    }
    data.revision = 'b'.repeat(64)
    return init.method === 'POST' ? Response.json({ permission: body.permission }, { status: 201 }) : new Response(null, { status: 204 })
  })
  return { ...fixture, data }
}
function mount() {
  const instance = createI18n('en')
  render(<I18nextProvider i18n={instance}><LanguageProvider><MemoryRouter initialEntries={['/settings']}><App /></MemoryRouter></LanguageProvider></I18nextProvider>)
  return instance
}
const cell = async (permission: string, role: string) => await screen.findByRole('checkbox', { name: `${permission} — ${role}` }) as HTMLInputElement
const writes = (fetcher: ReturnType<typeof mockAPI>['fetcher']) => fetcher.mock.calls.filter(([path, init]) => path.startsWith('/api/admin/') && ['POST', 'PUT'].includes(init?.method || ''))

it('shows database assignments without assuming Admin grants and disables protected or unavailable cells', async () => {
  settingsAPI(); mount()
  expect((await cell('accounts.read', 'Admin')).checked).toBe(false)
  expect((await cell('accounts.read', 'Viewer')).checked).toBe(true)
  expect((await cell('accounts.write', 'Admin')).checked).toBe(false)
  expect((await cell('accounts.write', 'User')).checked).toBe(true)
  expect((await cell('admin.manage', 'Admin')).disabled).toBe(true)
  expect((await cell('admin.manage', 'User')).disabled).toBe(true)
  expect((await cell('example.read', 'Admin')).disabled).toBe(true)
  expect((await cell('disabled.read', 'Admin')).disabled).toBe(true)
  expect((await cell('disabled.read', 'User')).disabled).toBe(false)
  expect((await cell('legacy.read', 'Admin')).disabled).toBe(true)
  expect(screen.getByText('Module disabled')).toBeTruthy()
  expect(screen.getByText('Not in this build')).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Settings' })).toBeTruthy()
})

it('preserves unsaved changes when switching to Arabic, and cancel restores the database values', async () => {
  const { fetcher } = settingsAPI(); const instance = mount()
  await userEvent.click(await cell('accounts.write', 'Viewer'))
  expect(screen.getByText(resources.en.admin.unsavedPermissions)).toBeTruthy()
  await act(async () => { await instance.changeLanguage('ar') })
  expect(document.documentElement.dir).toBe('rtl')
  expect((await cell('accounts.write', resources.ar.admin.roleViewer)).checked).toBe(true)
  await userEvent.click(screen.getByRole('button', { name: resources.ar.common.cancel }))
  expect((await cell('accounts.write', resources.ar.admin.roleViewer)).checked).toBe(false)
  expect(writes(fetcher)).toHaveLength(0)
})

it('saves an explicit confirmed revisioned batch and displays one dismissible success notification', async () => {
  const { fetcher, data } = settingsAPI(); mount()
  await userEvent.click(await cell('accounts.write', 'Viewer'))
  await userEvent.click(screen.getByRole('button', { name: 'Save permissions' }))
  expect(writes(fetcher)).toHaveLength(0)
  const dialog = screen.getByRole('dialog')
  expect(within(dialog).getByText('accounts.write')).toBeTruthy()
  await userEvent.click(within(dialog).getByRole('button', { name: 'Confirm' }))
  const toast = await screen.findByRole('status')
  expect(toast.textContent).toContain(resources.en.admin.changesSaved)
  expect(writes(fetcher)).toHaveLength(1)
  expect(JSON.parse(writes(fetcher)[0][1]!.body as string)).toEqual({ revision: 'a'.repeat(64), changes: [{ role: 'Viewer', permission: 'accounts.write', assigned: true }] })
  expect(data.permissions.find((p) => p.name === 'accounts.write')!.roles).toContain('Viewer')
  await userEvent.click(within(toast).getByRole('button', { name: 'Close' }))
  await waitFor(() => expect(screen.queryByRole('status')).toBeNull())
})

it('registers a declared permission only after confirmation and grants no role', async () => {
  const { fetcher, data } = settingsAPI(); mount()
  await userEvent.click(await screen.findByRole('button', { name: 'Register example.read' }))
  expect(writes(fetcher)).toHaveLength(0)
  await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Confirm' }))
  await screen.findByRole('status')
  expect(writes(fetcher)).toHaveLength(1)
  expect(writes(fetcher)[0][0]).toBe('/api/admin/permissions')
  expect(JSON.parse(writes(fetcher)[0][1]!.body as string)).toEqual({ permission: 'example.read' })
  expect(data.permissions.find((p) => p.name === 'example.read')!.roles).toEqual([])
  await waitFor(async () => expect((await cell('example.read', 'Admin')).disabled).toBe(false))
})

it('preserves edits on conflict, shows a localized error toast and does not expose server prose', async () => {
  const { data } = settingsAPI(409); const instance = mount()
  await userEvent.click(await cell('accounts.write', 'Viewer'))
  await userEvent.click(screen.getByRole('button', { name: 'Save permissions' }))
  await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Confirm' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  expect((await cell('accounts.write', 'Viewer')).checked).toBe(true)
  expect(data.permissions.find((p) => p.name === 'accounts.write')!.roles).toEqual(['User'])
  await act(async () => { await instance.changeLanguage('fr') })
  const alerts = await screen.findAllByText(resources.fr.admin.errorConflict)
  expect(alerts).toHaveLength(2) // Existing inline error plus the global notification.
  expect(document.body.textContent).not.toContain('PRIVATE SERVER DETAILS')
  await userEvent.click(screen.getByRole('button', { name: resources.fr.common.cancel }))
  expect((await cell('accounts.write', resources.fr.admin.roleViewer)).checked).toBe(false)
})

it('filters permissions with translated empty states', async () => {
  settingsAPI(); mount(); await cell('accounts.read', 'Admin')
  await userEvent.type(screen.getByRole('textbox', { name: 'Search permissions' }), 'example.read')
  expect(await cell('example.read', 'Admin')).toBeTruthy()
  expect(screen.queryByRole('checkbox', { name: 'accounts.read — Admin' })).toBeNull()
  await userEvent.type(screen.getByRole('textbox', { name: 'Search permissions' }), 'does-not-exist')
  expect(screen.getByText('No matching permissions.')).toBeTruthy()
})

it.each(['User', 'Viewer'])('blocks %s from Settings without fetching the permission catalog', async (role) => {
  const { fetcher } = mockAPI({ user: { ...bob, roles: [role] } }); mount()
  await screen.findByRole('heading', { name: 'Access denied' })
  expect(screen.queryByRole('link', { name: 'Settings' })).toBeNull()
  expect(fetcher.mock.calls.some(([path]) => path === '/api/admin/permissions')).toBe(false)
})
