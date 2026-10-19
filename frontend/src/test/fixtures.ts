import { vi } from 'vitest'
import type { Account, Audit, Identity, Role, User } from '../api/client'

export const identity: Identity = { issuer: 'https://issuer.test', subject: 'subject-1', email: 'alice@example.test', email_verified: true, display_name: 'Alice', provider: 'oidc' }
export const admin: User = { ...identity, id: 'admin-1', active: true, roles: ['Admin'], permissions: ['admin.manage', 'accounts.read', 'accounts.write'], account_ids: ['account-1'] }
export const bob: User = { ...admin, id: 'user-2', subject: 'subject-2', display_name: 'Bob', email: 'bob@example.test', roles: ['Viewer'], permissions: ['accounts.read'], account_ids: [] }
export const account: Account = { id: 'account-1', name: 'Original account name', active: true }
export const auditEvent: Audit = { id: '1', created_at: '2026-06-12T14:30:00Z', actor_id: admin.id, target_id: bob.id, action: 'user.roles', details: { before: [], after: ['Viewer'] } }
export const roles: Role[] = [{ name: 'Admin', permissions: ['admin.manage', 'accounts.read', 'accounts.write'] }, { name: 'User', permissions: ['accounts.read', 'accounts.write'] }, { name: 'Viewer', permissions: ['accounts.read'] }]

export function mockMedia(desktop = true) {
  vi.stubGlobal('matchMedia', vi.fn((query: string) => ({
    matches: query.includes('min-width:900px') && desktop, media: query,
    onchange: null, addListener: vi.fn(), removeListener: vi.fn(),
    addEventListener: vi.fn(), removeEventListener: vi.fn(), dispatchEvent: vi.fn(),
  })))
}

// A local API simulation; no real requests, credentials, or database writes.
export function mockAPI(options: { user?: User; provider?: Identity['provider']; authenticated?: boolean; accessStatus?: number; writeStatus?: number; logoutStatus?: number; modules?: string[] } = {}) {
  const current = structuredClone(options.user || admin)
  const users = [current, structuredClone(bob)]
  const accounts = [structuredClone(account)]
  const audit = [structuredClone(auditEvent)]
  const responses = new Map<string, number>()
  let authenticated = options.authenticated !== false
  const fetcher = vi.fn(async (path: string, init?: RequestInit) => {
    const method = init?.method || 'GET'
    const forcedStatus = responses.get(path)
    if (forcedStatus) return Response.json({ error: 'UNTRUSTED SERVER DETAILS' }, { status: forcedStatus })
    if (path === '/api/auth/config') return Response.json({ provider: options.provider || 'oidc' })
    if (path === '/api/health') return Response.json({ status: 'ok' })
    if (path === '/api/auth/me') return authenticated ? Response.json({ ...identity, issuer: current.issuer, subject: current.subject, provider: options.provider || 'oidc' }) : Response.json({ error: 'unauthenticated' }, { status: 401 })
    if (path === '/api/auth/logout') {
      if (options.logoutStatus) return new Response(null, { status: options.logoutStatus })
      authenticated = false
      return new Response(null, { status: 204 })
    }
    if (path === '/api/modules') return Response.json({ modules: options.modules || [] })
    if (path === '/api/access/me') return options.accessStatus ? Response.json({ error: 'UNTRUSTED SERVER DETAILS' }, { status: options.accessStatus }) : Response.json(current)
    if (path === '/api/accounts') return Response.json(accounts.filter((a) => a.active && current.account_ids.includes(a.id)))
    if (method !== 'GET') {
      if (options.writeStatus) return Response.json({ error: 'UNTRUSTED SERVER DETAILS' }, { status: options.writeStatus })
      const body = JSON.parse(init!.body as string)
      const [, , , entity, id, field] = path.split('/')
      if (entity === 'users') {
        const target = users.find((u) => u.id === id)!
        if (field === 'roles') target.roles = body.roles
        else if (field === 'accounts') target.account_ids = body.account_ids
        else target.active = body.active
      } else if (entity === 'accounts') {
        if (method === 'POST') accounts.push({ id: `account-${accounts.length + 1}`, ...body })
        else Object.assign(accounts.find((a) => a.id === id)!, body)
      }
      audit.unshift({ ...auditEvent, id: String(audit.length + 1) })
      return new Response(null, { status: 204 })
    }
    const offset = Number(new URL(path, 'http://localhost').searchParams.get('offset') || 0)
    if (path.startsWith('/api/admin/users?')) return Response.json(users.slice(offset, offset + 100))
    if (path.startsWith('/api/admin/accounts?')) return Response.json(accounts.slice(offset, offset + 100))
    if (path === '/api/admin/roles') return Response.json(roles)
    if (path.startsWith('/api/admin/audit?')) return Response.json(audit.slice(offset, offset + 100))
    throw new Error(`Unexpected request: ${path}`)
  })
  vi.stubGlobal('fetch', fetcher)
  return { fetcher, users, accounts, audit, current, responses }
}
