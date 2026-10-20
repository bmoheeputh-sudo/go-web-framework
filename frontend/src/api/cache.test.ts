import { afterEach, expect, it, vi } from 'vitest'
import { waitFor } from '@testing-library/react'
import { QueryCache } from './cache'

afterEach(() => vi.unstubAllGlobals())

it('deduplicates pending reads and reuses their results until explicitly invalidated', async () => {
  const fetcher = vi.fn(async () => Response.json(['value']))
  vi.stubGlobal('fetch', fetcher)
  const cache = new QueryCache(vi.fn())
  cache.load('/api/admin/roles'); cache.load('/api/admin/roles')
  await waitFor(() => expect(cache.snapshot('/api/admin/roles')?.data).toEqual(['value']))
  cache.load('/api/admin/roles')
  expect(fetcher).toHaveBeenCalledTimes(1)
  cache.invalidate(); cache.load('/api/admin/roles')
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2))
})

it('discards delayed responses after invalidation instead of resurrecting stale data', async () => {
  let resolveOld: (response: Response) => void = () => {}
  const fetcher = vi.fn()
    .mockImplementationOnce(() => new Promise<Response>((resolve) => { resolveOld = resolve }))
    .mockResolvedValueOnce(Response.json(['fresh']))
  vi.stubGlobal('fetch', fetcher)
  const cache = new QueryCache(vi.fn())
  cache.load('/api/admin/users?offset=0')
  const oldSignal = fetcher.mock.calls[0][1].signal as AbortSignal
  cache.invalidate(); cache.load('/api/admin/users?offset=0')
  expect(oldSignal.aborted).toBe(true)
  await waitFor(() => expect(cache.snapshot('/api/admin/users?offset=0')?.data).toEqual(['fresh']))
  resolveOld(Response.json(['stale']))
  await new Promise((resolve) => setTimeout(resolve, 0))
  expect(cache.snapshot('/api/admin/users?offset=0')?.data).toEqual(['fresh'])
})

it('retains a safe error code and permits explicit retry after a failure', async () => {
  const fetcher = vi.fn().mockResolvedValueOnce(new Response('private details', { status: 503 })).mockResolvedValueOnce(Response.json([]))
  vi.stubGlobal('fetch', fetcher)
  const cache = new QueryCache(vi.fn())
  cache.load('/api/admin/audit?offset=0')
  await waitFor(() => expect(cache.snapshot('/api/admin/audit?offset=0')?.error).toBe('errorUnavailable'))
  cache.load('/api/admin/audit?offset=0')
  expect(fetcher).toHaveBeenCalledTimes(1)
  cache.invalidate(); cache.load('/api/admin/audit?offset=0')
  await waitFor(() => expect(cache.snapshot('/api/admin/audit?offset=0')?.data).toEqual([]))
})

it('notifies session expiration on unauthorized writes without exposing server text', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('private details', { status: 401 })))
  const expired = vi.fn()
  const cache = new QueryCache(expired)
  await expect(cache.mutate('/api/admin/users/u1', 'PUT', { active: false })).rejects.toThrow('errorUnauthenticated')
  expect(expired).toHaveBeenCalledOnce()
})

it('keeps settled rows visible while refreshing after a mutation', async () => {
  let completeRefresh: (response: Response) => void = () => {}
  const fetcher = vi.fn()
    .mockResolvedValueOnce(Response.json(['before']))
    .mockResolvedValueOnce(new Response(null, { status: 204 }))
    .mockImplementationOnce(() => new Promise<Response>((resolve) => { completeRefresh = resolve }))
  vi.stubGlobal('fetch', fetcher)
  const cache = new QueryCache(vi.fn())
  cache.load('/api/admin/accounts?offset=0')
  await waitFor(() => expect(cache.snapshot('/api/admin/accounts?offset=0')?.data).toEqual(['before']))
  await cache.mutate('/api/admin/accounts/a1', 'PUT', { name: 'after' })
  expect(cache.snapshot('/api/admin/accounts?offset=0')?.data).toEqual(['before'])
  expect(cache.snapshot('/api/admin/accounts?offset=0')?.loading).toBe(true)
  cache.load('/api/admin/accounts?offset=0')
  expect(cache.snapshot('/api/admin/accounts?offset=0')?.data).toEqual(['before'])
  completeRefresh(Response.json(['after']))
  await waitFor(() => expect(cache.snapshot('/api/admin/accounts?offset=0')?.data).toEqual(['after']))
})

it('marks affected collections stale without refetching unrelated administration data', async () => {
  const fetcher = vi.fn(async (_path: string, init?: RequestInit) => init?.method === 'PUT'
    ? new Response(null, { status: 204 }) : Response.json([]))
  vi.stubGlobal('fetch', fetcher)
  const cache = new QueryCache(vi.fn())
  cache.load('/api/admin/users?offset=0'); cache.load('/api/admin/roles'); cache.load('/api/admin/audit?offset=0')
  await waitFor(() => expect(cache.snapshot('/api/admin/audit?offset=0')?.data).toEqual([]))
  await cache.mutate('/api/admin/users/u1', 'PUT', { active: false })
  cache.load('/api/admin/users?offset=0'); cache.load('/api/admin/roles'); cache.load('/api/admin/audit?offset=0')
  await waitFor(() => expect(fetcher.mock.calls.filter(([path]) => path === '/api/admin/audit?offset=0')).toHaveLength(2))
  expect(fetcher.mock.calls.filter(([path]) => path === '/api/admin/users?offset=0')).toHaveLength(2)
  expect(fetcher.mock.calls.filter(([path]) => path === '/api/admin/roles')).toHaveLength(1)
})

it('does not retain protected rows after a refresh is forbidden', async () => {
  const fetcher = vi.fn().mockResolvedValueOnce(Response.json(['previously allowed']))
    .mockResolvedValueOnce(new Response(null, { status: 403 }))
  vi.stubGlobal('fetch', fetcher)
  const cache = new QueryCache(vi.fn())
  cache.load('/api/admin/users?offset=0')
  await waitFor(() => expect(cache.snapshot('/api/admin/users?offset=0')?.data).toEqual(['previously allowed']))
  cache.invalidate(['/api/admin/users'])
  cache.load('/api/admin/users?offset=0')
  await waitFor(() => expect(cache.snapshot('/api/admin/users?offset=0')?.error).toBe('errorForbidden'))
  expect(cache.snapshot('/api/admin/users?offset=0')?.data).toBeUndefined()
})
