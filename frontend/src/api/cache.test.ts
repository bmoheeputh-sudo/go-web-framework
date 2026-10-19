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
