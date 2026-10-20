import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryCache } from './cache'
import { QueryContext, useMutation } from './queries'
import { NotificationContext } from '../notifications/notifications'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function TestMutation() {
  const { mutate, busy } = useMutation()
  return <button disabled={busy} onClick={() => { void mutate('/api/admin/accounts/a1', 'PUT', { name: 'Updated' }) }}>Save</button>
}

it('submits a rapid administrative mutation only once and refreshes without document navigation', async () => {
  let complete: (response: Response) => void = () => {}
  const fetcher = vi.fn((path: string, init?: RequestInit) => {
    expect(path).toBe('/api/admin/accounts/a1')
    expect(init?.method).toBe('PUT')
    return new Promise<Response>((resolve) => { complete = resolve })
  })
  vi.stubGlobal('fetch', fetcher)
  const notify = vi.fn()
  const cache = new QueryCache(vi.fn())
  render(<QueryContext.Provider value={cache}><NotificationContext.Provider value={notify}><TestMutation /></NotificationContext.Provider></QueryContext.Provider>)
  const save = screen.getByRole('button', { name: 'Save' })
  const initialPath = window.location.pathname
  fireEvent.click(save); fireEvent.click(save)
  expect(fetcher).toHaveBeenCalledTimes(1)
  expect(fetcher.mock.calls[0][0]).toBe('/api/admin/accounts/a1')
  complete(new Response(null, { status: 204 }))
  await waitFor(() => expect(notify).toHaveBeenCalledTimes(1))
  expect(window.location.pathname).toBe(initialPath)
})
