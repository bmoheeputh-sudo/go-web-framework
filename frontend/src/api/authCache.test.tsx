import { afterEach, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryCache } from './cache'
import { QueryContext, useQuery } from './queries'
import { authSettingsPath, authStatusPath } from './authConfiguration'
import { useAuthenticationCacheSync } from './authCache'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

const historyPath = `${authSettingsPath}?limit=20&before_version=0`
function AuthViews() {
  const status = useQuery<{ marker: string }>(authStatusPath)
  const history = useQuery<{ marker: string }>(historyPath)
  const { refreshAfterChange } = useAuthenticationCacheSync()
  return <><span data-testid="status">{status.data?.marker}</span><span data-testid="history">{history.data?.marker}</span>
    <button onClick={refreshAfterChange}>Refresh authentication</button></>
}

it('preserves visible authentication views during a scoped background refresh', async () => {
  let finishStatus: (response: Response) => void = () => {}
  let finishHistory: (response: Response) => void = () => {}
  let statusReads = 0, historyReads = 0
  const fetcher = vi.fn((path: string) => {
    if (path === authStatusPath) return ++statusReads === 1 ? Promise.resolve(Response.json({ marker: 'initial status' }))
      : new Promise<Response>((resolve) => { finishStatus = resolve })
    if (path === historyPath) return ++historyReads === 1 ? Promise.resolve(Response.json({ marker: 'initial history' }))
      : new Promise<Response>((resolve) => { finishHistory = resolve })
    throw new Error(`unexpected request ${path}`)
  })
  vi.stubGlobal('fetch', fetcher)
  const cache = new QueryCache(vi.fn())
  render(<QueryContext.Provider value={cache}><AuthViews /></QueryContext.Provider>)
  await waitFor(() => expect(screen.getByTestId('history').textContent).toBe('initial history'))
  await waitFor(() => expect(screen.getByTestId('status').textContent).toBe('initial status'))
  const historyNode = screen.getByTestId('history')
  fireEvent.click(screen.getByRole('button', { name: 'Refresh authentication' }))
  await waitFor(() => expect(historyReads).toBe(2))
  expect(screen.getByTestId('history')).toBe(historyNode)
  expect(historyNode.textContent).toBe('initial history')
  expect(screen.getByTestId('status').textContent).toBe('initial status')
  finishStatus(Response.json({ marker: 'current status' }))
  finishHistory(Response.json({ marker: 'current history' }))
  await waitFor(() => expect(historyNode.textContent).toBe('current history'))
  expect(screen.getByTestId('status').textContent).toBe('current status')
})
