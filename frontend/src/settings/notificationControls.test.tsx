import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { I18nextProvider } from 'react-i18next'
import { createI18n, resources } from '../i18n'
import { NotificationPager } from './NotificationControls'

afterEach(cleanup)
it.each([0, 1, 20])('hides pagination for %i records on the first page', (total) => {
  render(<I18nextProvider i18n={createI18n('en')}><NotificationPager offset={0} total={total} busy={false} onChange={vi.fn()} /></I18nextProvider>)
  expect(screen.queryByRole('navigation')).toBeNull()
})
it('retains previous-page navigation if the filtered last page becomes empty', () => {
  const change = vi.fn()
  render(<I18nextProvider i18n={createI18n('en')}><NotificationPager offset={20} total={0} busy={false} onChange={change} /></I18nextProvider>)
  expect((screen.getByRole('button', { name: resources.en.common.nextPage }) as HTMLButtonElement).disabled).toBe(true)
  fireEvent.click(screen.getByRole('button', { name: resources.en.common.previousPage })); expect(change).toHaveBeenCalledWith(0)
})
it('keeps page changes bounded and disables navigation while loading', () => {
  const change = vi.fn(), instance = createI18n('en')
  const view = render(<I18nextProvider i18n={instance}><NotificationPager offset={0} total={21} busy onChange={change} /></I18nextProvider>)
  fireEvent.click(screen.getByRole('button', { name: resources.en.common.nextPage })); expect(change).not.toHaveBeenCalled()
  view.rerender(<I18nextProvider i18n={instance}><NotificationPager offset={0} total={21} busy={false} onChange={change} /></I18nextProvider>)
  fireEvent.click(screen.getByRole('button', { name: resources.en.common.nextPage })); expect(change).toHaveBeenCalledWith(20)
})
