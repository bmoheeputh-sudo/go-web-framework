import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { I18nextProvider } from 'react-i18next'
import LanguageProvider from '../LanguageProvider'
import { createI18n, resources } from '../i18n'
import VerificationResultPage from './VerificationResultPage'

afterEach(() => { cleanup(); vi.restoreAllMocks() })

it.each(['success', 'declined', 'failed', 'unrecognized'])(
  'shows a minimal %s result without consulting authentication APIs', (result) => {
    const fetcher = vi.spyOn(globalThis, 'fetch')
    const close = vi.spyOn(window, 'close').mockImplementation(() => {})
    render(<I18nextProvider i18n={createI18n('en')}><LanguageProvider><VerificationResultPage result={result} /></LanguageProvider></I18nextProvider>)
    const key = result === 'success' || result === 'declined' ? result : 'failed'
    expect(screen.getByRole('heading', { name: resources.en.auth[`verificationPopup_${key}`] })).toBeTruthy()
    expect(screen.getByText(resources.en.auth.verificationPopupReturn)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: resources.en.auth.verificationPopupClose }))
    expect(close).toHaveBeenCalledOnce()
    expect(fetcher).not.toHaveBeenCalled()
  },
)

it('keeps the minimal result readable in Arabic RTL', () => {
  render(<I18nextProvider i18n={createI18n('ar')}><LanguageProvider><VerificationResultPage result="success" /></LanguageProvider></I18nextProvider>)
  expect(document.documentElement.dir).toBe('rtl')
  expect(screen.getByRole('heading', { name: resources.ar.auth.verificationPopup_success })).toBeTruthy()
})
