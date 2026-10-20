import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { I18nextProvider } from 'react-i18next'
import { Button } from '@mui/material'
import LanguageProvider from '../../LanguageProvider'
import { createI18n, resources } from '../../i18n'
import { mockMedia } from '../../test/fixtures'
import StatusBadge from './StatusBadge'
import SectionCard from './SectionCard'
import TwoColumnKeyValue from './TwoColumnKeyValue'
import DetailDrawer from './DetailDrawer'

beforeEach(() => { mockMedia(); localStorage.clear() })
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

function mount(language: 'en' | 'ar', showDrawer = false) {
  const close = vi.fn()
  const view = render(<I18nextProvider i18n={createI18n(language)}><LanguageProvider>
    <SectionCard title="Security overview" description="Current state" actions={<Button>Review</Button>}>
      <StatusBadge label="Healthy" tone="success" />
      <TwoColumnKeyValue items={[{ label: 'Issuer', value: <bdi>https://issuer.example.test</bdi> }, { label: 'Subject', value: 'user-1' }]} />
    </SectionCard>
    {showDrawer && <DetailDrawer open title="Account detail" onClose={close} actions={<Button onClick={close}>Done</Button>}>
      <TwoColumnKeyValue items={[{ label: 'Account', value: 'Example' }]} />
    </DetailDrawer>}
  </LanguageProvider></I18nextProvider>)
  return { ...view, close }
}

it.each(['light', 'dark'] as const)('uses semantic surfaces and status colors in %s mode', (mode) => {
  localStorage.setItem('gwf.appearance', mode)
  mount('en')
  const section = screen.getByRole('region', { name: 'Security overview' })
  expect(section.className).toContain('MuiPaper-outlined')
  expect(getComputedStyle(section).backgroundColor).toBe(mode === 'dark' ? 'rgb(18, 18, 18)' : 'rgb(255, 255, 255)')
  expect(screen.getByText('Healthy').closest('.MuiChip-root')?.className).toContain('MuiChip-colorSuccess')
  expect(section.querySelectorAll('dt')).toHaveLength(2)
  expect(section.querySelectorAll('dd')).toHaveLength(2)
  expect(screen.getByRole('button', { name: 'Review' })).toBeTruthy()
})

it.each([['en', 'right'], ['ar', 'left']] as const)('anchors the detail drawer on the %s trailing edge and provides a translated close button', async (language, anchor) => {
  const { close } = mount(language, true)
  await screen.findByText('Account detail')
  const drawer = document.querySelector('.MuiDrawer-paper') as HTMLElement
  expect(drawer).toBeTruthy()
  const placement = getComputedStyle(drawer)
  expect(placement[anchor], JSON.stringify({ left: placement.left, right: placement.right, root: drawer.parentElement?.className })).toBe('0px')
  const button = screen.getByRole('button', { name: resources[language].common.close })
  button.focus()
  await userEvent.keyboard('{Enter}')
  expect(close).toHaveBeenCalledOnce()
  expect(document.documentElement.dir).toBe(language === 'ar' ? 'rtl' : 'ltr')
})
