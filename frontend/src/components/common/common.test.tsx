import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { I18nextProvider } from 'react-i18next'
import { Button, TableCell, TableRow, TextField } from '@mui/material'
import LanguageProvider from '../../LanguageProvider'
import { createI18n, resources } from '../../i18n'
import { mockMedia } from '../../test/fixtures'
import StatusBadge from './StatusBadge'
import SectionCard from './SectionCard'
import TwoColumnKeyValue from './TwoColumnKeyValue'
import DetailDrawer from './DetailDrawer'
import PageHeader from './PageHeader'
import CompactTable from '../CompactTable'
import { administrationFieldSx, createAppTheme, typographyRoles } from '../../design/theme'

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

it.each(['light', 'dark'] as const)('uses semantic typography roles and readable detail values in %s mode', (mode) => {
  localStorage.setItem('gwf.appearance', mode)
  render(<I18nextProvider i18n={createI18n('en')}><LanguageProvider>
    <PageHeader title="Security dashboard" description="Current application state" actions={<Button>Review</Button>} />
    <SectionCard title="Provider status" description="Verified configuration">
      <TwoColumnKeyValue items={[{ label: 'Issuer', value: <bdi>https://issuer.example.test</bdi> }]} />
      <StatusBadge label="Ready" tone="success" />
    </SectionCard>
    <CompactTable label="Recent changes" headers={['Event', 'Time']} empty={false} emptyMessage="No events">
      <TableRow><TableCell>Updated</TableCell><TableCell>Today</TableCell></TableRow>
    </CompactTable>
  </LanguageProvider></I18nextProvider>)
  expect(screen.getByRole('heading', { level: 1, name: 'Security dashboard' })).toBeTruthy()
  expect(screen.getByRole('heading', { level: 2, name: 'Provider status' })).toBeTruthy()
  expect(getComputedStyle(screen.getByText('Issuer')).fontWeight).toBe('600')
  expect(getComputedStyle(screen.getByText('Ready').closest('.MuiChip-root')!).fontWeight).toBe('650')
  expect(screen.getByRole('table', { name: 'Recent changes' }).querySelectorAll('th')).toHaveLength(2)
  expect(createAppTheme(mode, 'ltr', 'en').typography[typographyRoles.pageTitle].fontSize).toContain('clamp(')
})

it('keeps the shared page heading and details semantic in Arabic RTL', () => {
  mount('ar')
  expect(document.documentElement.dir).toBe('rtl')
  expect(screen.getByRole('heading', { level: 2, name: 'Security overview' })).toBeTruthy()
  const details = screen.getByRole('region', { name: 'Security overview' })
  expect(details.querySelectorAll('dt')).toHaveLength(2)
  expect(details.querySelectorAll('dd')).toHaveLength(2)
})

it('opts into readable column headers, wrapping status labels and nested section headings', () => {
  render(<I18nextProvider i18n={createI18n('en')}><LanguageProvider>
    <SectionCard title="Workflow"><SectionCard title="Confirmation" headingLevel="h3">
      <StatusBadge label="Needs inspection after an uncertain outcome" tone="warning" wrap />
      <TextField label="CSV import receipt ID" sx={administrationFieldSx} />
    </SectionCard></SectionCard>
    <CompactTable label="Notifications" headers={['Queue status', 'Actions']} minColumnWidths={[180, 112]} empty={false} emptyMessage="Empty" stickyActions>
      <TableRow><TableCell>Queued</TableCell><TableCell><Button>Inspect</Button></TableCell></TableRow>
    </CompactTable>
  </LanguageProvider></I18nextProvider>)
  expect(screen.getByRole('heading', { level: 3, name: 'Confirmation' })).toBeTruthy()
  expect(getComputedStyle(screen.getByText('Needs inspection after an uncertain outcome')).whiteSpace).toBe('normal')
  expect(getComputedStyle(screen.getByRole('columnheader', { name: 'Queue status' })).overflowWrap).toBe('normal')
  expect(getComputedStyle(screen.getByRole('columnheader', { name: 'Queue status' })).minWidth).toBe('180px')
  expect(screen.getByRole('region', { name: 'Notifications' }).tabIndex).toBe(0)
  expect(screen.getByLabelText('CSV import receipt ID')).toBeTruthy()
})
