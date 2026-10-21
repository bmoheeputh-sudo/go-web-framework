import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { I18nextProvider } from 'react-i18next'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { invitationsPath } from '../api/accessPolicy'
import type { CSVPreview, CSVPreviewRow, ImportReceipt, InvitationExpectation } from '../api/accessPolicy'
import QueryProvider from '../api/QueryProvider'
import { SessionContext } from '../auth/session'
import type { Session } from '../auth/session'
import { appearanceStorageKey } from '../appearance/appearance'
import { createI18n, resources } from '../i18n'
import type { Language } from '../i18n'
import LanguageProvider from '../LanguageProvider'
import NotificationProvider from '../notifications/NotificationProvider'
import { admin, identity, mockMedia } from '../test/fixtures'
import CSVInvitationImport from './CSVInvitationImport'

const en = resources.en.auth, common = resources.en.common
const csv = '\ufeffemail,display_name\r\nEmployee+tag@VOPAK.COM,"Employee, One"\r\nsecond@vopak.com,Second\r\n'
const importID = '11111111-1111-4111-8111-111111111111'
const expected: InvitationExpectation = { expected_policy_generation: 8, expected_activation_generation: 3, revision_id: '22222222-2222-4222-8222-222222222222', expected_revision_generation: 4 }
function Location() { const location = useLocation(); return <output data-testid="csv-location">{location.search}</output> }
function setup(options: { previewStatus?: number; mutationStatus?: number; receiptStatus?: number; recover?: boolean; stale?: boolean; language?: Language; theme?: 'dark' | 'light'; disabled?: boolean; mode?: 'allow_all' | 'approved_users_only'; invalidResult?: boolean } = {}) {
  if (options.theme) localStorage.setItem(appearanceStorageKey, options.theme)
  const rows: CSVPreviewRow[] = ['ready', 'ready', 'invalid_email', 'duplicate_csv', 'existing_pending', 'already_claimed', 'existing_user_review', 'blocked_domain', 'stale_configuration_or_policy', 'invalid_display_name'].map((status, n) => ({ row: n + 1, email: n ? `employee${n}@vopak.com` : 'Employee+tag@VOPAK.COM', display_name: n === 2 ? '<img src=x onerror=alert(1)>' : n === 1 ? '=SUM(1,2)' : `Employee ${n}`, status: status as CSVPreviewRow['status'] }))
  let receipt: ImportReceipt | null = options.recover ? { ...expected, id: importID, deployment_id: 'deployment-a', environment: 'development', actor_user_id: admin.id, content_digest: 'c'.repeat(64), expiration_days: 7, total_rows: 10, selected_rows: [1, 2], created_count: 2, skipped_count: 4, rejected_count: 4, created_invitation_ids: ['33333333-3333-4333-8333-000000000001', '33333333-3333-4333-8333-000000000002'], created_at: '2026-10-20T10:00:00Z', completed_at: '2026-10-20T10:00:01Z', outcome: 'completed', reason: 'Approved employee onboarding' } : null
  const fetcher = vi.fn(async (path: string, init?: RequestInit) => {
    if (path === invitationsPath + '/import/preview') {
      if (options.previewStatus) return Response.json({ error: options.previewStatus === 400 ? 'oidc_import_invalid_csv' : 'oidc_import_conflict' }, { status: options.previewStatus })
      const input = JSON.parse(String(init?.body)); const selected = options.stale ? [] : input.selected_rows || [1, 2]
      return Response.json({ ...expected, rows: options.stale ? rows.map((row) => ({ ...row, status: 'stale_configuration_or_policy' })) : rows, selected_rows: selected, total_rows: 10, ready_rows: options.stale ? 0 : 2, skipped_rows: 4 + (2 - selected.length), invalid_rows: 4, will_create: selected.length, expiration_days: input.expiration_days, content_digest: 'c'.repeat(64), preview_digest: options.stale ? '' : 'd'.repeat(63) + selected.length, preview_expires_at: new Date(Date.now() + 300000).toISOString(), max_rows: 500, max_bytes: 1048576 } satisfies CSVPreview)
    }
    if (path === invitationsPath + '/import') {
      const input = JSON.parse(String(init?.body))
      receipt = { ...expected, id: input.import_id, deployment_id: 'deployment-a', environment: 'development', actor_user_id: admin.id, content_digest: 'c'.repeat(64), expiration_days: input.expiration_days, total_rows: 10, selected_rows: input.selected_rows, created_count: input.selected_rows.length, skipped_count: 4 + 2 - input.selected_rows.length, rejected_count: 4, created_invitation_ids: input.selected_rows.map((n: number) => '33333333-3333-4333-8333-' + String(n).padStart(12, '0')), created_at: '2026-10-20T10:00:00Z', completed_at: '2026-10-20T10:00:01Z', outcome: 'completed', reason: input.reason }
      if (options.mutationStatus) return Response.json({ error: options.mutationStatus === 503 ? 'oidc_import_commit_uncertain' : 'oidc_import_conflict', import_id: input.import_id, automatic_retry_allowed: false }, { status: options.mutationStatus })
      return Response.json(options.invalidResult ? {} : receipt)
    }
    if (path.startsWith(invitationsPath + '/imports/')) {
      if (options.receiptStatus) return Response.json({ error: 'oidc_import_receipt_not_found' }, { status: options.receiptStatus })
      return receipt ? Response.json(receipt) : Response.json({ error: 'oidc_import_receipt_not_found' }, { status: 404 })
    }
    throw new Error('Unexpected CSV test request')
  })
  vi.stubGlobal('fetch', fetcher)
  const session: Session = { authentication: { status: 'authenticated', identity }, access: { loading: false, user: admin, error: '' }, health: 'ok', oidcEnabled: true, loggingOut: false, logoutFailed: false, loginFailed: false, logout: vi.fn(), expire: vi.fn(), refreshAccess: vi.fn() }
  const instance = createI18n(options.language || 'en'), onImported = vi.fn()
  const content = (visible = true) => <I18nextProvider i18n={instance}><LanguageProvider><NotificationProvider><SessionContext.Provider value={session}><QueryProvider><MemoryRouter initialEntries={['/settings?auth_section=user-access' + (options.recover ? '&invitation_import=' + importID : '')]}>{visible && <CSVInvitationImport expected={expected} disabled={Boolean(options.disabled)} mode={options.mode || 'allow_all'} onImported={onImported} />}<Location /></MemoryRouter></QueryProvider></SessionContext.Provider></NotificationProvider></LanguageProvider></I18nextProvider>
  const view = render(content())
  return { fetcher, instance, session, onImported, hide: () => view.rerender(content(false)), show: () => view.rerender(content()) }
}
beforeEach(() => { mockMedia(); localStorage.clear(); sessionStorage.clear() })
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })
const dialog = () => screen.getByRole('dialog')
const imports = (fetcher: ReturnType<typeof setup>['fetcher']) => fetcher.mock.calls.filter(([path]) => path === invitationsPath + '/import')
const previews = (fetcher: ReturnType<typeof setup>['fetcher']) => fetcher.mock.calls.filter(([path]) => path === invitationsPath + '/import/preview')
async function upload(data = csv, language: Language = 'en') {
  const labels = resources[language].auth
  await userEvent.click(screen.getByRole('button', { name: labels.csvImportButton }))
  await userEvent.upload(screen.getByLabelText(labels.csvChooseFile), new File([data], 'employees.csv', { type: 'text/csv' }))
  await screen.findByText('employees.csv')
}
async function preview() { await userEvent.click(within(dialog()).getByRole('button', { name: en.csvPreview })); await screen.findByText('=SUM(1,2)') }
async function confirm() {
  await userEvent.click(within(dialog()).getByRole('button', { name: en.csvReviewImport })); await screen.findByLabelText(en.accessReason + ' *')
  fireEvent.change(screen.getByLabelText(en.accessReason + ' *'), { target: { value: 'Approved employee onboarding' } })
  await userEvent.click(screen.getByRole('checkbox', { name: en.csvConfirmAck }))
}

it('uploads exact BOM/CRLF/quoted content, previews selected rows, confirms once and views imported invitations', async () => {
  const { fetcher, onImported } = setup(); await upload(); await preview()
  expect(JSON.parse(String(previews(fetcher)[0][1]?.body)).csv).toBe(csv)
  expect(imports(fetcher)).toHaveLength(0)
  const second = screen.getByRole('checkbox', { name: en.csvSelectRow.replace('{{row}}', '2').replace('{{email}}', 'employee1@vopak.com') })
  await userEvent.click(second)
  expect(screen.getByText(en.csvSkipped).nextElementSibling?.textContent).toBe('5')
  await confirm()
  expect(JSON.parse(String(previews(fetcher)[1][1]?.body)).selected_rows).toEqual([1])
  await userEvent.dblClick(screen.getByRole('button', { name: en.csvConfirmImport }))
  await screen.findByText(en.csvCompleted)
  expect(imports(fetcher)).toHaveLength(1)
  const body = JSON.parse(String(imports(fetcher)[0][1]?.body))
  expect(body).toMatchObject({ ...expected, csv, selected_rows: [1], expiration_days: 7, preview_digest: 'd'.repeat(63) + '1', reason: 'Approved employee onboarding', confirm: true })
  expect(body.import_id).toMatch(/^[0-9a-f-]{36}$/); expect(body.idempotency_key).toMatch(/^[0-9a-f-]{36}$/)
  expect(screen.getByTestId('csv-location').textContent).toContain(body.import_id)
  expect(screen.getByTestId('csv-location').textContent).not.toContain('Employee')
  await userEvent.click(screen.getByRole('button', { name: en.csvViewInvitations })); expect(onImported).toHaveBeenCalledWith(body.import_id)
  expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0)
  expect(fetcher.mock.calls.every(([, init]) => init?.cache === 'no-store' && init.credentials === 'same-origin')).toBe(true)
})
it('renders CSV values only as text and prevents selecting every non-ready classification', async () => {
  setup(); await upload(); await preview()
  expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeTruthy(); expect(document.querySelector('img')).toBeNull()
  for (const status of ['invalid_email', 'invalid_display_name', 'duplicate_csv', 'existing_pending', 'already_claimed', 'existing_user_review', 'blocked_domain', 'stale_configuration_or_policy']) expect(screen.getByText(en['csvStatus_' + status])).toBeTruthy()
  expect(screen.getAllByRole('checkbox').filter((element) => !(element as HTMLInputElement).disabled)).toHaveLength(3)
  await userEvent.click(screen.getByRole('checkbox', { name: en.csvSelectReady }))
  expect((screen.getByRole('button', { name: en.csvReviewImport }) as HTMLButtonElement).disabled).toBe(true)
})
it('requires a reason and explicit confirmation and supports custom expiration', async () => {
  const { fetcher } = setup(); await upload()
  fireEvent.change(screen.getByLabelText(en.invitationExpiration + ' *'), { target: { value: '30' } }); await preview()
  await userEvent.click(screen.getByRole('button', { name: en.csvReviewImport })); await screen.findByLabelText(en.accessReason + ' *')
  expect((screen.getByRole('button', { name: en.csvConfirmImport }) as HTMLButtonElement).disabled).toBe(true)
  fireEvent.change(screen.getByLabelText(en.accessReason + ' *'), { target: { value: '审核人' } })
  expect((screen.getByRole('button', { name: en.csvConfirmImport }) as HTMLButtonElement).disabled).toBe(true)
  fireEvent.change(screen.getByLabelText(en.accessReason + ' *'), { target: { value: '审核员工批量邀请' } })
  expect((screen.getByRole('button', { name: en.csvConfirmImport }) as HTMLButtonElement).disabled).toBe(true)
  await userEvent.click(screen.getByRole('checkbox', { name: en.csvConfirmAck })); await userEvent.click(screen.getByRole('button', { name: en.csvConfirmImport })); await screen.findByText(en.csvCompleted)
  expect(JSON.parse(String(imports(fetcher)[0][1]?.body)).expiration_days).toBe(30)
})
it('rejects oversized and invalid UTF-8 files before any preview request', async () => {
  const { fetcher } = setup(); await userEvent.click(screen.getByRole('button', { name: en.csvImportButton }))
  await userEvent.upload(screen.getByLabelText(en.csvChooseFile), new File([new Uint8Array(1048577)], 'large.csv', { type: 'text/csv' })); await screen.findByText(en.csvSizeError)
  await userEvent.upload(screen.getByLabelText(en.csvChooseFile), new File([new Uint8Array([255])], 'bad.csv', { type: 'text/csv' })); await screen.findByText(en.csvFormatError)
  expect(previews(fetcher)).toHaveLength(0)
})
it.each([400, 409, 503])('handles preview HTTP %s without making an import', async (previewStatus) => {
  const { fetcher } = setup({ previewStatus }); await upload(); await userEvent.click(screen.getByRole('button', { name: en.csvPreview }))
  await within(dialog()).findByText(en[previewStatus === 400 ? 'csvFormatError' : previewStatus === 409 ? 'csvConflict' : 'csvUnavailable'])
  expect(imports(fetcher)).toHaveLength(0); expect(screen.getByText('employees.csv')).toBeTruthy()
})
it('keeps stale configuration rows unselected and prevents confirmation', async () => {
  setup({ stale: true }); await upload(); await preview()
  expect(screen.getAllByRole('checkbox').every((element) => (element as HTMLInputElement).disabled)).toBe(true)
  expect((screen.getByRole('button', { name: en.csvReviewImport }) as HTMLButtonElement).disabled).toBe(true)
})
it('does not retry a conflicting commit and preserves the administrator input for another preview', async () => {
  const { fetcher } = setup({ mutationStatus: 409 }); await upload(); await preview(); await confirm(); await userEvent.click(screen.getByRole('button', { name: en.csvConfirmImport }))
  await within(dialog()).findByText(en.csvConflict)
  expect(imports(fetcher)).toHaveLength(1); expect((screen.getByRole('button', { name: en.csvReviewImport }) as HTMLButtonElement).disabled).toBe(true)
  await userEvent.click(screen.getByRole('button', { name: en.csvRefreshPreview })); await screen.findByText('=SUM(1,2)'); await userEvent.click(screen.getByRole('button', { name: en.csvReviewImport }))
  expect((await screen.findByLabelText(en.accessReason + ' *') as HTMLInputElement).value).toBe('Approved employee onboarding')
  expect(imports(fetcher)).toHaveLength(1)
})
it('inspects a receipt after an uncertain response without retrying the mutation', async () => {
  const { fetcher } = setup({ mutationStatus: 503 }); await upload(); await preview(); await confirm(); await userEvent.click(screen.getByRole('button', { name: en.csvConfirmImport }))
  await screen.findByRole('button', { name: en.csvInspect }); expect(fetcher.mock.calls.filter(([path]) => path.includes('/imports/'))).toHaveLength(0)
  expect(screen.queryByRole('button', { name: en.csvConfirmImport })).toBeNull()
  await userEvent.click(screen.getByRole('button', { name: en.csvInspect })); await screen.findByText(en.csvCompleted); expect(imports(fetcher)).toHaveLength(1)
})
it('recovers an interrupted session from only the receipt reference', async () => {
  const { fetcher } = setup({ recover: true }); await screen.findByText(en.csvCompleted)
  expect(screen.getByText(importID)).toBeTruthy(); expect(imports(fetcher)).toHaveLength(0); expect(previews(fetcher)).toHaveLength(0)
  expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0)
})
it('never treats a missing receipt as proof that an uncertain import failed', async () => {
  const { fetcher } = setup({ recover: true, receiptStatus: 404 }); await screen.findByText(en.csvReceiptMissing)
  expect(screen.queryByRole('button', { name: en.csvNewImport })).toBeNull()
  await userEvent.click(screen.getByRole('button', { name: en.csvInspect })); expect(imports(fetcher)).toHaveLength(0)
})
it.each([401, 403])('handles receipt authorization HTTP %s', async (receiptStatus) => {
  const { session, fetcher } = setup({ recover: true, receiptStatus }); await within(dialog()).findByText(common.accessDenied)
  expect(receiptStatus === 401 ? session.expire : session.refreshAccess).toHaveBeenCalled(); expect(imports(fetcher)).toHaveLength(0)
})
it.each(['allow_all', 'approved_users_only'] as const)('explains %s access semantics at confirmation', async (mode) => {
  setup({ mode }); await upload(); await preview(); await confirm()
  expect(screen.getByText(mode === 'allow_all' ? en.invitationAllowAll : en.invitationApprovedOnly)).toBeTruthy(); expect(screen.getByText(en.invitationNoEmail)).toBeTruthy()
})
it('requires explicit discard without opening another dialog and restores a draft across navigation', async () => {
  const { hide, show, fetcher } = setup(); await upload(); await userEvent.keyboard('{Escape}'); expect(screen.getByText(en.invitationDiscardHelp)).toBeTruthy()
  expect(screen.getAllByRole('dialog')).toHaveLength(1); await userEvent.click(screen.getByRole('button', { name: en.invitationKeepEditing }))
  hide(); show(); await screen.findByText('employees.csv'); expect(previews(fetcher)).toHaveLength(0)
  await userEvent.click(screen.getByRole('button', { name: common.cancel })); await userEvent.click(screen.getByRole('button', { name: en.invitationDiscard })); await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
})
it('does not offer an import when the current policy/provider is unavailable', () => {
  const { fetcher } = setup({ disabled: true }); expect((screen.getByRole('button', { name: en.csvImportButton }) as HTMLButtonElement).disabled).toBe(true); expect(fetcher).not.toHaveBeenCalled()
})
it.each([['en', 'light'], ['ar', 'dark']] as const)('supports %s locale and %s appearance, preserving CSV values on language changes', async (language, theme) => {
  const { instance } = setup({ language, theme }); await upload(csv, language)
  expect(document.documentElement.dir).toBe(language === 'ar' ? 'rtl' : 'ltr'); expect(getComputedStyle(document.body).colorScheme).toBe(theme)
  await act(async () => { await instance.changeLanguage(language === 'ar' ? 'en' : 'ar') }); expect(screen.getByText('employees.csv')).toBeTruthy()
  expect((screen.getByLabelText(resources[language === 'ar' ? 'en' : 'ar'].auth.invitationExpiration + ' *') as HTMLInputElement).value).toBe('7')
})
it('provides complete CSV labels and placeholders in all twelve locales', () => {
  for (const bundles of Object.values(resources)) for (const key of Object.keys(en).filter((key) => key.startsWith('csv'))) {
    expect(bundles.auth[key]?.trim()).toBeTruthy(); expect(bundles.auth[key].match(/{{\w+}}/g) || []).toEqual(en[key].match(/{{\w+}}/g) || [])
  }
})

it('requires inspection for a successful HTTP response that lacks a valid receipt', async () => {
  const { fetcher } = setup({ invalidResult: true }); await upload(); await preview(); await confirm()
  await userEvent.click(screen.getByRole('button', { name: en.csvConfirmImport })); await screen.findByRole('button', { name: en.csvInspect })
  expect(imports(fetcher)).toHaveLength(1)
  await userEvent.click(screen.getByRole('button', { name: en.csvInspect })); await screen.findByText(en.csvCompleted)
  expect(imports(fetcher)).toHaveLength(1)
})
