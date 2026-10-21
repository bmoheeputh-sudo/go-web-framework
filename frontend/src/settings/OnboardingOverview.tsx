import { useEffect, useState } from 'react'
import { Alert, Button, MenuItem, Stack, TableCell, TableRow, TextField, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { listOnboarding } from '../api/notificationManagement'
import type { OnboardingCategory, OnboardingPage } from '../api/notificationManagement'
import CompactTable from '../components/CompactTable'
import { PageTools } from '../components/PageTools'
import SectionCard from '../components/common/SectionCard'
import TwoColumnKeyValue from '../components/common/TwoColumnKeyValue'
import { typographyRoles } from '../design/theme'
import { formatDate, formatNumber } from '../i18n'
import { AuthConfigurationError } from '../api/authConfiguration'
import { useSession } from '../auth/session'
import { notificationDiagnostic, notificationErrorKey } from './notificationManagementState'
import { NotificationPager, SuppressionDialog } from './NotificationControls'

const categories: OnboardingCategory[] = ['onboarded', 'pending', 'unobserved', 'inactive']
export default function OnboardingOverview() {
  const { t, i18n } = useTranslation(['admin', 'common'])
  const session = useSession()
  const [category, setCategory] = useState<OnboardingCategory>('onboarded'), [offset, setOffset] = useState(0), [revision, setRevision] = useState(0)
  const [search, setSearch] = useState(''), [query, setQuery] = useState(''), [page, setPage] = useState<OnboardingPage | null>(null)
  const [loading, setLoading] = useState(true), [error, setError] = useState(''), [suppression, setSuppression] = useState<{ ref: string; email: string } | null>(null)
  const language = i18n.resolvedLanguage || 'en'
  useEffect(() => {
    const controller = new AbortController()
    listOnboarding(category, query, '', offset, controller.signal).then((value) => { if (!controller.signal.aborted) { setPage(value); setError('') } }).catch((failure) => { if (!controller.signal.aborted) { setPage(null); setError(notificationErrorKey(failure, false)); if (failure instanceof AuthConfigurationError && failure.status === 401) session.expire(); if (failure instanceof AuthConfigurationError && failure.status === 403) void session.refreshAccess() } }).finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [category, query, offset, revision, session])
  return <Stack spacing={2}>
    <PageTools busy={loading} error={error} onRefresh={() => { setLoading(true); setRevision((n) => n + 1) }} />
    <SectionCard title={t('nmOverview')}>
      <Stack spacing={2}>
        <Alert severity="info">{t('nmCoverageHelp')}</Alert>
        <Alert severity="info">{t('nmUnknownHelp')}</Alert>
        {page && <TwoColumnKeyValue items={categories.map((key) => ({ label: t(`nmCategory_${key}`), value: formatNumber(page.counts[key], language) }))} />}
        <Stack component="form" direction={{ xs: 'column', sm: 'row' }} spacing={2} onSubmit={(event) => { event.preventDefault(); setLoading(true); setRevision((n) => n + 1); setQuery(search); setOffset(0) }}>
          <TextField select label={t('nmTargetGroup')} value={category} onChange={(event) => { setLoading(true); setCategory(event.target.value as OnboardingCategory); setOffset(0) }}>{categories.map((key) => <MenuItem key={key} value={key}>{t(`nmCategory_${key}`)}</MenuItem>)}</TextField>
          <TextField label={t('nmSearch')} value={search} onChange={(event) => setSearch(event.target.value)} /><Button disabled={loading} type="submit">{t('nmApplyFilters')}</Button>
        </Stack>
        <CompactTable label={t('nmOverview')} headers={[t('nmEmployee'), t('nmLoginEvidence'), t('nmEligibility'), t('actions')]} empty={!page?.items.length} emptyMessage={t('nmEmpty')} stickyActions minWidth={640}>
          {page?.items.map((row) => <TableRow key={row.target}>
            <TableCell><Typography variant={typographyRoles.primaryValue}>{row.display_name}</Typography><bdi>{row.email}</bdi></TableCell>
            <TableCell>{row.first_successful_oidc_login_at ? <Typography variant="body2">{t('nmFirstLogin', { date: formatDate(row.first_successful_oidc_login_at, language) })}</Typography> : <Typography variant="body2">{t('nmNoObservation')}</Typography>}{row.last_successful_oidc_login_at && <Typography variant="body2">{t('nmLastLogin', { date: formatDate(row.last_successful_oidc_login_at, language) })}</Typography>}{row.claim_evidence && <Typography variant="body2">{t('nmClaimEvidence')}</Typography>}</TableCell>
            <TableCell>{t(notificationDiagnostic(row.code))}</TableCell>
            <TableCell><Button onClick={() => setSuppression({ ref: row.target, email: row.email })} aria-label={t('nmManageRecipient', { email: row.email })}>{t('nmSuppression')}</Button></TableCell>
          </TableRow>)}
        </CompactTable>
        <NotificationPager offset={offset} total={page?.total || 0} busy={loading} onChange={(value) => { setLoading(true); setOffset(value) }} />
      </Stack>
    </SectionCard>
    {suppression && <SuppressionDialog target={suppression} onClose={() => setSuppression(null)} onChanged={() => setRevision((n) => n + 1)} />}
  </Stack>
}
