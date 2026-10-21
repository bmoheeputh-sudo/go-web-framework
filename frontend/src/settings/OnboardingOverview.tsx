import { useEffect, useState } from 'react'
import { Alert, Box, Button, MenuItem, Stack, TableCell, TableRow, TextField, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { listOnboarding } from '../api/notificationManagement'
import type { OnboardingCategory, OnboardingPage } from '../api/notificationManagement'
import CompactTable from '../components/CompactTable'
import { PageTools } from '../components/PageTools'
import SectionCard from '../components/common/SectionCard'
import { administrationEmailSx, administrationFieldSx, administrationFilterSx, typographyRoles } from '../design/theme'
import { formatDate, formatNumber } from '../i18n'
import { AuthConfigurationError } from '../api/authConfiguration'
import { useSession } from '../auth/session'
import { notificationDiagnostic, notificationErrorKey } from './notificationManagementState'
import { NotificationPager, SuppressionDialog } from './NotificationControls'

const categories: OnboardingCategory[] = ['onboarded', 'pending', 'unobserved', 'inactive']
export default function OnboardingOverview() {
  const { t, i18n } = useTranslation(['admin', 'common', 'auth'])
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
    <SectionCard title={t('nmOverview')} description={t('nmCoverageHelp')}>
      <Stack spacing={2}>
        <Alert severity="info">{t('nmUnknownHelp')}</Alert>
        {page && <Box component="dl" sx={{ display: 'grid', gridTemplateColumns: { xs: 'minmax(0, 1fr)', sm: 'repeat(2, minmax(0, 1fr))', lg: 'repeat(4, minmax(0, 1fr))' }, gap: 2, m: 0 }}>
          {categories.map((key) => <Box key={key} component="div" sx={{ p: 2, display: 'flex', flexDirection: 'column', bgcolor: 'action.hover', borderRadius: 1, minWidth: 0 }}>
            <Typography component="dt" variant={typographyRoles.detailLabel} color="text.secondary" sx={{ flex: 1 }}>{t(`nmCategory_${key}`)}</Typography>
            <Typography component="dd" variant="h5" sx={{ m: 0, mt: 1, fontVariantNumeric: 'tabular-nums', color: key === 'onboarded' ? 'success.main' : key === 'pending' ? 'info.main' : 'text.primary' }}>{formatNumber(page.counts[key], language)}</Typography>
          </Box>)}
        </Box>}
        <Box component="form" sx={administrationFilterSx} onSubmit={(event) => { event.preventDefault(); setLoading(true); setRevision((n) => n + 1); setQuery(search); setOffset(0) }}>
          <TextField sx={administrationFieldSx} select label={t('nmTargetGroup')} value={category} onChange={(event) => { setLoading(true); setCategory(event.target.value as OnboardingCategory); setOffset(0) }}>{categories.map((key) => <MenuItem key={key} value={key}>{t(`nmCategory_${key}`)}</MenuItem>)}</TextField>
          <TextField sx={administrationFieldSx} label={t('nmSearch')} value={search} onChange={(event) => setSearch(event.target.value)} /><Button disabled={loading} type="submit">{t('nmApplyFilters')}</Button>
        </Box>
        <CompactTable label={t('nmOverview')} headers={[t('nmEmployee'), t('nmLoginEvidence'), t('nmEligibility'), t('auth:actions')]} empty={!page?.items.length && !loading} emptyMessage={t('nmOnboardingEmpty')} stickyActions minWidth={792} minColumnWidths={[240, 240, 184, 128]}>
          {page?.items.map((row) => <TableRow key={row.target}>
            <TableCell><Typography variant={typographyRoles.primaryValue}>{row.display_name}</Typography><Typography component="bdi" variant={typographyRoles.supportingText} sx={administrationEmailSx}>{row.email}</Typography></TableCell>
            <TableCell>{row.first_successful_oidc_login_at ? <Stack spacing={0.25}><Typography variant={typographyRoles.detailLabel} color="text.secondary">{t('nmFirstLoginLabel')}</Typography><Typography component="time" dateTime={row.first_successful_oidc_login_at} variant={typographyRoles.supportingText}>{formatDate(row.first_successful_oidc_login_at, language)}</Typography></Stack> : <Typography variant={typographyRoles.supportingText} color="text.secondary">{t('nmNoObservation')}</Typography>}{row.last_successful_oidc_login_at && <Stack spacing={0.25} sx={{ mt: 1 }}><Typography variant={typographyRoles.detailLabel} color="text.secondary">{t('nmLastLoginLabel')}</Typography><Typography component="time" dateTime={row.last_successful_oidc_login_at} variant={typographyRoles.supportingText}>{formatDate(row.last_successful_oidc_login_at, language)}</Typography></Stack>}{row.claim_evidence && <Typography variant={typographyRoles.supportingText} sx={{ mt: 1 }}>{t('nmClaimEvidence')}</Typography>}</TableCell>
            <TableCell>{t(notificationDiagnostic(row.code))}</TableCell>
            <TableCell><Button size="small" variant="outlined" onClick={() => setSuppression({ ref: row.target, email: row.email })} aria-label={t('nmManageRecipient', { email: row.email })}>{t('nmManage')}</Button></TableCell>
          </TableRow>)}
        </CompactTable>
        <NotificationPager label={t('nmOverview')} offset={offset} total={page?.total || 0} busy={loading} onChange={(value) => { setLoading(true); setOffset(value) }} />
      </Stack>
    </SectionCard>
    {suppression && <SuppressionDialog target={suppression} onClose={() => setSuppression(null)} onChanged={() => setRevision((n) => n + 1)} />}
  </Stack>
}
