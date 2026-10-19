import { Alert, Button, LinearProgress, Stack, Typography } from '@mui/material'
import RefreshRounded from '@mui/icons-material/RefreshRounded'
import { useTranslation } from 'react-i18next'
import { useQueryCache } from '../api/queries'
import { formatNumber } from '../i18n'

export function PageTools({ busy, error, onRefresh }: { busy: boolean; error: string; onRefresh?: () => void }) {
  const { t } = useTranslation(['admin', 'common'])
  const cache = useQueryCache()
  return <Stack spacing={2} sx={{ mb: 3 }}>
    <Button startIcon={<RefreshRounded />} onClick={() => { onRefresh?.(); cache.invalidate() }} disabled={busy} sx={{ alignSelf: 'flex-start' }}>{t('refresh')}</Button>
    {busy && <LinearProgress aria-label={t('common:loading')} />}
    {error && <Alert severity="error">{t(error)}</Alert>}
  </Stack>
}

export function Pager({ page, count, busy, onChange, label }: { page: number; count: number; busy: boolean; onChange: (page: number) => void; label: string }) {
  const { t, i18n } = useTranslation('common')
  return <Stack direction="row" role="group" aria-label={label} sx={{ my: 2, gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
    <Button disabled={busy || page === 0} onClick={() => onChange(page - 1)}>{t('previousPage')}</Button>
    <Typography variant="body2" color="text.secondary">{t('page', { page: formatNumber(page + 1, i18n.resolvedLanguage || 'en') })}</Typography>
    <Button disabled={busy || count < 100} onClick={() => onChange(page + 1)}>{t('nextPage')}</Button>
  </Stack>
}
