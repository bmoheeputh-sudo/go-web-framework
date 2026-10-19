import { Box, Chip, CircularProgress, Paper, Stack, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { useSession } from '../auth/session'
import AuthenticationNotice from '../auth/AuthenticationNotice'
import AccessPortal from '../AccessPortal'

const providers = { oidc: 'providerOidc', google_iap: 'providerIap', local_dev: 'providerLocal' }

export default function DashboardPage() {
  const { t } = useTranslation(['common', 'auth'])
  const { health, authentication } = useSession()
  return <Stack spacing={3}>
    <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: '1fr 2fr' }, gap: 3 }}>
      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" component="h2" gutterBottom>{t('backendStatus')}</Typography>
        {health === 'checking' ? <CircularProgress size={24} aria-label={t('checkingConnection')} /> : <Chip label={t(health)} color={health === 'connected' ? 'success' : 'error'} variant="outlined" />}
      </Paper>
      <Paper sx={{ p: 3, minWidth: 0 }}>
        <Typography variant="h6" component="h2" gutterBottom>{t('auth:title')}</Typography>
        <AuthenticationNotice />
        {authentication.status === 'authenticated' && <Box component="dl" sx={{ m: 0, display: 'grid', gap: 2 }}>
          {[
            ['provider', t(`auth:${providers[authentication.identity.provider]}`)],
            ['displayName', authentication.identity.display_name || t('notProvided')],
            ['email', authentication.identity.email || t('notProvided')],
          ].map(([label, value]) => <Box key={label}>
            <Typography component="dt" variant="body2" color="text.secondary">{t(`auth:${label}`)}</Typography>
            <Typography component="dd" sx={{ m: 0, overflowWrap: 'anywhere' }}><bdi>{value}</bdi></Typography>
          </Box>)}
        </Box>}
      </Paper>
    </Box>
    {authentication.status === 'authenticated' && <AccessPortal />}
  </Stack>
}
