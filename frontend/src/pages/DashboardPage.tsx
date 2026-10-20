import { Box, CircularProgress, Stack } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { useSession } from '../auth/session'
import AuthenticationNotice from '../auth/AuthenticationNotice'
import AccessPortal from '../AccessPortal'
import SectionCard from '../components/common/SectionCard'
import StatusBadge from '../components/common/StatusBadge'
import TwoColumnKeyValue from '../components/common/TwoColumnKeyValue'

const providers = { oidc: 'providerOidc', google_iap: 'providerIap', local_dev: 'providerLocal' }

export default function DashboardPage() {
  const { t } = useTranslation(['common', 'auth'])
  const { health, authentication } = useSession()
  return <Stack spacing={3}>
    <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: '1fr 2fr' }, gap: 3 }}>
      <SectionCard title={t('backendStatus')}>
        {health === 'checking' ? <CircularProgress size={24} aria-label={t('checkingConnection')} /> : <StatusBadge label={t(health)} tone={health === 'connected' ? 'success' : 'error'} />}
      </SectionCard>
      <SectionCard title={t('auth:title')}>
        <AuthenticationNotice />
        {authentication.status === 'authenticated' && <TwoColumnKeyValue items={[
          { label: t('auth:provider'), value: t(`auth:${providers[authentication.identity.provider]}`) },
          { label: t('auth:displayName'), value: <bdi>{authentication.identity.display_name || t('notProvided')}</bdi> },
          { label: t('auth:email'), value: <bdi>{authentication.identity.email || t('notProvided')}</bdi> },
        ]} />}
      </SectionCard>
    </Box>
    {authentication.status === 'authenticated' && <AccessPortal />}
  </Stack>
}
