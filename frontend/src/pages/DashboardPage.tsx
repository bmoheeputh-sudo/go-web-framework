import { Stack } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { useSession } from '../auth/session'
import AuthenticationNotice from '../auth/AuthenticationNotice'
import AccessPortal from '../AccessPortal'
import SectionCard from '../components/common/SectionCard'
import TwoColumnKeyValue from '../components/common/TwoColumnKeyValue'

const providers = { oidc: 'providerOidc', local_dev: 'providerLocal' }

export default function DashboardPage() {
  const { t } = useTranslation(['common', 'auth'])
  const { authentication } = useSession()
  return <Stack spacing={3}>
    <SectionCard title={t('auth:title')}>
      <AuthenticationNotice />
      {authentication.status === 'authenticated' && <TwoColumnKeyValue items={[
        { label: t('auth:provider'), value: t(`auth:${providers[authentication.identity.provider]}`) },
        { label: t('auth:displayName'), value: <bdi>{authentication.identity.display_name || t('notProvided')}</bdi> },
        { label: t('auth:email'), value: <bdi>{authentication.identity.email || t('notProvided')}</bdi> },
      ]} />}
    </SectionCard>
    {authentication.status === 'authenticated' && <AccessPortal />}
  </Stack>
}
