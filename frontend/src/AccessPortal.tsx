import { Alert, Button, Chip, LinearProgress, Stack, Typography } from '@mui/material'
import RefreshRounded from '@mui/icons-material/RefreshRounded'
import { useTranslation } from 'react-i18next'
import { useSession } from './auth/session'
import { useQuery, useQueryCache } from './api/queries'
import type { Account } from './api/client'
import { roleKeys } from './i18n'
import SectionCard from './components/common/SectionCard'

export default function AccessPortal() {
  const { t } = useTranslation(['admin', 'common'])
  const { access, refreshAccess } = useSession()
  const cache = useQueryCache()
  const user = access.user
  const canRead = user?.active && user.permissions.includes('accounts.read')
  const accounts = useQuery<Account[]>(canRead ? '/api/accounts' : null)
  const error = access.error || accounts.error
  return <SectionCard title={t('accountAccess')} actions={<Button startIcon={<RefreshRounded />} disabled={access.loading} onClick={() => { cache.invalidate(); refreshAccess() }}>{t('refreshAccess')}</Button>}>
    {(access.loading || accounts.loading) && <LinearProgress aria-label={t('common:loading')} />}
    {error && <Alert severity="warning">{t(error)}</Alert>}
    {user && <Stack spacing={2}>
      <Stack direction="row" sx={{ gap: 1, flexWrap: 'wrap' }}>
        {user.roles.length ? user.roles.map((role) => <Chip key={role} label={t(roleKeys[role] || role, { defaultValue: role })} />) : <Typography color="text.secondary">{t('noRoles')}</Typography>}
      </Stack>
      {accounts.data?.map((account) => <Typography key={account.id}><bdi>{account.name}</bdi></Typography>)}
      {canRead && accounts.data?.length === 0 && <Typography color="text.secondary">{t('noAccounts')}</Typography>}
    </Stack>}
  </SectionCard>
}
