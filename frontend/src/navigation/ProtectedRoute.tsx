import { Alert, Button, CircularProgress, Paper, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import type { NavItem } from './NavigationRegistry'
import { canAccess } from './authorization'
import { useSession } from '../auth/session'
import AuthenticationNotice from '../auth/AuthenticationNotice'

export default function ProtectedRoute({ item }: { item: NavItem }) {
  const { t } = useTranslation(['common', 'admin'])
  const { authentication, access, refreshAccess } = useSession()
  if (item.public && !item.requiredRole && !item.requiredPermission) return item.element
  if (authentication.status !== 'authenticated') return <Paper sx={{ p: 3 }}><AuthenticationNotice /></Paper>
  if (access.loading) return <CircularProgress size={28} aria-label={t('loading')} />
  if (access.error && access.error !== 'errorForbidden') return <Paper sx={{ p: 3 }}>
    <Alert severity="error">{t(`admin:${access.error}`)}</Alert>
    <Button onClick={refreshAccess}>{t('admin:refreshAccess')}</Button>
  </Paper>
  if (!canAccess(item, access.user)) return <Paper sx={{ p: 4 }}>
    <Typography variant="h5" component="h2" gutterBottom>{t('accessDenied')}</Typography>
    <Alert severity="warning">{t('admin:errorForbidden')}</Alert>
    <Button onClick={refreshAccess} sx={{ mt: 2 }}>{t('admin:refreshAccess')}</Button>
  </Paper>
  return item.element
}
