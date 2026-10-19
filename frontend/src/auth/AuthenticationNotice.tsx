import { Alert, Box, Button, CircularProgress } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { useSession } from './session'

export default function AuthenticationNotice() {
  const { t } = useTranslation('auth')
  const { authentication, oidcEnabled } = useSession()
  return <Box aria-live="polite">
    {authentication.status === 'loading' && <CircularProgress size={24} aria-label={t('checking')} />}
    {authentication.status === 'error' && <Alert severity="error">{t('identityError')}</Alert>}
    {authentication.status === 'unauthenticated' && <>
      <Alert severity="info">{t('unauthenticated')}</Alert>
      {oidcEnabled && <Button variant="contained" href="/api/auth/login" sx={{ mt: 2 }}>{t('signIn')}</Button>}
    </>}
  </Box>
}
