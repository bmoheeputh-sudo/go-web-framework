import { Alert, Box, Button, Paper, Stack, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'

// This page is display-only. The administrator window reads the protected test
// status endpoint; a query parameter here is never verification evidence.
export default function VerificationResultPage({ result }: { result: string | null }) {
  const { t } = useTranslation('auth')
  const outcome = result === 'success' ? 'success' : result === 'declined' ? 'declined' : 'failed'
  return <Box component="main" sx={{ minHeight: '100vh', display: 'grid', placeItems: 'center', p: 2 }}>
    <Paper variant="outlined" sx={{ width: '100%', maxWidth: 440, p: 3 }}>
      <Stack spacing={2}>
        <Typography component="h1" variant="h5">{t(`verificationPopup_${outcome}`)}</Typography>
        <Alert severity={outcome === 'success' ? 'success' : 'warning'}>{t('verificationPopupReturn')}</Alert>
        <Button variant="contained" onClick={() => window.close()}>{t('verificationPopupClose')}</Button>
      </Stack>
    </Paper>
  </Box>
}
