import { Alert, Paper, Stack, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'

export default function ItemsPage() {
  const { t } = useTranslation('example')
  return <Paper sx={{ p: 3 }}><Stack spacing={2}>
    <Typography component="h2" variant="h5">{t('example:itemsTitle')}</Typography>
    <Alert severity="info">{t('example:description')}</Alert>
  </Stack></Paper>
}
