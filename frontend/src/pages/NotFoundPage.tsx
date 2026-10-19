import { Button, Paper, Typography } from '@mui/material'
import { Link } from 'react-router-dom'
import { useTranslation } from 'react-i18next'

export default function NotFoundPage() {
  const { t } = useTranslation('common')
  return <Paper sx={{ p: 4 }}>
    <Typography variant="overline">404</Typography>
    <Typography variant="h5" component="h2" gutterBottom>{t('pageNotFound')}</Typography>
    <Button component={Link} to="/" variant="contained">{t('backDashboard')}</Button>
  </Paper>
}
