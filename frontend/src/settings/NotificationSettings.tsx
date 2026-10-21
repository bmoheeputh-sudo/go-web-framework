import { lazy, Suspense } from 'react'
import { Alert, Box, Stack, Tab, Tabs, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import { useSession } from '../auth/session'

const EmailConnectors = lazy(() => import('./EmailConnectors'))
const NotificationSend = lazy(() => import('./NotificationSend'))
const NotificationHistory = lazy(() => import('./NotificationHistory'))
const OnboardingOverview = lazy(() => import('./OnboardingOverview'))
const views = ['connectors', 'invitations', 'reminders', 'history', 'onboarding'] as const
const labels = ['emailConnectorsTitle', 'nmInvitations', 'nmReminders', 'nmHistory', 'nmOverview'] as const
export default function NotificationSettings() {
  const { t } = useTranslation(['admin', 'common'])
  const session = useSession()
  const [params, setParams] = useSearchParams()
  const value = views.includes(params.get('notification_view') as typeof views[number]) ? params.get('notification_view')! : 'connectors'
  if (session.authentication.status !== 'authenticated' || !session.access.user?.active || !session.access.user.permissions.includes('admin.manage')) return <Alert severity="error">{t('common:accessDenied')}</Alert>
  return <Stack spacing={2}>
    <Alert severity="info">{t('nmDeliveryDisabled')}</Alert>
    <Tabs value={value} variant="scrollable" scrollButtons="auto" aria-label={t('emailNotifications')} onChange={(_, next: string) => setParams((old) => { const p = new URLSearchParams(old); p.set('notification_view', next); return p }, { preventScrollReset: true })}>
      {views.map((view, index) => <Tab key={view} value={view} id={`notification-${view}-tab`} aria-controls={`notification-${view}-panel`} label={t(labels[index])} />)}
    </Tabs>
    <Box role="tabpanel" id={`notification-${value}-panel`} aria-labelledby={`notification-${value}-tab`} sx={{ minWidth: 0 }}>
      <Suspense fallback={<Typography>{t('common:loading')}</Typography>}>
        {value === 'connectors' ? <EmailConnectors /> : value === 'invitations' ? <NotificationSend key="invitation" kind="invitation" /> : value === 'reminders' ? <NotificationSend key="reminder" kind="reminder" /> : value === 'history' ? <NotificationHistory /> : <OnboardingOverview />}
      </Suspense>
    </Box>
  </Stack>
}
