import { lazy, Suspense } from 'react'
import { Box, Tabs, Tab, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { useSearchParams } from 'react-router-dom'
import RolePermissions from '../settings/RolePermissions'
import PageHeader from '../components/common/PageHeader'

const AuthenticationSettings = lazy(() => import('../settings/AuthenticationSettings'))
const NotificationSettings = lazy(() => import('../settings/NotificationSettings'))

export default function SettingsPage() {
  const { t } = useTranslation(['admin', 'auth', 'common'])
  const [params, setParams] = useSearchParams()
  const tab = params.get('tab') === 'notifications' ? 2 : params.get('tab') === 'authentication' ? 1 : 0
  function selectTab(value: number) {
    const next = new URLSearchParams(params)
    if (value === 2) next.set('tab', 'notifications')
    else if (value === 1) next.set('tab', 'authentication')
    else next.delete('tab')
    setParams(next, { preventScrollReset: true })
  }
  return <>
    <Tabs value={tab} onChange={(_, value: number) => selectTab(value)} variant="scrollable" scrollButtons="auto" aria-label={t('common:navSettings')} sx={{ mb: 2, borderBottom: 1, borderColor: 'divider' }}>
      <Tab id="settings-roles-tab" aria-controls="settings-roles-panel" label={t('rolesPermissions')} />
      <Tab id="settings-auth-tab" aria-controls="settings-auth-panel" label={t('auth:title')} />
      <Tab id="settings-notifications-tab" aria-controls="settings-notifications-panel" label={t('emailNotifications')} />
    </Tabs>
    <Box role="tabpanel" id="settings-roles-panel" aria-labelledby="settings-roles-tab" hidden={tab !== 0}>
      <Box sx={{ mb: 2 }}><PageHeader title={t('rolesPermissions')} component="h2" compact /></Box>
      <RolePermissions />
    </Box>
    <Box role="tabpanel" id="settings-notifications-panel" aria-labelledby="settings-notifications-tab" hidden={tab !== 2} sx={{ minWidth: 0 }}>
      {tab === 2 && <Suspense fallback={<Typography>{t('common:loading')}</Typography>}><NotificationSettings /></Suspense>}
    </Box>
    <Box role="tabpanel" id="settings-auth-panel" aria-labelledby="settings-auth-tab" hidden={tab !== 1} sx={{ minWidth: 0 }}>
      {/* Unmount to discard entered secrets on leaving this tab. Role edits above remain intact. */}
      {tab === 1 && <Suspense fallback={<Typography>{t('common:loading')}</Typography>}><AuthenticationSettings /></Suspense>}
    </Box>
  </>
}
