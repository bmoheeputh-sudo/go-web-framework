import { lazy, Suspense, useState } from 'react'
import { Box, Tabs, Tab, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import RolePermissions from '../settings/RolePermissions'

const AuthenticationSettings = lazy(() => import('../settings/AuthenticationSettings'))

export default function SettingsPage() {
  const { t } = useTranslation(['admin', 'auth', 'common'])
  const [tab, setTab] = useState(0)
  return <>
    <Tabs value={tab} onChange={(_, value: number) => setTab(value)} variant="scrollable" scrollButtons="auto" aria-label={t('common:navSettings')} sx={{ mb: 2, borderBottom: 1, borderColor: 'divider' }}>
      <Tab id="settings-roles-tab" aria-controls="settings-roles-panel" label={t('rolesPermissions')} />
      <Tab id="settings-auth-tab" aria-controls="settings-auth-panel" label={t('auth:title')} />
    </Tabs>
    <Box role="tabpanel" id="settings-roles-panel" aria-labelledby="settings-roles-tab" hidden={tab !== 0}>
      <Typography component="h2" variant="h6" sx={{ mb: 2 }}>{t('rolesPermissions')}</Typography>
      <RolePermissions />
    </Box>
    <Box role="tabpanel" id="settings-auth-panel" aria-labelledby="settings-auth-tab" hidden={tab !== 1} sx={{ minWidth: 0 }}>
      {/* Unmount to discard entered secrets on leaving this tab. Role edits above remain intact. */}
      {tab === 1 && <Suspense fallback={<Typography>{t('common:loading')}</Typography>}><AuthenticationSettings /></Suspense>}
    </Box>
  </>
}
