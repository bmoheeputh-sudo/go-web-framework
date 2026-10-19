import { Suspense, useState } from 'react'
import { Alert, Box, CircularProgress, Stack, useMediaQuery } from '@mui/material'
import { useTheme } from '@mui/material/styles'
import { Outlet, useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { browserStorage } from '../i18n'
import type { NavItem } from '../navigation/NavigationRegistry'
import { canAccess } from '../navigation/authorization'
import { useSession } from '../auth/session'
import Sidebar from './Sidebar'
import TopBar from './TopBar'

const drawerPreferenceKey = 'gwf.sidebar.expanded'
function initialExpanded() {
  try { return browserStorage()?.getItem(drawerPreferenceKey) !== 'false' } catch { return true }
}

export default function AdminLayout({ items, moduleWarning = false }: { items: readonly NavItem[]; moduleWarning?: boolean }) {
  const theme = useTheme()
  const desktop = useMediaQuery(theme.breakpoints.up('md'))
  const location = useLocation()
  const { t } = useTranslation(['common', 'auth'])
  const { authentication, access, loginFailed, logoutFailed } = useSession()
  const [expanded, setExpanded] = useState(initialExpanded)
  // Reset on every history-entry change, including returning to an old entry.
  // Adjust before rendering so a menu never flashes open on the next page.
  const [menu, setMenu] = useState({ key: location.key, open: false })
  if (menu.key !== location.key) setMenu({ key: location.key, open: false })
  const mobileOpen = menu.key === location.key && menu.open
  const user = authentication.status === 'authenticated' && !access.loading ? access.user : null
  const visible = items.filter((item) => canAccess(item, user))
  const titleKey = items.find((item) => item.path === (location.pathname.replace(/\/$/, '') || '/'))?.labelKey || 'common:pageNotFound'
  function toggleExpanded() {
    const next = !expanded
    setExpanded(next)
    try { browserStorage()?.setItem(drawerPreferenceKey, String(next)) } catch { /* Keep the in-memory preference. */ }
  }
  return <Box sx={{ display: 'flex', minHeight: '100dvh', width: '100%', minWidth: 0 }}>
    <Sidebar items={visible} desktop={desktop} expanded={expanded} mobileOpen={mobileOpen} onToggle={toggleExpanded} onClose={() => setMenu({ key: location.key, open: false })} />
    <Box sx={{ flex: 1, minWidth: 0 }}>
      <TopBar titleKey={titleKey} desktop={desktop} mobileOpen={mobileOpen} onMenu={() => setMenu({ key: location.key, open: !mobileOpen })} />
      <Box component="main" sx={{ p: { xs: 2, sm: 3, xl: 4 }, maxWidth: 1600, mx: 'auto', overflowWrap: 'anywhere' }}>
        <Stack spacing={2} sx={{ mb: loginFailed || logoutFailed || moduleWarning ? 2 : 0 }}>
          {loginFailed && authentication.status !== 'authenticated' && <Alert severity="error">{t('auth:loginFailed')}</Alert>}
          {logoutFailed && <Alert severity="error">{t('auth:logoutFailed')}</Alert>}
          {moduleWarning && <Alert severity="warning">{t('common:modulesUnavailable')}</Alert>}
        </Stack>
        <Suspense fallback={<CircularProgress size={28} aria-label={t('loading')} />}><Outlet /></Suspense>
      </Box>
    </Box>
  </Box>
}
