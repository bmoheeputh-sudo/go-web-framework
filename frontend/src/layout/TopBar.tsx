import { AppBar, Box, IconButton, Toolbar, Typography } from '@mui/material'
import MenuRounded from '@mui/icons-material/MenuRounded'
import { useTranslation } from 'react-i18next'
import LanguageSelector from '../LanguageSelector'
import ThemeSelector from '../appearance/ThemeSelector'
import UserProfileMenu from './UserProfileMenu'

export default function TopBar({ titleKey, desktop, mobileOpen, onMenu }: { titleKey: string; desktop: boolean; mobileOpen: boolean; onMenu: () => void }) {
  const { t } = useTranslation(['common', 'auth'])
  return <AppBar position="sticky" color="inherit" elevation={0} sx={{ borderBottom: 1, borderColor: 'divider', top: 0 }}>
    <Toolbar sx={{ gap: 1, flexWrap: { xs: 'wrap', md: 'nowrap' }, height: { md: 80 }, py: 1, px: { xs: 1, sm: 2 }, minHeight: 80 }}>
      {!desktop && <IconButton aria-label={t(mobileOpen ? 'closeMenu' : 'openMenu')} aria-expanded={mobileOpen} onClick={onMenu}><MenuRounded /></IconButton>}
      <Typography variant="h5" component="h1" noWrap={desktop} sx={{ flex: '1 1 100px', minWidth: 0, fontWeight: 650, overflowWrap: 'anywhere' }}>{t(titleKey)}</Typography>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, flexShrink: 0, marginInlineStart: 'auto' }}>
        <LanguageSelector />
        <ThemeSelector />
        <UserProfileMenu />
      </Box>
    </Toolbar>
  </AppBar>
}
