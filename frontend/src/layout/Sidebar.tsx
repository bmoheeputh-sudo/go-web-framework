import MuiDrawer from '@mui/material/Drawer'
import type { SlideProps } from '@mui/material/Slide'
import { Box, Button, Divider, IconButton, List, ListItemButton, ListItemIcon, ListItemText, Toolbar, Tooltip, Typography } from '@mui/material'
import { alpha, styled, useTheme } from '@mui/material/styles'
import ChevronLeftRounded from '@mui/icons-material/ChevronLeftRounded'
import ChevronRightRounded from '@mui/icons-material/ChevronRightRounded'
import CloseRounded from '@mui/icons-material/CloseRounded'
import ShieldOutlined from '@mui/icons-material/ShieldOutlined'
import { NavLink, useLocation } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import type { NavItem } from '../navigation/NavigationRegistry'

const MiniDrawer = styled(MuiDrawer, { shouldForwardProp: (prop) => prop !== 'expanded' })<{ expanded: boolean }>(({ theme, expanded, variant }) => ({
  width: variant === 'temporary' ? undefined : expanded ? 260 : 68,
  flexShrink: 0,
  overflowX: 'hidden',
  transition: theme.transitions.create('width', { duration: theme.transitions.duration.standard }),
  '& .MuiDrawer-paper': {
    width: expanded ? 260 : 68,
    maxWidth: 'calc(100vw - 24px)',
    boxSizing: 'border-box',
    overflowX: 'hidden',
    overflowY: 'hidden',
    transition: theme.transitions.create('width', { duration: theme.transitions.duration.standard }),
  },
  '@media (prefers-reduced-motion: reduce)': { transition: 'none', '& .MuiDrawer-paper': { transition: 'none' } },
}))

interface Props {
  items: readonly NavItem[]
  desktop: boolean
  expanded: boolean
  mobileOpen: boolean
  onToggle: () => void
  onClose: () => void
}

export default function Sidebar({ items, desktop, expanded, mobileOpen, onToggle, onClose }: Props) {
  const { t } = useTranslation('common')
  const theme = useTheme()
  const location = useLocation()
  const rtl = theme.direction === 'rtl'
  const showLabels = !desktop || expanded
  const placement = rtl ? 'left' : 'right'
  const collapseIcon = rtl ? <ChevronRightRounded /> : <ChevronLeftRounded />
  const expandIcon = rtl ? <ChevronLeftRounded /> : <ChevronRightRounded />
  const transitionProps: Partial<SlideProps> = { direction: rtl ? 'left' : 'right' }
  const toggleLabel = t(expanded ? 'collapseSidebar' : 'expandSidebar')
  return <>
    {desktop && <Box data-testid="sidebar-edge" style={{ left: rtl ? 'auto' : 0, right: rtl ? 0 : 'auto' }}
      sx={{ position: 'fixed', top: 0, height: 80, width: expanded ? 260 : 68, overflow: 'visible', pointerEvents: 'none',
        zIndex: theme.zIndex.drawer + 1, transition: theme.transitions.create('width', { duration: theme.transitions.duration.standard }),
        '@media (prefers-reduced-motion: reduce)': { transition: 'none' } }}>
      {/* Outside the scrolling/clipped drawer paper; absolute positioning adds no layout width. */}
      <Tooltip title={toggleLabel} placement={placement}>
        <IconButton id="sidebar-toggle-edge" aria-label={toggleLabel} aria-expanded={expanded} onClick={onToggle}
          style={{ left: rtl ? -12 : 'auto', right: rtl ? 'auto' : -12 }}
          sx={{ position: 'absolute', top: 'calc(50% - 12px)', width: 24, height: 24, p: 0, borderRadius: '50%',
            pointerEvents: 'auto', border: '1px solid', borderColor: 'divider', bgcolor: 'background.paper', boxShadow: 1,
            '& .MuiSvgIcon-root': { fontSize: 18 }, '&:hover': { bgcolor: 'action.hover', boxShadow: 2 },
            '&.Mui-focusVisible': { outline: '2px solid', outlineColor: 'primary.main', outlineOffset: 2 } }}>
          {expanded ? collapseIcon : expandIcon}
        </IconButton>
      </Tooltip>
    </Box>}
    <MiniDrawer expanded={showLabels} variant={desktop ? 'permanent' : 'temporary'}
    anchor={rtl ? 'right' : 'left'} open={desktop || mobileOpen} onClose={onClose}
    slotProps={{
      // Explicit physical anchor plus RTL styles otherwise double-mirrors MUI's
      // left/right defaults. Inline positioning and Slide direction avoid that.
      paper: { style: { left: rtl ? 'auto' : 0, right: rtl ? 0 : 'auto', borderLeft: 'none', borderRight: 'none' }, sx: { borderInlineEnd: '1px solid', borderColor: 'divider', borderRadius: 0 } },
      transition: transitionProps,
    }}>
    <Toolbar sx={{ px: '12px !important', gap: 1, minHeight: '80px !important', height: 80, flexShrink: 0,
      flexWrap: 'nowrap', justifyContent: showLabels ? 'space-between' : 'center' }}>
      <Box aria-label={t('appName')} sx={{ minWidth: 0, display: 'flex', flexDirection: 'column', gap: 0.5,
        alignItems: showLabels ? 'flex-start' : 'center' }}>
        {/* Keep the original wide wordmark intact; a white backing preserves contrast in dark mode. */}
        {showLabels ? <Box sx={{ width: 140, maxWidth: '100%', p: 0.5, bgcolor: 'common.white', borderRadius: 0.5 }}>
          <Box component="img" src={`${import.meta.env.BASE_URL}assets/vopak-logo.png`} alt={t('brandLogoAlt')}
            width={1182} height={265} sx={{ display: 'block', width: '100%', height: 'auto', objectFit: 'contain' }} />
        </Box> : <Tooltip title={t('appName')} placement={placement}>
          <ShieldOutlined color="primary" titleAccess={t('appName')} sx={{ fontSize: 28 }} />
        </Tooltip>}
        {showLabels && <Typography variant="subtitle2" noWrap>{t('appShortName')}</Typography>}
      </Box>
      {!desktop && <Tooltip title={t('closeMenu')} placement={placement}>
        <IconButton aria-label={t('closeMenu')} aria-expanded={mobileOpen} onClick={onClose}
          sx={{ width: 40, height: 40, flexShrink: 0 }}><CloseRounded /></IconButton>
      </Tooltip>}
    </Toolbar>
    <Divider />
    <Box component="nav" aria-label={t('navigation')} sx={{ flex: 1, minHeight: 0, py: 2, overflowY: 'auto', overflowX: 'hidden' }}>
      <List disablePadding>
        {items.map((item) => {
          const active = (location.pathname.replace(/\/$/, '') || '/') === item.path
          return <Tooltip key={item.path} title={showLabels ? '' : t(item.labelKey)} placement={placement} describeChild>
            <ListItemButton component={NavLink} to={item.path} end caseSensitive aria-label={t(item.labelKey)} selected={active}
              onClick={() => { if (!desktop) onClose() }}
              sx={{ mx: 1, mb: 0.5, px: 1.75, height: 48, borderRadius: 2, gap: 1.5, color: active ? 'primary.main' : 'text.secondary', '&.Mui-selected': { backgroundColor: alpha(theme.palette.primary.main, theme.palette.action.selectedOpacity) } }}>
              <ListItemIcon sx={{ minWidth: 24, color: 'inherit' }}>{item.icon}</ListItemIcon>
              <ListItemText primary={t(item.labelKey)} sx={{ display: showLabels ? 'block' : 'none', whiteSpace: 'nowrap' }} slotProps={{ primary: { sx: { fontWeight: active ? 600 : 500, fontSize: 14 } } }} />
            </ListItemButton>
          </Tooltip>
        })}
      </List>
    </Box>
    {showLabels && <Box data-testid="sidebar-brand-footer" sx={{ flexShrink: 0, px: 2, py: desktop ? 1.5 : 1,
      borderTop: 1, borderColor: 'divider', color: 'text.secondary' }}>
      <Typography variant="caption" component="div" noWrap><bdi dir="ltr">{t('brandCopyright', { year: new Date().getFullYear() })}</bdi></Typography>
      {desktop && <Typography variant="caption" component="div" noWrap>{t('appShortName')}</Typography>}
    </Box>}
    {desktop && <Box sx={{ flexShrink: 0, p: 1.5, borderTop: 1, borderColor: 'divider', bgcolor: 'background.paper',
      display: 'flex', justifyContent: expanded ? 'flex-end' : 'center' }}>
      <Tooltip title={toggleLabel} placement={placement}>
        {expanded ? <Button id="sidebar-toggle-bottom" size="small" startIcon={collapseIcon} aria-expanded={expanded}
          onClick={onToggle} sx={{ minWidth: 0 }}>{toggleLabel}</Button>
          : <IconButton id="sidebar-toggle-bottom" aria-label={toggleLabel} aria-expanded={expanded} onClick={onToggle}>{expandIcon}</IconButton>}
      </Tooltip>
    </Box>}
  </MiniDrawer>
  </>
}
