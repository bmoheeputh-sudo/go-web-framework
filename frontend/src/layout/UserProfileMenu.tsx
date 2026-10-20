import { useId, useState } from 'react'
import { Avatar, Box, Divider, ButtonBase, ListItemIcon, Menu, MenuItem, Tooltip, Typography, useMediaQuery } from '@mui/material'
import { useTheme } from '@mui/material/styles'
import ExpandMoreRounded from '@mui/icons-material/ExpandMoreRounded'
import { roleKeys } from '../i18n'
import LogoutRounded from '@mui/icons-material/LogoutRounded'
import { useTranslation } from 'react-i18next'
import { useSession } from '../auth/session'

const providers = { oidc: 'OIDC', local_dev: 'Local DEV' }

export default function UserProfileMenu() {
  const { t } = useTranslation(['auth', 'common', 'admin'])
  const { authentication, access, logout, loggingOut } = useSession()
  const theme = useTheme()
  const desktop = useMediaQuery(theme.breakpoints.up('md'))
  const detailsID = useId()
  const [anchor, setAnchor] = useState<HTMLElement | null>(null)
  if (authentication.status !== 'authenticated') return null
  const { identity } = authentication
  const displayName = identity.display_name.trim() || identity.email.trim() || t('common:notProvided')
  // Display precedence only; permissions and authorization still come from Go.
  const roles = access.user?.active ? access.user.roles : []
  const primaryRole = ['Admin', 'User', 'Viewer'].find((role) => roles.includes(role)) || roles[0]
  const roleLabel = access.loading ? t('common:loading') : primaryRole
    ? t(`admin:${roleKeys[primaryRole] || primaryRole}`, { defaultValue: primaryRole }) : t('common:none')
  const edge = theme.direction === 'rtl' ? 'left' : 'right'
  const fields = [
    ['displayName', identity.display_name], ['email', identity.email],
    ['provider', providers[identity.provider]], ['issuerLabel', identity.issuer], ['subjectLabel', identity.subject],
  ]
  return <>
    <Tooltip title={<bdi>{displayName}</bdi>} describeChild>
      <ButtonBase aria-label={t('profileMenu')} aria-describedby={desktop ? detailsID : undefined} aria-haspopup="menu" aria-expanded={Boolean(anchor)}
        aria-controls={anchor ? 'user-profile-menu' : undefined} disabled={loggingOut} onClick={(event) => setAnchor(event.currentTarget)}
        sx={{ p: 0.5, gap: 1, borderRadius: 2, minWidth: 44, minHeight: 44, maxWidth: { xs: 44, md: 240, lg: 300 },
          textAlign: 'start', '&:hover': { bgcolor: 'action.hover' }, '&.Mui-focusVisible': { outline: '2px solid', outlineColor: 'primary.main', outlineOffset: 2 } }}>
        <Avatar sx={{ width: 36, height: 36, bgcolor: 'primary.main', color: 'primary.contrastText', fontSize: 16, flexShrink: 0 }}>
          {Array.from(displayName)[0]?.toLocaleUpperCase()}
        </Avatar>
        {desktop && <>
          <Box id={detailsID} sx={{ minWidth: 0, maxWidth: { md: 160, lg: 220 }, overflow: 'hidden' }}>
            <Typography component="div" variant="body2" noWrap sx={{ minWidth: 0, fontWeight: 600 }}><bdi>{displayName}</bdi></Typography>
            <Typography component="div" variant="caption" color="text.secondary" noWrap sx={{ minWidth: 0 }}>{roleLabel}</Typography>
          </Box>
          <ExpandMoreRounded fontSize="small" sx={{ flexShrink: 0 }} />
        </>}
      </ButtonBase>
    </Tooltip>
    <Menu id="user-profile-menu" anchorEl={anchor} open={Boolean(anchor)} onClose={() => setAnchor(null)}
      anchorOrigin={{ vertical: 'bottom', horizontal: edge }} transformOrigin={{ vertical: 'top', horizontal: edge }}
      slotProps={{ paper: { sx: { width: 360, maxWidth: 'calc(100vw - 32px)' } }, list: { 'aria-label': t('profileMenu') } }}>
      <Box component="li" role="presentation" sx={{ px: 2, py: 1 }}>
        <Typography component="h2" variant="subtitle1" sx={{ mb: 1 }}>{t('profileMenu')}</Typography>
        <Box component="dl" sx={{ m: 0 }}>
          {fields.map(([label, value]) => <Box key={label} sx={{ mb: 1 }}>
            <Typography component="dt" variant="caption" color="text.secondary">{t(label)}</Typography>
            <Typography component="dd" variant="body2" sx={{ m: 0, overflowWrap: 'anywhere' }}><bdi>{value || t('common:notProvided')}</bdi></Typography>
          </Box>)}
        </Box>
      </Box>
      <Divider component="li" />
      {identity.provider === 'oidc' ? <MenuItem disabled={loggingOut} onClick={() => { setAnchor(null); void logout() }}>
        <ListItemIcon><LogoutRounded fontSize="small" /></ListItemIcon>
        {t(loggingOut ? 'signingOut' : 'signOut')}
      </MenuItem> : <Box component="li" role="presentation" sx={{ px: 2, py: 1 }}>
        <Typography variant="body2" color="text.secondary">{t('localDevIdentity')}</Typography>
      </Box>}
    </Menu>
  </>
}
