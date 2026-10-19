import { useState } from 'react'
import { IconButton, ListItemIcon, Menu, MenuItem, Tooltip } from '@mui/material'
import { useTheme } from '@mui/material/styles'
import LightModeRounded from '@mui/icons-material/LightModeRounded'
import DarkModeRounded from '@mui/icons-material/DarkModeRounded'
import SettingsBrightnessRounded from '@mui/icons-material/SettingsBrightnessRounded'
import { useTranslation } from 'react-i18next'
import { useAppearance } from './appearance'

const modes = {
  light: { Icon: LightModeRounded, label: 'appearanceLight' },
  dark: { Icon: DarkModeRounded, label: 'appearanceDark' },
  system: { Icon: SettingsBrightnessRounded, label: 'appearanceSystem' },
} as const

export default function ThemeSelector() {
  const { t } = useTranslation('common')
  const theme = useTheme()
  const { appearance, setAppearance } = useAppearance()
  const [anchor, setAnchor] = useState<HTMLElement | null>(null)
  const edge = theme.direction === 'rtl' ? 'left' : 'right'
  const { Icon, label } = modes[appearance]
  return <>
    <Tooltip title={`${t('appearance')}: ${t(label)}`}>
      <IconButton id="appearance-selector" aria-label={t('appearance')} aria-description={t(label)}
        aria-haspopup="menu" aria-expanded={Boolean(anchor)} aria-controls={anchor ? 'appearance-menu' : undefined}
        onClick={(event) => setAnchor(event.currentTarget)}><Icon /></IconButton>
    </Tooltip>
    <Menu id="appearance-menu" anchorEl={anchor} open={Boolean(anchor)} onClose={() => setAnchor(null)}
      anchorOrigin={{ vertical: 'bottom', horizontal: edge }} transformOrigin={{ vertical: 'top', horizontal: edge }}
      slotProps={{ paper: { dir: theme.direction }, list: { 'aria-label': t('appearance') } }}>
      {(['light', 'dark', 'system'] as const).map((mode) => {
        const { Icon: ModeIcon, label: modeLabel } = modes[mode]
        return <MenuItem key={mode} role="menuitemradio" selected={appearance === mode} aria-checked={appearance === mode}
          onClick={() => { setAppearance(mode); setAnchor(null) }}>
          <ListItemIcon><ModeIcon fontSize="small" /></ListItemIcon>{t(modeLabel)}
        </MenuItem>
      })}
    </Menu>
  </>
}
