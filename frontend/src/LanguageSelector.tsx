import { useState } from 'react'
import { IconButton, Menu, MenuItem, Tooltip, Typography } from '@mui/material'
import LanguageRounded from '@mui/icons-material/LanguageRounded'
import { useTheme } from '@mui/material/styles'
import { useTranslation } from 'react-i18next'
import { browserStorage, languages, languageStorageKey, supportedLanguage } from './i18n'

export default function LanguageSelector() {
  const { t, i18n } = useTranslation('common')
  const theme = useTheme()
  const [anchor, setAnchor] = useState<HTMLElement | null>(null)
  const language = supportedLanguage(i18n.resolvedLanguage || i18n.language) || 'en'
  const edge = theme.direction === 'rtl' ? 'left' : 'right'
  return <>
    <Tooltip title={t('language')}>
      <IconButton id="language-selector" aria-label={t('language')} aria-description={languages[language]} aria-haspopup="menu" aria-expanded={Boolean(anchor)}
        aria-controls={anchor ? 'language-menu' : undefined} onClick={(event) => setAnchor(event.currentTarget)}
        sx={{ gap: 0.5, borderRadius: 2, flexShrink: 0 }}>
        <LanguageRounded />
        <Typography component="span" variant="caption" dir="ltr" sx={{ fontWeight: 600 }}>{language.toUpperCase()}</Typography>
      </IconButton>
    </Tooltip>
    <Menu id="language-menu" anchorEl={anchor} open={Boolean(anchor)} onClose={() => setAnchor(null)}
      anchorOrigin={{ vertical: 'bottom', horizontal: edge }} transformOrigin={{ vertical: 'top', horizontal: edge }}
      slotProps={{ paper: { dir: theme.direction, sx: { maxHeight: 'min(70vh, 480px)' } }, list: { 'aria-label': t('language') } }}>
      {Object.entries(languages).map(([code, name]) => <MenuItem key={code} role="menuitemradio" aria-checked={language === code}
        selected={language === code} onClick={() => {
          setAnchor(null)
          try { browserStorage()?.setItem(languageStorageKey, code) } catch { /* In-memory selection still works. */ }
          void i18n.changeLanguage(code)
        }}><bdi lang={code}>{name}</bdi></MenuItem>)}
    </Menu>
  </>
}
