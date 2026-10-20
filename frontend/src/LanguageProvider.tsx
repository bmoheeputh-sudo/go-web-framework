import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { CacheProvider } from '@emotion/react'
import createCache from '@emotion/cache'
import { ThemeProvider } from '@mui/material/styles'
import CssBaseline from '@mui/material/CssBaseline'
import useMediaQuery from '@mui/material/useMediaQuery'
import { prefixer } from 'stylis'
import rtlPlugin from '@mui/stylis-plugin-rtl'
import { browserStorage, direction, supportedLanguage } from './i18n'
import { AppearanceContext, appearanceStorageKey, initialAppearance } from './appearance/appearance'
import type { Appearance } from './appearance/appearance'
import { createAppTheme } from './design/theme'

const caches = {
  ltr: createCache({ key: 'mui', stylisPlugins: [prefixer] }),
  rtl: createCache({ key: 'muirtl', stylisPlugins: [prefixer, rtlPlugin] }),
}

export default function LanguageProvider({ children }: { children: ReactNode }) {
  const { i18n } = useTranslation()
  const language = supportedLanguage(i18n.resolvedLanguage || i18n.language) || 'en'
  const dir = direction(language)
  const [appearance, updateAppearance] = useState(initialAppearance)
  const systemDark = useMediaQuery('(prefers-color-scheme: dark)', { noSsr: true })
  const mode = appearance === 'system' ? (systemDark ? 'dark' : 'light') : appearance
  function setAppearance(value: Appearance) {
    updateAppearance(value)
    try { browserStorage()?.setItem(appearanceStorageKey, value) } catch { /* Selection still works in memory. */ }
  }
  const theme = useMemo(() => createAppTheme(mode, dir, language), [dir, language, mode])
  useEffect(() => {
    // Global direction also covers MUI menus/dialogs rendered through portals.
    document.documentElement.lang = language
    document.documentElement.dir = dir
  }, [language, dir])
  return <AppearanceContext.Provider value={{ appearance, setAppearance }}>
    <CacheProvider value={caches[dir]}><ThemeProvider theme={theme}><CssBaseline enableColorScheme />{children}</ThemeProvider></CacheProvider>
  </AppearanceContext.Provider>
}
