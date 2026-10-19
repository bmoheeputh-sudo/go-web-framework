import { useEffect, useMemo } from 'react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { CacheProvider } from '@emotion/react'
import createCache from '@emotion/cache'
import { createTheme, ThemeProvider } from '@mui/material/styles'
import { arEG, enUS, esES, frFR, hiIN, idID, msMS, nlNL, ptBR, thTH, viVN, zhCN } from '@mui/material/locale'
import { prefixer } from 'stylis'
import rtlPlugin from '@mui/stylis-plugin-rtl'
import { direction, supportedLanguage } from './i18n'

const caches = {
  ltr: createCache({ key: 'mui', stylisPlugins: [prefixer] }),
  rtl: createCache({ key: 'muirtl', stylisPlugins: [prefixer, rtlPlugin] }),
}
const muiLocales = { en: enUS, nl: nlNL, fr: frFR, es: esES, 'pt-BR': ptBR, 'zh-CN': zhCN, id: idID, ms: msMS, th: thTH, vi: viVN, hi: hiIN, ar: arEG }

export default function LanguageProvider({ children }: { children: ReactNode }) {
  const { i18n } = useTranslation()
  const language = supportedLanguage(i18n.resolvedLanguage || i18n.language) || 'en'
  const dir = direction(language)
  const theme = useMemo(() => createTheme({ direction: dir }, muiLocales[language]), [dir, language])
  useEffect(() => {
    // Global direction also covers MUI menus/dialogs rendered through portals.
    document.documentElement.lang = language
    document.documentElement.dir = dir
  }, [language, dir])
  return <CacheProvider value={caches[dir]}><ThemeProvider theme={theme}>{children}</ThemeProvider></CacheProvider>
}
