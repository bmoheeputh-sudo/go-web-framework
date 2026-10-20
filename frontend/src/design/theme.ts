import { createTheme } from '@mui/material/styles'
import type { PaletteMode } from '@mui/material'
import { arEG, enUS, esES, frFR, hiIN, idID, msMS, nlNL, ptBR, thTH, viVN, zhCN } from '@mui/material/locale'
import type { Language } from '../i18n'

export const designTokens = {
  sidebarExpanded: 260,
  sidebarCollapsed: 68,
  toolbarHeight: 80,
  contentMaxWidth: 1600,
  detailDrawerWidth: 480,
  controlRadius: 8,
  surfaceRadius: 12,
} as const

const muiLocales = { en: enUS, nl: nlNL, fr: frFR, es: esES, 'pt-BR': ptBR, 'zh-CN': zhCN, id: idID, ms: msMS, th: thTH, vi: viVN, hi: hiIN, ar: arEG }

export function createAppTheme(mode: PaletteMode, dir: 'ltr' | 'rtl', language: Language) {
  return createTheme({
    direction: dir,
    // Brand values live here. Components use palette roles, never these literals.
    palette: mode === 'dark'
      ? { mode, primary: { main: '#90caf9' } }
      : { mode, primary: { main: '#244f8f' }, background: { default: '#f4f6fb', paper: '#ffffff' }, text: { primary: '#19253b', secondary: '#58667e' }, divider: '#e3e8f0' },
    spacing: 8,
    shape: { borderRadius: designTokens.surfaceRadius },
    breakpoints: { values: { xs: 0, sm: 600, md: 900, lg: 1200, xl: 1536 } },
    typography: {
      fontFamily: "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif",
      h1: { fontWeight: 700 }, h2: { fontWeight: 700 }, h3: { fontWeight: 650 },
      h4: { fontWeight: 650 }, h5: { fontWeight: 650 }, h6: { fontWeight: 650 },
      button: { textTransform: 'none', fontWeight: 600 },
    },
    components: {
      MuiButton: { defaultProps: { disableElevation: true }, styleOverrides: { root: { borderRadius: designTokens.controlRadius } } },
      MuiTextField: { defaultProps: { size: 'small' } },
      MuiOutlinedInput: { styleOverrides: { root: { borderRadius: designTokens.controlRadius } } },
      MuiTable: { defaultProps: { size: 'small' } },
      MuiTableCell: { styleOverrides: { head: { fontWeight: 650 } } },
      MuiDialog: { styleOverrides: { paper: { borderRadius: designTokens.surfaceRadius } } },
      MuiDrawer: { styleOverrides: { paper: { backgroundImage: 'none' } } },
    },
  }, muiLocales[language])
}
