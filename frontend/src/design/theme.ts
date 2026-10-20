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

// Semantic roles use MUI variants so modules inherit the same hierarchy.
export const typographyRoles = {
  pageTitle: 'h4',
  toolbarTitle: 'h5',
  sectionTitle: 'h6',
  primaryValue: 'body1',
  supportingText: 'body2',
  detailLabel: 'caption',
  tableHeader: 'subtitle2',
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
      h1: { fontSize: 'clamp(2rem, 1.65rem + 1.3vw, 2.75rem)', fontWeight: 700, lineHeight: 1.18, letterSpacing: '-0.03em' },
      h2: { fontSize: 'clamp(1.8rem, 1.5rem + 1vw, 2.3rem)', fontWeight: 700, lineHeight: 1.2, letterSpacing: '-0.025em' },
      h3: { fontSize: 'clamp(1.6rem, 1.4rem + 0.7vw, 2rem)', fontWeight: 700, lineHeight: 1.23, letterSpacing: '-0.02em' },
      h4: { fontSize: 'clamp(1.45rem, 1.25rem + 0.65vw, 1.85rem)', fontWeight: 700, lineHeight: 1.25, letterSpacing: '-0.02em' },
      h5: { fontSize: 'clamp(1.25rem, 1.1rem + 0.45vw, 1.55rem)', fontWeight: 650, lineHeight: 1.3, letterSpacing: '-0.015em' },
      h6: { fontSize: '1.08rem', fontWeight: 650, lineHeight: 1.35, letterSpacing: '-0.01em' },
      subtitle1: { fontSize: '0.98rem', fontWeight: 600, lineHeight: 1.45 },
      subtitle2: { fontSize: '0.82rem', fontWeight: 650, lineHeight: 1.4, letterSpacing: '0.01em' },
      body1: { fontSize: '0.95rem', fontWeight: 400, lineHeight: 1.55 },
      body2: { fontSize: '0.875rem', fontWeight: 400, lineHeight: 1.5 },
      caption: { fontSize: '0.78rem', fontWeight: 500, lineHeight: 1.4 },
      overline: { fontSize: '0.72rem', fontWeight: 700, lineHeight: 1.4, letterSpacing: '0.08em' },
      button: { fontSize: '0.875rem', textTransform: 'none', fontWeight: 650, lineHeight: 1.3 },
    },
    components: {
      MuiButton: { defaultProps: { disableElevation: true }, styleOverrides: {
        root: { borderRadius: designTokens.controlRadius, minHeight: 36 },
        sizeSmall: { minHeight: 30 },
      } },
      MuiTextField: { defaultProps: { size: 'small' } },
      MuiOutlinedInput: { styleOverrides: { root: { borderRadius: designTokens.controlRadius }, input: { lineHeight: 1.45 } } },
      MuiInputLabel: { styleOverrides: { root: { fontWeight: 500 } } },
      MuiFormControlLabel: { styleOverrides: { label: ({ theme }) => ({ ...theme.typography.body2 }) } },
      MuiTable: { defaultProps: { size: 'small' } },
      MuiTableCell: { styleOverrides: {
        root: { padding: '8px 12px', verticalAlign: 'middle' },
        head: ({ theme }) => ({ ...theme.typography.subtitle2, color: theme.palette.text.secondary, padding: '10px 12px' }),
        body: ({ theme }) => ({ ...theme.typography.body2 }),
      } },
      MuiTab: { styleOverrides: { root: ({ theme }) => ({ ...theme.typography.subtitle2, textTransform: 'none', minHeight: 48 }) } },
      MuiChip: { styleOverrides: { root: ({ theme }) => ({ ...theme.typography.caption, fontWeight: 650 }), label: { paddingInline: 10 } } },
      MuiDialog: { styleOverrides: { paper: { borderRadius: designTokens.surfaceRadius } } },
      MuiDrawer: { styleOverrides: { paper: { backgroundImage: 'none' } } },
    },
  }, muiLocales[language])
}
