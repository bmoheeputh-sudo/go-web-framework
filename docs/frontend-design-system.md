# Frontend design system

The application has one MUI theme, built by `createAppTheme` in `frontend/src/design/theme.ts` and provided by `LanguageProvider`. Appearance selection still chooses Light, Dark, or System; the selected language still controls MUI locale, HTML direction, and the Emotion RTL cache. Do not create a second theme provider for modules.

## Tokens

Use `theme.palette` roles for color: `primary`, `success`, `warning`, `error`, `info`, `text.primary`, `text.secondary`, `background.default`, `background.paper`, `divider`, and `action.hover`. Brand color literals are confined to the theme. Use `alpha(theme.palette.primary.main, opacity)` for derived colors. The dark theme retains MUI's accessible dark surfaces; the light theme retains the existing Vopak Enterprise Security palette.

MUI's 8 px spacing scale, default breakpoints (`xs` through `xl`), 12 px surface radius, and 8 px form/button radius are centralized in the theme. `designTokens` holds the established 260/68 px sidebar widths, 80 px toolbar, 1600 px content limit, and 480 px detail panel width. Use responsive `sx` values and logical inline properties in RTL-sensitive layouts. Paper does not have a mandatory global outline; select an outlined variant only when a section needs a border.

Buttons have no elevation, text fields and tables default to small size, table headings use a consistent weight, and dialogs and drawers inherit MUI theme surfaces. Keep headings semantic (`h1` for the page, `h2` for sections) even when their visual variant differs. Use the shared `CompactTable`, `PageTools`, and Snackbar notification provider for lists, loading, refresh, and mutation feedback.

## Shared primitives

Import from `frontend/src/components/common/`:

- `StatusBadge` displays a localized label with a semantic `neutral`, `success`, `warning`, `error`, or `info` tone. It does not choose a state from a provider identifier or translate the label itself.
- `SectionCard` provides a labeled section, optional description and actions, responsive padding, and an explicitly outlined surface.
- `TwoColumnKeyValue` renders responsive `dt`/`dd` details. Supply already localized labels and preserve the exact value of user-created data. Wrap untrusted LTR identifiers in `<bdi>` where needed.
- `DetailDrawer` provides a responsive, scrollable detail panel with a translated Close control and a trailing edge that mirrors in Arabic RTL. Pass actions as normal React controls; the caller retains authorization and mutation logic.

These primitives are opt-in. Existing pages remain unchanged in this foundation phase. Prefer them for new Settings sections, Users/Accounts details, Audit inspection, and future modules; migrate old sections only when their feature is next edited.

## Extension checks

Navigation stays in the existing React Router registry. New module pages must declare required permissions, use existing query and mutation hooks, and keep backend RBAC authoritative. Reuse namespace translations for all 12 languages and test both light/dark and Arabic RTL. Never store secrets or activation evidence in browser storage.

The repository-local ESLint rule rejects hardcoded component colors inside `sx`, inline `style`, and MUI `styled` declarations. It excludes the centralized theme, tests, fixtures, and assets, so legitimate palette definitions and data values remain possible. `frontend/src/App.css` is an unused Vite starter stylesheet; it is not imported by the application and can be removed in a separate cleanup. Existing page-specific spacing and Paper composition are candidates for gradual Phase K.2B adoption.
