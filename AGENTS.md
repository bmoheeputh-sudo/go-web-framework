# Repository engineering conventions

These instructions apply to this repository. Preserve the existing authentication, RBAC, account isolation, and audit boundaries when changing the UI or backend.

For frontend work:

- Extend the MUI theme in `frontend/src/design/theme.ts`; use its palette, spacing, typography, breakpoints, and `designTokens` instead of introducing another theme system.
- Reuse `frontend/src/components/common/`, `CompactTable`, `PageTools`, and the global notification provider before creating a new primitive or UI dependency.
- Never hardcode hex, RGB, HSL, or CSS named colors in component styling. Use semantic MUI palette tokens or colors derived from `theme`, including `alpha()`.
- Preserve React Router navigation and Fetch-based AJAX updates. Do not reload the document for internal routes or CRUD operations.
- Keep route guards and Go authorization intact. Never infer access from a hidden navigation link or module capability alone.
- Make layouts responsive and test Arabic RTL, including drawer anchors and portal-based menus.
- Keep all 12 translations consistent, use English fallback, and localize user-facing labels without translating user-created data or provider identifiers.
- Use keyboard-operable controls, visible focus, semantic headings, and accessible names for icons, dialogs, and status messages.
- Never persist credentials, tokens, evidence IDs, or other authentication secrets in browser storage or logs.
- Run `cd frontend && npm test && npm run lint && npm run build`, followed by `git diff --check`, after frontend changes. Report any check that could not run.

Use [the frontend design system guide](docs/frontend-design-system.md) for component and token usage. Do not add a second routing or UI framework without a demonstrated need.
