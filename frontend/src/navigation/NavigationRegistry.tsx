import type { ReactNode } from 'react'
import DashboardRounded from '@mui/icons-material/DashboardRounded'
import PeopleAltRounded from '@mui/icons-material/PeopleAltRounded'
import BusinessRounded from '@mui/icons-material/BusinessRounded'
import ShieldRounded from '@mui/icons-material/ShieldRounded'
import HistoryRounded from '@mui/icons-material/HistoryRounded'

import { DashboardPage, UsersPage, AccountsPage, RolesPage, AuditLogsPage } from '../pages/lazyPages'

export interface NavItem {
  path: `/${string}`
  labelKey: `${string}:${string}`
  icon: ReactNode
  element: ReactNode
  requiredRole?: string
  requiredPermission?: string
  /** Authentication is required unless explicitly public. */
  public?: boolean
}

export const defaultNavigation: readonly NavItem[] = [
  { path: '/', labelKey: 'common:navDashboard', icon: <DashboardRounded />, element: <DashboardPage />, public: true },
  { path: '/users', labelKey: 'common:navUsers', icon: <PeopleAltRounded />, element: <UsersPage />, requiredPermission: 'admin.manage' },
  { path: '/accounts', labelKey: 'common:navAccounts', icon: <BusinessRounded />, element: <AccountsPage />, requiredPermission: 'admin.manage' },
  { path: '/roles', labelKey: 'common:navRoles', icon: <ShieldRounded />, element: <RolesPage />, requiredPermission: 'admin.manage' },
  { path: '/audit', labelKey: 'common:navAudit', icon: <HistoryRounded />, element: <AuditLogsPage />, requiredPermission: 'admin.manage' },
]

// Explicit, static registration at application startup; no dynamic plugins.
export function createNavigationRegistry(additional: readonly NavItem[] = [], core: readonly NavItem[] = defaultNavigation): readonly NavItem[] {
  const items = [...core, ...additional]
  const paths = new Set<string>()
  for (const item of items) {
    if (!/^\/(?:[\w-]+(?:\/[\w-]+)*)?$/.test(item.path) || /^\/api(?:\/|$)/i.test(item.path)) throw new Error('Navigation paths must be static application paths outside /api')
    if (paths.has(item.path.toLowerCase())) throw new Error(`Duplicate navigation path: ${item.path}`)
    if (item.public && (item.requiredRole || item.requiredPermission)) throw new Error('Public navigation cannot require privileges')
    paths.add(item.path.toLowerCase())
  }
  return items
}
