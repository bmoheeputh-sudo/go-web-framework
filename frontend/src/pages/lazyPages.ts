import { lazy } from 'react'

export const DashboardPage = lazy(() => import('./DashboardPage'))
export const UsersPage = lazy(() => import('./UsersPage'))
export const AccountsPage = lazy(() => import('./AccountsPage'))
export const RolesPage = lazy(() => import('./RolesPage'))
export const AuditLogsPage = lazy(() => import('./AuditLogsPage'))

export const SettingsPage = lazy(() => import('./SettingsPage'))
