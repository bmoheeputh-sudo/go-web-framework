import type { User } from '../api/client'
import type { NavItem } from './NavigationRegistry'

export function canAccess(item: NavItem, user: User | null): boolean {
  // A role and a permission, when both specified, are AND requirements.
  if (item.public && !item.requiredRole && !item.requiredPermission) return true
  return Boolean(user?.active === true &&
    (!item.requiredRole || user.roles.includes(item.requiredRole)) &&
    (!item.requiredPermission || user.permissions.includes(item.requiredPermission)))
}
