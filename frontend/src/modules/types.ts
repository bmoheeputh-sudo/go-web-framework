import type { NavItem } from '../navigation/NavigationRegistry'
import type { Language } from '../i18n'

export interface ModulePage extends Omit<NavItem, 'public' | 'requiredPermission'> {
  requiredPermission: string
}

export interface FrontendModule {
  id: string
  pages: readonly ModulePage[]
  translations: Record<Language, Record<string, string>>
}

// Explicit import functions, never URLs or import paths supplied by the server.
export type ModuleCatalog = Readonly<Record<string, () => Promise<{ default: FrontendModule }>>>
