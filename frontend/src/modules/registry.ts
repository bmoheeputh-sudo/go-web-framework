import type { i18n } from 'i18next'
import { registerModuleTranslations } from '../i18n'
import { createNavigationRegistry } from '../navigation/NavigationRegistry'
import type { NavItem } from '../navigation/NavigationRegistry'
import type { ModuleCatalog } from './types'

export const moduleCatalog: ModuleCatalog = {
  example: () => import('./example'),
}
const moduleID = /^[a-z][a-z0-9_]{0,39}$/
const permissionName = /^[a-z][a-z0-9_]{0,39}\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$/

export function capabilityIDs(value: unknown): string[] {
  if (!value || typeof value !== 'object' || !('modules' in value) ||
    !Array.isArray(value.modules) || !value.modules.every((id: unknown) => typeof id === 'string' && moduleID.test(id))) {
    throw new Error('Invalid module capabilities')
  }
  return [...new Set<string>(value.modules)]
}

// Async composition keeps disabled modules' translations out of initial bundles.
// No translations are injected until the caller confirms the session is current.
export async function composeModules(enabledIDs: readonly string[], instance: i18n, catalog: ModuleCatalog = moduleCatalog) {
  const enabled = [...new Set(enabledIDs)]
  const modules = await Promise.all(enabled.map(async (id) => {
    if (!moduleID.test(id)) throw new Error('Invalid module ID')
    if (!Object.hasOwn(catalog, id)) {
      console.warn(`Enabled module "${id}" is not bundled in this frontend; ignoring it.`)
      return null
    }
    const { default: module } = await catalog[id]()
    if (module.id !== id) throw new Error('Module catalog ID mismatch')
    for (const page of module.pages) {
      if ('public' in page || !page.path.startsWith(`/modules/${id}/`) ||
        !page.labelKey.startsWith(`${id}:`) ||
        !permissionName.test(page.requiredPermission) || !page.requiredPermission.startsWith(`${id}.`)) {
        throw new Error('Invalid protected module page')
      }
    }
    return module
  }))
  const selected = modules.filter((module) => module !== null)
  const pages: NavItem[] = selected.flatMap((module) => [...module.pages])
  createNavigationRegistry(pages) // Validate static paths and duplicate routes.
  return {
    pages,
    registerTranslations: () => {
      for (const module of selected) registerModuleTranslations(instance, module.id, module.translations)
    },
  }
}
