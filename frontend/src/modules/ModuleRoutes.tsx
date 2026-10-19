import { useContext, useEffect, useState } from 'react'
import { I18nContext } from 'react-i18next'
import { api, APIError } from '../api/client'
import type { Identity } from '../api/client'
import { useSession } from '../auth/session'
import AppRoutes from '../navigation/AppRoutes'
import { createNavigationRegistry } from '../navigation/NavigationRegistry'
import type { NavItem } from '../navigation/NavigationRegistry'
import { capabilityIDs, composeModules } from './registry'

type Composition = { identity: Identity | null; items: readonly NavItem[]; warning: boolean }

export default function ModuleRoutes({ core }: { core: readonly NavItem[] }) {
  const { authentication, expire } = useSession()
  // The provider instance is stable across language changes; useTranslation's
  // language-specific wrapper is not a capability-fetch dependency.
  const { i18n } = useContext(I18nContext)
  const identity = authentication.status === 'authenticated' ? authentication.identity : null
  const [composition, setComposition] = useState<Composition>({ identity: null, items: core, warning: false })

  useEffect(() => {
    if (!identity) return
    const controller = new AbortController()
    async function load() {
      try {
        const capabilities = await api<unknown>('/api/modules', 'GET', undefined, controller.signal)
        if (controller.signal.aborted) return
        const modules = await composeModules(capabilityIDs(capabilities), i18n)
        if (controller.signal.aborted) return
        const items = createNavigationRegistry(modules.pages, core)
        modules.registerTranslations()
        setComposition({ identity, items, warning: false })
      } catch (error) {
        if (controller.signal.aborted) return
        if (error instanceof APIError && error.status === 401) expire()
        else setComposition({ identity, items: core, warning: true })
      }
    }
    void load()
    return () => controller.abort()
  }, [identity, i18n, core, expire])

  // Identity changes hide previous routes immediately, before effect cleanup.
  const current = identity !== null && composition.identity === identity
  return <AppRoutes items={current ? composition.items : core} moduleWarning={current && composition.warning} />
}
