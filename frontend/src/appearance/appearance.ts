import { createContext, useContext } from 'react'
import { browserStorage } from '../i18n'

export type Appearance = 'light' | 'dark' | 'system'
export const appearanceStorageKey = 'gwf.appearance'
export function isAppearance(value: string | null): value is Appearance {
  return value === 'light' || value === 'dark' || value === 'system'
}
export function initialAppearance(): Appearance {
  try {
    const saved = browserStorage()?.getItem(appearanceStorageKey) || null
    if (isAppearance(saved)) return saved
  } catch { /* Blocked storage uses the system preference. */ }
  return 'system'
}
export const AppearanceContext = createContext<{ appearance: Appearance; setAppearance: (mode: Appearance) => void } | null>(null)
export function useAppearance() {
  const context = useContext(AppearanceContext)
  if (!context) throw new Error('LanguageProvider is required')
  return context
}
