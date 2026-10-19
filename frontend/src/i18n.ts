import { createInstance } from 'i18next'
import type { Resource } from 'i18next'
import { initReactI18next } from 'react-i18next'

export const languages = {
  en: 'English', nl: 'Nederlands', fr: 'Français', es: 'Español',
  'pt-BR': 'Português (Brasil)', 'zh-CN': '简体中文', id: 'Bahasa Indonesia',
  ms: 'Bahasa Melayu', th: 'ไทย', vi: 'Tiếng Việt', hi: 'हिन्दी', ar: 'العربية',
} as const
export type Language = keyof typeof languages
export const languageStorageKey = 'gwf.language'
export const namespaces = ['common', 'auth', 'admin'] as const

// Bundle translations locally: language selection never sends identity or
// authentication data to a translation service.
const files = import.meta.glob<Record<string, string>>('./locales/*/*.json', { eager: true, import: 'default' })
export const resources: Record<string, Record<string, Record<string, string>>> = {}
for (const [path, translation] of Object.entries(files)) {
  const [, language, namespace] = path.match(/locales\/([^/]+)\/([^/]+)\.json$/)!
  resources[language] ??= {}
  resources[language][namespace] = translation
}

export function supportedLanguage(value: string): Language | undefined {
  const normalized = value.toLowerCase().replaceAll('_', '-')
  const exact = Object.keys(languages).find((language) => language.toLowerCase() === normalized)
  if (exact) return exact as Language
  const base = normalized.split('-')[0]
  if (base === 'pt') return 'pt-BR'
  if (base === 'zh') return 'zh-CN'
  return Object.hasOwn(languages, base) ? base as Language : undefined
}

export function detectLanguage(storage: Pick<Storage, 'getItem'> | undefined, browserLanguages: readonly string[]): Language {
  try {
    const saved = storage?.getItem(languageStorageKey)
    if (saved && Object.hasOwn(languages, saved)) return saved as Language
  } catch { /* Preferences remain usable when storage is blocked. */ }
  for (const language of browserLanguages) {
    const supported = supportedLanguage(language)
    if (supported) return supported
  }
  return 'en'
}

export function browserStorage(): Storage | undefined {
  try { return window.localStorage } catch { return undefined }
}

export function direction(language: string) { return supportedLanguage(language) === 'ar' ? 'rtl' : 'ltr' }

export function createI18n(language: Language, translations: Resource = resources) {
  const instance = createInstance()
  void instance.use(initReactI18next).init({
    resources: translations, lng: language, fallbackLng: 'en',
    supportedLngs: Object.keys(languages), load: 'currentOnly',
    ns: [...namespaces], defaultNS: 'common', initAsync: false,
    interpolation: { escapeValue: false }, // React escapes rendered text.
    returnEmptyString: false,
  })
  return instance
}

export function formatNumber(value: number, language: string) {
  return new Intl.NumberFormat(language).format(value)
}

export function formatDate(value: string, language: string) {
  return new Intl.DateTimeFormat(language, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}

// Unknown future codes remain visible rather than being mislabelled. These
// mappings affect display only; API requests always retain the original codes.
export const roleKeys: Record<string, string> = { Admin: 'roleAdmin', User: 'roleUser', Viewer: 'roleViewer' }
export const permissionKeys: Record<string, string> = {
  'admin.manage': 'permissionAdmin', 'accounts.read': 'permissionRead', 'accounts.write': 'permissionWrite',
}
export const actionKeys: Record<string, string> = {
  'admin.bootstrap': 'actionBootstrap', 'user.roles': 'actionRoles', 'user.active': 'actionActive',
  'user.accounts': 'actionAssociations', 'account.save': 'actionSave', 'account.rename': 'actionRename',
}
