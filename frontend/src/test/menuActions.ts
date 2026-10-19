import { expect } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { languages, resources } from '../i18n'
import type { Language } from '../i18n'
import type { Appearance } from '../appearance/appearance'

export async function chooseLanguage(language: Language) {
  await userEvent.click(document.getElementById('language-selector')!)
  await userEvent.click(await screen.findByRole('menuitemradio', { name: languages[language] }))
  await waitFor(() => expect(screen.queryByRole('menu')).toBeNull())
}
export async function chooseAppearance(appearance: Appearance) {
  const language = document.documentElement.lang as Language
  const labels = { light: 'appearanceLight', dark: 'appearanceDark', system: 'appearanceSystem' } as const
  await userEvent.click(document.getElementById('appearance-selector')!)
  await userEvent.click(await screen.findByRole('menuitemradio', { name: resources[language].common[labels[appearance]] }))
  await waitFor(() => expect(screen.queryByRole('menu')).toBeNull())
}
