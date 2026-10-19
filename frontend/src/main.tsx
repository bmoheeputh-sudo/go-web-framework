import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { I18nextProvider } from 'react-i18next'
import { browserStorage, createI18n, detectLanguage, direction } from './i18n'
import LanguageProvider from './LanguageProvider'
import { BrowserRouter } from 'react-router-dom'

const language = detectLanguage(browserStorage(), navigator.languages)
const i18n = createI18n(language)
document.documentElement.lang = language
document.documentElement.dir = direction(language)

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <I18nextProvider i18n={i18n}>
      <LanguageProvider><BrowserRouter><App /></BrowserRouter></LanguageProvider>
    </I18nextProvider>
  </StrictMode>,
)
