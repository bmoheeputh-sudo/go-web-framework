import { FormControl, InputLabel, NativeSelect } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { browserStorage, languages, languageStorageKey } from './i18n'

export default function LanguageSelector() {
  const { t, i18n } = useTranslation('common')
  return (
    <FormControl variant="standard" size="small" sx={{ minWidth: 150, color: 'inherit' }}>
      <InputLabel htmlFor="language-selector" sx={{ color: 'inherit' }}>{t('language')}</InputLabel>
      <NativeSelect value={i18n.resolvedLanguage} inputProps={{ id: 'language-selector' }}
        sx={{ color: 'inherit', '& .MuiNativeSelect-icon': { color: 'inherit' }, '& option': { color: 'text.primary', backgroundColor: 'background.paper' } }}
        onChange={(event) => {
          const language = event.target.value
          if (!Object.hasOwn(languages, language)) return
          try { browserStorage()?.setItem(languageStorageKey, language) } catch { /* In-memory selection still works. */ }
          void i18n.changeLanguage(language)
        }}>
        {Object.entries(languages).map(([code, name]) => <option key={code} value={code} lang={code} dir={code === 'ar' ? 'rtl' : 'ltr'}>{name}</option>)}
      </NativeSelect>
    </FormControl>
  )
}
