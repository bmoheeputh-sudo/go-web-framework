import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'
import tseslint from 'typescript-eslint'
import { defineConfig, globalIgnores } from 'eslint/config'
import noHardcodedComponentColors from './eslint-rules/no-hardcoded-component-colors.mjs'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      reactHooks.configs.flat.recommended,
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      globals: globals.browser,
    },
  },
  {
    files: ['src/**/*.{ts,tsx}'],
    ignores: ['src/design/theme.ts', 'src/**/*.test.ts', 'src/**/*.test.tsx', 'src/test/**'],
    plugins: { designSystem: { rules: { 'no-hardcoded-component-colors': noHardcodedComponentColors } } },
    rules: { 'designSystem/no-hardcoded-component-colors': 'error' },
  },
])
