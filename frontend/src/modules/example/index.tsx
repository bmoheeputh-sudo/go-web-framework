import { ItemsPage } from './lazyPages'
import Assessment from '@mui/icons-material/Assessment'
import type { FrontendModule } from '../types'
import en from './locales/en.json'
import nl from './locales/nl.json'
import fr from './locales/fr.json'
import es from './locales/es.json'
import ptBR from './locales/pt-BR.json'
import zhCN from './locales/zh-CN.json'
import id from './locales/id.json'
import ms from './locales/ms.json'
import th from './locales/th.json'
import vi from './locales/vi.json'
import hi from './locales/hi.json'
import ar from './locales/ar.json'

const exampleModule: FrontendModule = {
  id: 'example',
  pages: [{ path: '/modules/example/items', labelKey: 'example:navItems', icon: <Assessment />,
    element: <ItemsPage />, requiredPermission: 'example.read' }],
  translations: { en, nl, fr, es, 'pt-BR': ptBR, 'zh-CN': zhCN, id, ms, th, vi, hi, ar },
}
export default exampleModule
