import SessionProvider from './auth/SessionProvider'
import { useSession } from './auth/session'
import QueryProvider from './api/QueryProvider'
import ModuleRoutes from './modules/ModuleRoutes'
import { defaultNavigation } from './navigation/NavigationRegistry'
import type { NavItem } from './navigation/NavigationRegistry'
import NotificationProvider from './notifications/NotificationProvider'

function Portal({ items }: { items: readonly NavItem[] }) {
  const { authentication } = useSession()
  const identityKey = authentication.status === 'authenticated'
    ? JSON.stringify([authentication.identity.issuer, authentication.identity.subject]) : 'anonymous'
  // A different identity or logout disposes all cached administration data.
  return <QueryProvider key={identityKey}><NotificationProvider><ModuleRoutes core={items} /></NotificationProvider></QueryProvider>
}

export default function App({ navigation = defaultNavigation }: { navigation?: readonly NavItem[] }) {
  return <SessionProvider><Portal items={navigation} /></SessionProvider>
}
