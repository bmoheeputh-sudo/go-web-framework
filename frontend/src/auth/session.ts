import { createContext, useContext } from 'react'
import type { Identity, User } from '../api/client'

export type Authentication =
  | { status: 'loading' | 'unauthenticated' | 'error' }
  | { status: 'authenticated'; identity: Identity }
export type Access = { loading: boolean; user: User | null; error: string }
export interface Session {
  authentication: Authentication
  access: Access
  health: string
  oidcEnabled: boolean
  loggingOut: boolean
  logoutFailed: boolean
  loginFailed: boolean
  logout: () => Promise<void>
  expire: () => void
  refreshAccess: () => void
}
export const SessionContext = createContext<Session | null>(null)
export function useSession() {
  const session = useContext(SessionContext)
  if (!session) throw new Error('SessionProvider is required')
  return session
}
