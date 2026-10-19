import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { QueryCache } from './cache'
import { QueryContext } from './queries'
import { useSession } from '../auth/session'

export default function QueryProvider({ children }: { children: ReactNode }) {
  const { expire } = useSession()
  const [cache] = useState(() => new QueryCache(expire))
  useEffect(() => () => cache.invalidate(), [cache])
  return <QueryContext.Provider value={cache}>{children}</QueryContext.Provider>
}
