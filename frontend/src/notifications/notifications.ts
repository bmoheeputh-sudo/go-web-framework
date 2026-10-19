import { createContext, useContext } from 'react'
import type { AlertColor } from '@mui/material/Alert'

export interface Notification {
  severity: AlertColor
  messageKey: `${string}:${string}`
  values?: Record<string, string | number>
}
export const NotificationContext = createContext<((notification: Notification) => void) | null>(null)
export function useNotifications() {
  const notify = useContext(NotificationContext)
  if (!notify) throw new Error('NotificationProvider is required')
  return notify
}
