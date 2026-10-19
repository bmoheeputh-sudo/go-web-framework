import { useCallback, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Alert, Snackbar } from '@mui/material'
import { useTheme } from '@mui/material/styles'
import { useTranslation } from 'react-i18next'
import { NotificationContext } from './notifications'
import type { Notification } from './notifications'

type Queued = Notification & { id: number; fingerprint: string }

export default function NotificationProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation()
  const theme = useTheme()
  const [queue, setQueue] = useState<Queued[]>([])
  const nextID = useRef(0)
  const notify = useCallback((notification: Notification) => {
    const values = Object.entries(notification.values || {}).sort(([a], [b]) => a.localeCompare(b))
    const fingerprint = JSON.stringify([notification.severity, notification.messageKey, values])
    const entry = { ...notification, id: ++nextID.current, fingerprint }
    // Collapse identical visible/queued messages. A later deliberate operation
    // can notify again after the previous message has been dismissed.
    setQueue((current) => current.some((item) => item.fingerprint === fingerprint) ? current : [...current, entry])
  }, [])
  const current = queue[0]
  const dismiss = () => setQueue((items) => items.slice(1))
  return <NotificationContext.Provider value={notify}>
    {children}
    {current && <Snackbar key={current.id} open autoHideDuration={6000}
      anchorOrigin={{ vertical: 'bottom', horizontal: theme.direction === 'rtl' ? 'left' : 'right' }}
      onClose={(_, reason) => { if (reason !== 'clickaway') dismiss() }}>
      <Alert severity={current.severity} variant="filled" onClose={dismiss} closeText={t('common:close')}
        role={current.severity === 'error' || current.severity === 'warning' ? 'alert' : 'status'}
        sx={{ width: '100%', overflowWrap: 'anywhere' }}>
        {t(current.messageKey, current.values)}
      </Alert>
    </Snackbar>}
  </NotificationContext.Provider>
}
