import ContentCopy from '@mui/icons-material/ContentCopy'
import { IconButton, Stack, Tooltip, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { useNotifications } from '../../notifications/notifications'

export default function TechnicalValue({ label, value }: { label: string; value: string }) {
  const { t } = useTranslation(['auth', 'common'])
  const notify = useNotifications()
  async function copy() {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('clipboard unavailable')
      await navigator.clipboard.writeText(value)
      notify({ severity: 'success', messageKey: 'auth:setupCopied', values: { field: label } })
    } catch { notify({ severity: 'error', messageKey: 'auth:setupCopyFailed', values: { field: label } }) }
  }
  return <Stack direction="row" sx={{ minWidth: 0, alignItems: 'flex-start', gap: 0.5 }}>
    <Typography component="span" variant="body2" sx={{ minWidth: 0, flex: 1, fontFamily: 'monospace', overflowWrap: 'anywhere' }}><bdi>{value}</bdi></Typography>
    <Tooltip title={t('copySetupValue', { field: label })}><IconButton size="small" aria-label={t('copySetupValue', { field: label })} onClick={() => void copy()}><ContentCopy fontSize="small" /></IconButton></Tooltip>
  </Stack>
}

