import { useId } from 'react'
import type { ReactNode } from 'react'
import { Box, Divider, Drawer, IconButton, Stack, Tooltip, Typography } from '@mui/material'
import { useTheme } from '@mui/material/styles'
import CloseRounded from '@mui/icons-material/CloseRounded'
import { useTranslation } from 'react-i18next'
import { designTokens } from '../../design/theme'

export default function DetailDrawer({ open, onClose, title, titleAdornment, actions, children }: {
  open: boolean
  onClose: () => void
  title: string
  titleAdornment?: ReactNode
  actions?: ReactNode
  children: ReactNode
}) {
  const { t } = useTranslation('common')
  const theme = useTheme()
  const titleID = useId()
  const rtl = theme.direction === 'rtl'
  return <Drawer open={open} onClose={onClose} anchor={rtl ? 'left' : 'right'}
    slotProps={{ paper: { 'aria-labelledby': titleID,
      // Emotion's RTL transform can mirror MUI's physical anchor a second time.
      style: { left: rtl ? 0 : 'auto', right: rtl ? 'auto' : 0 },
      sx: { width: { xs: '100%', sm: designTokens.detailDrawerWidth }, maxWidth: '100vw', display: 'flex', flexDirection: 'column' } } }}>
    <Stack direction="row" sx={{ alignItems: 'center', justifyContent: 'space-between', gap: 1, px: 2, py: 1.5 }}>
      <Stack direction="row" sx={{ minWidth: 0, alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
        <Typography id={titleID} component="h2" variant="h6" sx={{ minWidth: 0, overflowWrap: 'anywhere' }}>{title}</Typography>
        {titleAdornment}
      </Stack>
      <Tooltip title={t('close')}><IconButton aria-label={t('close')} onClick={onClose}><CloseRounded /></IconButton></Tooltip>
    </Stack>
    <Divider />
    <Box sx={{ flex: 1, minHeight: 0, overflowY: 'auto', p: { xs: 2, sm: 3 } }}>{children}</Box>
    {actions && <><Divider /><Stack direction="row" sx={{ p: 2, justifyContent: 'flex-end', gap: 1, flexWrap: 'wrap' }}>{actions}</Stack></>}
  </Drawer>
}
