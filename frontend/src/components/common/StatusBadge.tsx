import { Chip } from '@mui/material'
import type { ChipProps } from '@mui/material/Chip'

export type StatusTone = 'neutral' | 'success' | 'warning' | 'error' | 'info'

export default function StatusBadge({ label, tone = 'neutral', variant = 'outlined', wrap = false }: {
  label: string
  tone?: StatusTone
  variant?: ChipProps['variant']
  wrap?: boolean
}) {
  return <Chip size="small" label={label} color={tone === 'neutral' ? 'default' : tone} variant={variant}
    sx={{ maxWidth: '100%', ...(wrap ? { height: 'auto', minHeight: 24, py: 0.25 } : {}), '& .MuiChip-label': wrap ? { whiteSpace: 'normal', overflow: 'visible', textOverflow: 'clip', lineHeight: 1.4 } : { overflow: 'hidden', textOverflow: 'ellipsis' } }} />
}
