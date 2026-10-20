import { Chip } from '@mui/material'
import type { ChipProps } from '@mui/material/Chip'

export type StatusTone = 'neutral' | 'success' | 'warning' | 'error' | 'info'

export default function StatusBadge({ label, tone = 'neutral', variant = 'outlined' }: {
  label: string
  tone?: StatusTone
  variant?: ChipProps['variant']
}) {
  return <Chip size="small" label={label} color={tone === 'neutral' ? 'default' : tone} variant={variant}
    sx={{ maxWidth: '100%', '& .MuiChip-label': { overflow: 'hidden', textOverflow: 'ellipsis' } }} />
}
