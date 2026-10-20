import type { ReactNode } from 'react'
import { Box, Typography } from '@mui/material'
import { typographyRoles } from '../../design/theme'

export type DetailItem = { label: string; value: ReactNode }

export default function TwoColumnKeyValue({ items }: { items: readonly DetailItem[] }) {
  return <Box component="dl" sx={{ display: 'grid', gridTemplateColumns: { xs: 'minmax(0, 1fr)', sm: 'minmax(8rem, 1fr) minmax(0, 2fr)' }, columnGap: 2, rowGap: { xs: 0.5, sm: 1.5 }, m: 0 }}>
    {items.map((item, index) => <Box key={`${item.label}-${index}`} sx={{ display: 'contents' }}>
      <Typography component="dt" variant={typographyRoles.detailLabel} color="text.secondary" sx={{ minWidth: 0, fontWeight: 600, letterSpacing: '0.01em' }}>{item.label}</Typography>
      <Box component="dd" sx={{ m: 0, minWidth: 0, overflowWrap: 'anywhere', mb: { xs: 1.5, sm: 0 },
        typography: typographyRoles.primaryValue, fontWeight: 600, color: 'text.primary' }}>{item.value}</Box>
    </Box>)}
  </Box>
}
