import type { ReactNode } from 'react'
import { Box, Stack, Typography } from '@mui/material'
import { typographyRoles } from '../../design/theme'

export default function PageHeader({ title, description, actions, component = 'h1', compact = false, noWrap = false }: {
  title: string
  description?: string
  actions?: ReactNode
  component?: 'h1' | 'h2'
  compact?: boolean
  noWrap?: boolean
}) {
  return <Stack direction={{ xs: 'column', sm: 'row' }} sx={{ minWidth: 0, alignItems: { sm: 'center' }, justifyContent: 'space-between', gap: 1.5 }}>
    <Box sx={{ minWidth: 0 }}>
      <Typography component={component} variant={compact ? typographyRoles.toolbarTitle : typographyRoles.pageTitle}
        noWrap={noWrap} sx={{ overflowWrap: 'anywhere' }}>{title}</Typography>
      {description && <Typography variant={typographyRoles.supportingText} color="text.secondary" sx={{ mt: 0.5 }}>{description}</Typography>}
    </Box>
    {actions && <Box sx={{ flexShrink: 0 }}>{actions}</Box>}
  </Stack>
}
