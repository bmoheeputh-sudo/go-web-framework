import { useId } from 'react'
import type { ReactNode } from 'react'
import { Box, Paper, Stack, Typography } from '@mui/material'
import { typographyRoles } from '../../design/theme'

export default function SectionCard({ title, description, actions, busy, children }: {
  title: string
  description?: string
  actions?: ReactNode
  busy?: boolean
  children: ReactNode
}) {
  const titleID = useId()
  return <Paper component="section" variant="outlined" aria-labelledby={titleID} aria-busy={busy}
    sx={{ p: { xs: 2, sm: 3 }, minWidth: 0 }}>
    <Stack direction={{ xs: 'column', sm: 'row' }} sx={{ justifyContent: 'space-between', alignItems: { sm: 'flex-start' }, gap: 1.5, mb: { xs: 2, sm: 2.5 } }}>
      <Box sx={{ minWidth: 0 }}>
        <Typography id={titleID} component="h2" variant={typographyRoles.sectionTitle}>{title}</Typography>
        {description && <Typography variant={typographyRoles.supportingText} color="text.secondary" sx={{ mt: 0.5, maxWidth: '70ch' }}>{description}</Typography>}
      </Box>
      {actions && <Box sx={{ flexShrink: 0 }}>{actions}</Box>}
    </Stack>
    {children}
  </Paper>
}
