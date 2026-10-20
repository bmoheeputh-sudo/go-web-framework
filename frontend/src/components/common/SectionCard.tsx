import { useId } from 'react'
import type { ReactNode } from 'react'
import { Box, Paper, Stack, Typography } from '@mui/material'

export default function SectionCard({ title, description, actions, children }: {
  title: string
  description?: string
  actions?: ReactNode
  children: ReactNode
}) {
  const titleID = useId()
  return <Paper component="section" variant="outlined" aria-labelledby={titleID} sx={{ p: { xs: 2, sm: 3 }, minWidth: 0 }}>
    <Stack direction={{ xs: 'column', sm: 'row' }} sx={{ justifyContent: 'space-between', alignItems: { sm: 'flex-start' }, gap: 2, mb: 2 }}>
      <Box sx={{ minWidth: 0 }}>
        <Typography id={titleID} component="h2" variant="h6">{title}</Typography>
        {description && <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>{description}</Typography>}
      </Box>
      {actions && <Box sx={{ flexShrink: 0 }}>{actions}</Box>}
    </Stack>
    {children}
  </Paper>
}
