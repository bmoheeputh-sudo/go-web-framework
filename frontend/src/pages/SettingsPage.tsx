import { Box, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import RolePermissions from '../settings/RolePermissions'

// Add future implemented sections here; no controls for unfinished settings.
const sections = [{ id: 'roles-permissions', titleKey: 'rolesPermissions', element: <RolePermissions /> }] as const

export default function SettingsPage() {
  const { t } = useTranslation('admin')
  return <>{sections.map((section) => <Box component="section" key={section.id} aria-labelledby={section.id}>
    <Typography id={section.id} component="h2" variant="h6" sx={{ mb: 2 }}>{t(section.titleKey)}</Typography>
    {section.element}
  </Box>)}</>
}
