import { Paper, TableCell, TableRow, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { useQuery } from '../api/queries'
import type { Role } from '../api/client'
import { permissionKeys, roleKeys } from '../i18n'
import { PageTools } from '../components/PageTools'
import CompactTable from '../components/CompactTable'

export default function RolesPage() {
  const { t, i18n } = useTranslation(['admin', 'common'])
  const query = useQuery<Role[]>('/api/admin/roles')
  return <>
    <PageTools busy={query.loading} error={query.error} />
    <Typography variant="h6" component="h2" sx={{ mb: 2 }}>{t('permissionCatalog')}</Typography>
    <Paper sx={{ overflow: 'hidden' }}>
      <CompactTable label={t('common:navRoles')} headers={[t('common:navRoles'), t('permissionCatalog')]}
        empty={!query.loading && !query.error && query.data?.length === 0} emptyMessage={t('rolesEmpty')}>
        {query.data?.map((role) => <TableRow key={role.name}>
          <TableCell component="th" scope="row">{t(roleKeys[role.name] || role.name, { defaultValue: role.name })}</TableCell>
          <TableCell>{role.permissions.length ? new Intl.ListFormat(i18n.resolvedLanguage || 'en').format(role.permissions.map((permission) => t(permissionKeys[permission] || permission, { defaultValue: permission }))) : t('common:none')}</TableCell>
        </TableRow>)}
      </CompactTable>
    </Paper>
  </>
}
