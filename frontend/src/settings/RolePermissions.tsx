import { Fragment, useState } from 'react'
import { Alert, Box, Button, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle, MenuItem, Paper, Stack, TableCell, TableRow, TextField, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery } from '../api/queries'
import type { PermissionCatalog, PermissionChange } from '../api/client'
import { useSession } from '../auth/session'
import { permissionKeys, roleKeys } from '../i18n'
import CompactTable from '../components/CompactTable'
import { PageTools } from '../components/PageTools'

type Draft = { base: PermissionCatalog; changes: Record<string, PermissionChange> }
type Confirmation = { kind: 'save' } | { kind: 'register'; permission: string }

export default function RolePermissions() {
  const { t } = useTranslation(['admin', 'common'])
  const query = useQuery<PermissionCatalog>('/api/admin/permissions')
  const mutation = useMutation()
  const { refreshAccess } = useSession()
  const [draft, setDraft] = useState<Draft | null>(null)
  const [search, setSearch] = useState('')
  const [group, setGroup] = useState('all')
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null)
  const data = draft?.base || query.data
  const changes = Object.values(draft?.changes || {})
  const dirty = changes.length > 0
  const busy = query.loading || mutation.busy
  const groups = [...new Set(data?.permissions.map((permission) => permission.module) || [])].sort()
  const filtered = data?.permissions.filter((permission) => (group === 'all' || group === permission.module) &&
    `${permission.name} ${permission.description} ${t(permissionKeys[permission.name] || 'descriptionUnavailable')}`.toLocaleLowerCase().includes(search.toLocaleLowerCase())) || []
  function edit(role: string, permission: string, assigned: boolean) {
    if (!data) return
    const next = { ...draft?.changes }
    const key = `${role}:${permission}`
    const before = data.permissions.find((item) => item.name === permission)!.roles.includes(role)
    if (before === assigned) delete next[key]
    else next[key] = { role, permission, assigned }
    setDraft(Object.keys(next).length ? { base: data, changes: next } : null)
  }
  async function confirm() {
    if (!confirmation || !data) return
    const success = confirmation.kind === 'register'
      ? await mutation.mutate('/api/admin/permissions', 'POST', { permission: confirmation.permission })
      : await mutation.mutate('/api/admin/role-permissions', 'PUT', { revision: data.revision, changes })
    setConfirmation(null)
    if (success) { setDraft(null); refreshAccess() }
  }
  return <Stack spacing={2}>
    <Alert severity="info">{t('criticalPermissionPolicy')}</Alert>
    <PageTools busy={busy || dirty} error={mutation.error || query.error} onRefresh={mutation.clearError} />
    {dirty && <Alert severity="warning">{t('unsavedPermissions')}</Alert>}
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
      <TextField fullWidth label={t('searchPermissions')} value={search} onChange={(event) => setSearch(event.target.value)} />
      <TextField select label={t('permissionGroup')} value={group} onChange={(event) => setGroup(event.target.value)} sx={{ minWidth: 190 }}>
        <MenuItem value="all">{t('allGroups')}</MenuItem>
        {groups.map((id) => <MenuItem key={id} value={id}>{id === 'framework' ? t('frameworkGroup') : id}</MenuItem>)}
      </TextField>
    </Stack>
    <Paper sx={{ overflow: 'hidden' }} aria-busy={busy}>
      <CompactTable label={t('rolesPermissions')} headers={[t('permissionCatalog'), t('common:status'), ...(data?.roles || []).map((role) => t(roleKeys[role] || role))]}
        empty={!query.loading && !query.error && filtered.length === 0} emptyMessage={t('permissionsEmpty')} minWidth={640}>
        {groups.filter((id) => filtered.some((p) => p.module === id)).map((id) => <Fragment key={id}>
          <TableRow><TableCell component="th" scope="rowgroup" colSpan={2 + (data?.roles.length || 0)} sx={{ bgcolor: 'action.hover', fontWeight: 600 }}>{id === 'framework' ? t('frameworkGroup') : <bdi>{id}</bdi>}</TableCell></TableRow>
          {filtered.filter((permission) => permission.module === id).map((permission) => <TableRow key={permission.name}>
            <TableCell component="th" scope="row">
              <Typography component="div" variant="body2"><bdi>{permission.name}</bdi></Typography>
              <Typography variant="caption" color="text.secondary">{permissionKeys[permission.name] ? t(permissionKeys[permission.name]) : permission.description || t('descriptionUnavailable')}</Typography>
            </TableCell>
            <TableCell>
              <Stack spacing={1} sx={{ alignItems: 'flex-start' }}>
                {!permission.known && <Chip size="small" label={t('permissionUncompiled')} />}
                {permission.known && !permission.enabled && <Chip size="small" label={t('permissionDisabled')} />}
                {!permission.registered && <Chip size="small" color="warning" label={t('permissionMissing')} />}
                {!permission.registered && permission.known && permission.enabled && permission.module !== 'framework' &&
                  <Button size="small" disabled={busy || dirty} aria-label={t('registerNamedPermission', { permission: permission.name })}
                    onClick={() => setConfirmation({ kind: 'register', permission: permission.name })}>{t('registerPermission')}</Button>}
                {permission.registered && <Typography variant="caption">{t('permissionRegistered')}</Typography>}
              </Stack>
            </TableCell>
            {data?.roles.map((role) => {
              const assigned = draft?.changes[`${role}:${permission.name}`]?.assigned ?? permission.roles.includes(role)
              return <TableCell key={role}><Checkbox checked={assigned}
                disabled={busy || !permission.known || !permission.registered || permission.name === 'admin.manage' || (!permission.enabled && !permission.roles.includes(role))}
                slotProps={{ input: { 'aria-label': t('permissionAssignment', { permission: permission.name, role: t(roleKeys[role] || role) }) } }}
                onChange={(_, checked) => edit(role, permission.name, checked)} /></TableCell>
            })}
          </TableRow>)}
        </Fragment>)}
      </CompactTable>
    </Paper>
    <Stack direction="row" spacing={1}>
      <Button variant="contained" disabled={busy || !dirty} onClick={() => setConfirmation({ kind: 'save' })}>{t('savePermissions')}</Button>
      <Button disabled={mutation.busy || !dirty} onClick={() => { setDraft(null); mutation.clearError() }}>{t('common:cancel')}</Button>
    </Stack>
    <Dialog open={confirmation !== null} onClose={() => { if (!mutation.busy) setConfirmation(null) }} aria-labelledby="permission-confirm-title" fullWidth maxWidth="sm">
      <DialogTitle id="permission-confirm-title">{t('confirmPermissionChanges')}</DialogTitle>
      <DialogContent>
        <Typography sx={{ mb: 2 }}>{t(confirmation?.kind === 'register' ? 'registerPermissionHelp' : 'permissionChangesHelp')}</Typography>
        {confirmation?.kind === 'register' ? <bdi>{confirmation.permission}</bdi> : changes.map((change) => <Box key={`${change.role}:${change.permission}`}>
          <Typography><bdi>{change.permission}</bdi> · {t(roleKeys[change.role] || change.role)} · {t(change.assigned ? 'permissionGrant' : 'permissionRevoke')}</Typography>
        </Box>)}
      </DialogContent>
      <DialogActions>
        <Button disabled={mutation.busy} onClick={() => setConfirmation(null)}>{t('common:cancel')}</Button>
        <Button disabled={mutation.busy} onClick={() => void confirm()}>{t('confirmPermissions')}</Button>
      </DialogActions>
    </Dialog>
  </Stack>

}
