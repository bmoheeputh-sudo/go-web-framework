import { useState } from 'react'
import { Box, Button, Checkbox, Chip, FormControlLabel, MenuItem, Stack, TableCell, TableRow, TextField, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { useSession } from '../auth/session'
import { useMutation, useQuery } from '../api/queries'
import type { Account, Role, User } from '../api/client'
import { roleKeys } from '../i18n'
import CompactTable from '../components/CompactTable'
import { Pager, PageTools } from '../components/PageTools'
import SectionCard from '../components/common/SectionCard'

export default function UsersPage() {
  const { t, i18n } = useTranslation(['admin', 'common'])
  const { access } = useSession()
  const actorID = access.user!.id
  const [userPage, setUserPage] = useState(0)
  const [accountPage, setAccountPage] = useState(0)
  const [selectedID, setSelectedID] = useState('')
  const [linkID, setLinkID] = useState('')
  const userQuery = useQuery<User[]>(`/api/admin/users?offset=${userPage * 100}`)
  const roleQuery = useQuery<Role[]>('/api/admin/roles')
  const accountQuery = useQuery<Account[]>(`/api/admin/accounts?offset=${accountPage * 100}`)
  const users = userQuery.data || []
  const roles = roleQuery.data || []
  const accounts = accountQuery.data || []
  const selected = users.find((user) => user.id === selectedID)
  const mutation = useMutation()
  const { mutate } = mutation
  const busy = mutation.busy || userQuery.loading || roleQuery.loading || accountQuery.loading
  const error = mutation.error || userQuery.error || roleQuery.error || accountQuery.error
  return <>
    <PageTools busy={busy} error={error} onRefresh={mutation.clearError} />
    <SectionCard title={t('usersRoles')} description={t('usersHelp')} busy={busy}>
      <CompactTable label={t('common:navUsers')} headers={[t('user'), t('common:navRoles'), t('common:status')]}
        empty={!userQuery.loading && !userQuery.error && users.length === 0} emptyMessage={t('usersEmpty')}>
        {users.map((user) => <TableRow key={user.id} selected={selectedID === user.id} hover>
          <TableCell component="th" scope="row">
            <Button size="small" aria-label={t('selectUser', { name: user.display_name || user.subject })} disabled={busy} onClick={() => setSelectedID(user.id)} sx={{ textAlign: 'start' }}>
              <bdi>{user.display_name || user.subject}</bdi>
            </Button>
            <Typography variant="caption" component="div" color="text.secondary"><bdi>{user.email || user.subject}</bdi></Typography>
          </TableCell>
          <TableCell>{user.roles.length ? new Intl.ListFormat(i18n.resolvedLanguage || 'en').format(user.roles.map((role) => t(roleKeys[role] || role, { defaultValue: role }))) : t('common:none')}</TableCell>
          <TableCell><Chip size="small" variant="outlined" color={user.active ? 'success' : 'default'} label={t(user.active ? 'common:statusActive' : 'common:statusInactive')} /></TableCell>
        </TableRow>)}
      </CompactTable>
      <Pager label={t('common:navUsers')} page={userPage} count={users.length} busy={busy} onChange={(page) => { setSelectedID(''); setUserPage(page) }} />
      {selected && <Box sx={{ my: 2, overflowWrap: 'anywhere' }}>
        <Typography>{t('issuer', { issuer: selected.issuer })}</Typography>
        <Typography>{t('subject', { subject: selected.subject })}</Typography>
        <Typography color="text.secondary">{t('userID', { id: selected.id })}</Typography>
        {roles.map((role) => <FormControlLabel key={role.name} label={t(roleKeys[role.name] || role.name, { defaultValue: role.name })} control={<Checkbox checked={selected.roles.includes(role.name)} disabled={busy || selected.id === actorID}
          onChange={(_, checked) => {
            if (role.name === 'Admin' && checked && !window.confirm(t('grantAdmin', { issuer: selected.issuer, subject: selected.subject }))) return
            void mutate(`/api/admin/users/${selected.id}/roles`, 'PUT', { roles: checked ? [...selected.roles, role.name] : selected.roles.filter((r) => r !== role.name) })
          }} />} />)}
        <Box><Button disabled={busy || selected.id === actorID} onClick={() => void mutate(`/api/admin/users/${selected.id}`, 'PUT', { active: !selected.active })}>{t(selected.active ? 'deactivate' : 'activate')}</Button></Box>
        {selected.id === actorID && <Typography variant="body2">{t('selfRestriction')}</Typography>}
        <Typography variant="subtitle1" sx={{ mt: 2 }}>{t('linkedAccounts')}</Typography>
        <Stack direction="row" useFlexGap sx={{ mb: 2, flexWrap: 'wrap', gap: 1 }}>
          {selected.account_ids.map((id) => <Chip key={id} label={accounts.find((account) => account.id === id)?.name || id} disabled={busy}
            onDelete={() => void mutate(`/api/admin/users/${selected.id}/accounts`, 'PUT', { account_ids: selected.account_ids.filter((value) => value !== id) })} />)}
        </Stack>
        <TextField select fullWidth label={t('accountToLink')} value={accounts.some((account) => account.id === linkID) ? linkID : ''} disabled={busy} onChange={(e) => setLinkID(e.target.value)}>
          {accounts.map((account) => <MenuItem key={account.id} value={account.id} disabled={selected.account_ids.includes(account.id)}>{account.name}{account.active ? '' : ` ${t('common:inactive')}`}</MenuItem>)}
        </TextField>
        <Button disabled={busy || !accounts.some((account) => account.id === linkID) || selected.account_ids.includes(linkID) || selected.account_ids.length >= 100}
          onClick={() => void mutate(`/api/admin/users/${selected.id}/accounts`, 'PUT', { account_ids: [...selected.account_ids, linkID] })}>{t('linkAccount')}</Button>
        <Pager label={t('linkedAccounts')} page={accountPage} count={accounts.length} busy={busy} onChange={(page) => { setLinkID(''); setAccountPage(page) }} />
      </Box>}

    </SectionCard>
  </>
}
