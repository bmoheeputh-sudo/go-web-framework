import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { actionKeys, formatDate, formatNumber, permissionKeys, roleKeys } from './i18n'
import {
  Alert, Box, Button, Checkbox, Chip, FormControlLabel, MenuItem,
  Paper, Stack, TextField, Typography,
} from '@mui/material'

type User = {
  id: string; issuer: string; subject: string; email: string; display_name: string
  active: boolean; roles: string[]; permissions: string[]; account_ids: string[]
}
type Account = { id: string; name: string; active: boolean }
type Role = { name: string; permissions: string[] }
type Audit = { id: string; created_at: string; actor_id: string; action: string; target_id: string; details: unknown }

class APIError extends Error {}

async function api<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method, credentials: 'same-origin', cache: 'no-store',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) {
    if (response.status === 401) throw new APIError('errorUnauthenticated')
    if (response.status === 403) throw new APIError('errorForbidden')
    if (response.status === 409) throw new APIError('errorConflict')
    if (response.status === 400) throw new APIError('errorInvalid')
    throw new APIError('errorUnavailable')
  }
  return response.status === 204 ? undefined as T : response.json() as Promise<T>
}
function message(error: unknown) { return error instanceof APIError ? error.message : 'errorRequest' }

export default function AccessPortal() {
  const { t } = useTranslation('admin')
  const [user, setUser] = useState<User | null>(null)
  const [accounts, setAccounts] = useState<Account[]>([])
  const [error, setError] = useState('')
  const [revision, setRevision] = useState(0)
  useEffect(() => {
    let active = true
    async function load() {
      try {
        const current = await api<User>('/api/access/me')
        const linked = current.permissions.includes('accounts.read') ? await api<Account[]>('/api/accounts') : []
        if (active) { setUser(current); setAccounts(linked); setError('') }
      } catch (error) { if (active) { setError(message(error)); setUser(null); setAccounts([]) } }
    }
    void load()
    return () => { active = false }
  }, [revision])
  return (
    <Paper sx={{ p: 3, mt: 3 }}>
      <Typography variant="h6" gutterBottom>{t('accountAccess')}</Typography>
      <Button onClick={() => setRevision((r) => r + 1)} sx={{ mb: 2 }}>{t('refreshAccess')}</Button>
      {error && <Alert severity="warning">{t(error)}</Alert>}
      {user && <>
        <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
          {user.roles.length ? user.roles.map((role) => <Chip key={role} label={t(roleKeys[role] || role, { defaultValue: role })} />) : <Typography>{t('noRoles')}</Typography>}
        </Stack>
        {accounts.map((account) => <Typography key={account.id}>{account.name}</Typography>)}
        {user.permissions.includes('accounts.read') && accounts.length === 0 && <Typography>{t('noAccounts')}</Typography>}
        {user.permissions.includes('admin.manage') && <AdminPanel key={revision} actorID={user.id} />}
      </>}
    </Paper>
  )
}

function AdminPanel({ actorID }: { actorID: string }) {
  const { t, i18n } = useTranslation(['admin', 'common'])
  const language = i18n.resolvedLanguage || 'en'
  const [users, setUsers] = useState<User[]>([])
  const [roles, setRoles] = useState<Role[]>([])
  const [accounts, setAccounts] = useState<Account[]>([])
  const [audit, setAudit] = useState<Audit[]>([])
  const [userPage, setUserPage] = useState(0)
  const [accountPage, setAccountPage] = useState(0)
  const [auditPage, setAuditPage] = useState(0)
  const [selectedID, setSelectedID] = useState('')
  const [linkID, setLinkID] = useState('')
  const [accountID, setAccountID] = useState('')
  const [accountName, setAccountName] = useState('')
  const [accountActive, setAccountActive] = useState(true)
  const [revision, setRevision] = useState(0)
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState('')
  const selected = users.find((user) => user.id === selectedID)

  useEffect(() => {
    let active = true
    Promise.all([
      api<User[]>(`/api/admin/users?offset=${userPage * 100}`),
      api<Role[]>('/api/admin/roles'),
      api<Account[]>(`/api/admin/accounts?offset=${accountPage * 100}`),
      api<Audit[]>(`/api/admin/audit?offset=${auditPage * 100}`),
    ]).then(([users, roles, accounts, audit]) => {
      if (active) { setUsers(users); setRoles(roles); setAccounts(accounts); setAudit(audit); setError('') }
    }).catch((error) => {
      if (active) { setError(message(error)); setUsers([]); setRoles([]); setAccounts([]); setAudit([]) }
    }).finally(() => { if (active) setBusy(false) })
    return () => { active = false }
  }, [revision, userPage, accountPage, auditPage])

  async function mutate(path: string, method: string, body: unknown) {
    setBusy(true); setError('')
    try { await api(path, method, body); setRevision((r) => r + 1) }
    catch (error) { setError(message(error)); setBusy(false) }
  }
  const pager = (page: number, count: number, change: (page: number) => void) => (
    <Stack direction="row" spacing={1} sx={{ my: 1 }}>
      <Button disabled={busy || page === 0} onClick={() => { setBusy(true); change(page - 1) }}>{t('common:previousPage')}</Button>
      <Typography sx={{ alignSelf: 'center' }}>{t('common:page', { page: formatNumber(page + 1, language) })}</Typography>
      <Button disabled={busy || count < 100} onClick={() => { setBusy(true); change(page + 1) }}>{t('common:nextPage')}</Button>
    </Stack>
  )
  return (
    <Box sx={{ mt: 3 }}>
      <Typography variant="h5" gutterBottom>{t('title')}</Typography>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{t(error)}</Alert>}
      <Button disabled={busy} onClick={() => { setBusy(true); setRevision((r) => r + 1) }}>{t('refresh')}</Button>
      <Typography variant="h6" sx={{ mt: 2 }}>{t('usersRoles')}</Typography>
      <Typography variant="body2" sx={{ mb: 2 }}>{t('usersHelp')}</Typography>
      <TextField select fullWidth label={t('user')} value={selected ? selectedID : ''} disabled={busy} onChange={(e) => setSelectedID(e.target.value)}>
        {users.map((user) => <MenuItem key={user.id} value={user.id}>{user.display_name || user.subject} — {user.email || user.subject}{user.active ? '' : ` ${t('common:inactive')}`}</MenuItem>)}
      </TextField>
      {pager(userPage, users.length, (page) => { setSelectedID(''); setUserPage(page) })}
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
      </Box>}

      <Typography variant="h6" sx={{ mt: 3 }}>{t('accounts')}</Typography>
      <TextField select fullWidth label={t('accountToEdit')} value={accounts.some((account) => account.id === accountID) ? accountID : ''} disabled={busy} onChange={(e) => {
        const account = accounts.find((account) => account.id === e.target.value)
        setAccountID(account?.id || ''); setAccountName(account?.name || ''); setAccountActive(account?.active ?? true)
      }}>
        <MenuItem value="">{t('newAccount')}</MenuItem>
        {accounts.map((account) => <MenuItem key={account.id} value={account.id}>{account.name}{account.active ? '' : ` ${t('common:inactive')}`}</MenuItem>)}
      </TextField>
      {pager(accountPage, accounts.length, (page) => { setAccountID(''); setAccountName(''); setAccountActive(true); setLinkID(''); setAccountPage(page) })}
      <TextField fullWidth label={t('accountName')} value={accountName} disabled={busy} onChange={(e) => setAccountName(e.target.value)} sx={{ mt: 1 }} />
      <FormControlLabel label={t('activeAccount')} control={<Checkbox checked={accountActive} disabled={busy} onChange={(_, checked) => setAccountActive(checked)} />} />
      <Box><Button variant="contained" disabled={busy || !accountName.trim()} onClick={() => void mutate(accountID ? `/api/admin/accounts/${accountID}` : '/api/admin/accounts', accountID ? 'PUT' : 'POST', { name: accountName.trim(), active: accountActive })}>{t(accountID ? 'saveAccount' : 'createAccount')}</Button></Box>
      <Typography variant="h6" sx={{ mt: 3 }}>{t('permissionCatalog')}</Typography>
      {roles.map((role) => <Typography key={role.name}>{t(roleKeys[role.name] || role.name, { defaultValue: role.name })}: {new Intl.ListFormat(language).format(role.permissions.map((permission) => t(permissionKeys[permission] || permission, { defaultValue: permission })))}</Typography>)}
      <Typography variant="h6" sx={{ mt: 3 }}>{t('auditHistory')}</Typography>
      {audit.map((event) => <Box key={event.id} sx={{ py: 1, borderBottom: 1, borderColor: 'divider', overflowWrap: 'anywhere' }}>
        <Typography>{formatDate(event.created_at, language)} — {t(actionKeys[event.action] || event.action, { defaultValue: event.action })}</Typography>
        <Typography variant="body2">{t('actorTarget', { actor: event.actor_id, target: event.target_id })}</Typography>
        <Typography variant="caption">{t('rawDetails')}</Typography>
        <Typography variant="body2" component="pre" dir="ltr" sx={{ whiteSpace: 'pre-wrap', m: 0 }}>{JSON.stringify(event.details)}</Typography>
      </Box>)}
      {pager(auditPage, audit.length, setAuditPage)}
    </Box>
  )
}
