import { useState } from 'react'
import { Box, Button, Checkbox, FormControlLabel, TableCell, TableRow, Chip, TextField } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { useMutation, useQuery } from '../api/queries'
import type { Account } from '../api/client'
import CompactTable from '../components/CompactTable'
import { Pager, PageTools } from '../components/PageTools'
import SectionCard from '../components/common/SectionCard'

export default function AccountsPage() {
  const { t } = useTranslation(['admin', 'common'])
  const [accountPage, setAccountPage] = useState(0)
  const [accountID, setAccountID] = useState('')
  const [accountName, setAccountName] = useState('')
  const [accountActive, setAccountActive] = useState(true)
  const query = useQuery<Account[]>(`/api/admin/accounts?offset=${accountPage * 100}`)
  const accounts = query.data || []
  const { mutate, busy: saving, error, clearError } = useMutation()
  const busy = query.loading || saving
  return <>
    <PageTools busy={busy} error={error || query.error} onRefresh={clearError} />
    <Box sx={{ maxWidth: 880 }}><SectionCard title={t('accounts')} busy={busy}>
      <CompactTable label={t('common:navAccounts')} headers={[t('accountName'), t('common:status')]}
        empty={!query.loading && !query.error && accounts.length === 0} emptyMessage={t('accountsEmpty')} minWidth={360}>
        {accounts.map((account) => <TableRow key={account.id} selected={account.id === accountID} hover>
          <TableCell component="th" scope="row">
            <Button size="small" aria-label={t('editAccount', { name: account.name })} disabled={busy} onClick={() => {
              setAccountID(account.id); setAccountName(account.name); setAccountActive(account.active)
            }} sx={{ textAlign: 'start' }}><bdi>{account.name}</bdi></Button>
          </TableCell>
          <TableCell><Chip size="small" variant="outlined" color={account.active ? 'success' : 'default'} label={t(account.active ? 'common:statusActive' : 'common:statusInactive')} /></TableCell>
        </TableRow>)}
      </CompactTable>
      <Pager label={t('common:navAccounts')} page={accountPage} count={accounts.length} busy={busy} onChange={(page) => { setAccountID(''); setAccountName(''); setAccountActive(true); setAccountPage(page) }} />
      <Button disabled={busy} onClick={() => { setAccountID(''); setAccountName(''); setAccountActive(true) }}>{t('newAccount')}</Button>
      <TextField fullWidth label={t('accountName')} value={accountName} disabled={busy} onChange={(e) => setAccountName(e.target.value)} sx={{ mt: 1 }} />
      <FormControlLabel label={t('activeAccount')} control={<Checkbox checked={accountActive} disabled={busy} onChange={(_, checked) => setAccountActive(checked)} />} />
      <Box><Button variant="contained" disabled={busy || !accountName.trim()} onClick={() => void mutate(accountID ? `/api/admin/accounts/${accountID}` : '/api/admin/accounts', accountID ? 'PUT' : 'POST', { name: accountName.trim(), active: accountActive })}>{t(accountID ? 'saveAccount' : 'createAccount')}</Button></Box>

    </SectionCard></Box>
  </>
}
