import { useState } from 'react'
import { Paper, TableCell, TableRow, Typography } from '@mui/material'
import { useTranslation } from 'react-i18next'
import { useQuery } from '../api/queries'
import type { Audit } from '../api/client'
import { actionKeys, formatDate } from '../i18n'
import { Pager, PageTools } from '../components/PageTools'
import CompactTable from '../components/CompactTable'

export default function AuditLogsPage() {
  const { t, i18n } = useTranslation(['admin', 'common'])
  const [page, setPage] = useState(0)
  const query = useQuery<Audit[]>(`/api/admin/audit?offset=${page * 100}`)
  return <>
    <PageTools busy={query.loading} error={query.error} />
    <Typography variant="h6" component="h2" sx={{ mb: 2 }}>{t('auditHistory')}</Typography>
    <Paper sx={{ overflow: 'hidden' }}>
      <CompactTable label={t('common:navAudit')} headers={[t('auditEvent'), t('auditWho'), t('rawDetails')]}
        empty={!query.loading && !query.error && query.data?.length === 0} emptyMessage={t('auditEmpty')} minWidth={640}>
        {query.data?.map((event) => <TableRow key={event.id}>
          <TableCell component="th" scope="row" sx={{ minWidth: 180 }}>{formatDate(event.created_at, i18n.resolvedLanguage || 'en')} — {t(actionKeys[event.action] || event.action, { defaultValue: event.action })}</TableCell>
          <TableCell sx={{ minWidth: 180 }}>{t('actorTarget', { actor: event.actor_id, target: event.target_id })}</TableCell>
          <TableCell sx={{ minWidth: 200 }}><Typography variant="body2" component="pre" dir="ltr" sx={{ whiteSpace: 'pre-wrap', m: 0, textAlign: 'start' }}>{JSON.stringify(event.details)}</Typography></TableCell>
        </TableRow>)}
      </CompactTable>
    </Paper>
    <Pager label={t('common:navAudit')} page={page} count={query.data?.length || 0} busy={query.loading} onChange={setPage} />
  </>
}
