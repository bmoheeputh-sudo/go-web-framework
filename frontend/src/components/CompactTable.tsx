import type { ReactNode } from 'react'
import { Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material'

export default function CompactTable({ label, headers, children, empty, emptyMessage, minWidth = 480 }: {
  label: string; headers: string[]; children: ReactNode; empty: boolean; emptyMessage: string; minWidth?: number
}) {
  return <TableContainer role="region" aria-label={label} tabIndex={0}
    sx={{ maxWidth: '100%', overflowX: 'auto', '&:focus-visible': { outline: '2px solid', outlineColor: 'primary.main', outlineOffset: -2 } }}>
    <Table size="small" aria-label={label} sx={{ minWidth, '& td, & th': { overflowWrap: 'anywhere' } }}>
      <TableHead sx={{ bgcolor: 'action.hover' }}>
        <TableRow>{headers.map((header) => <TableCell key={header} scope="col" sx={{ fontWeight: 600 }}>{header}</TableCell>)}</TableRow>
      </TableHead>
      <TableBody>
        {children}
        {empty && <TableRow><TableCell colSpan={headers.length} sx={{ py: 3 }}>
          <Typography variant="body2" color="text.secondary">{emptyMessage}</Typography>
        </TableCell></TableRow>}
      </TableBody>
    </Table>
  </TableContainer>
}
