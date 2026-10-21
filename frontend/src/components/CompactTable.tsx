import type { ReactNode } from 'react'
import { Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material'
import { typographyRoles } from '../design/theme'

export default function CompactTable({ label, headers, children, empty, emptyMessage, minWidth = 480, stickyActions = false }: {
  label: string; headers: string[]; children: ReactNode; empty: boolean; emptyMessage: string; minWidth?: number; stickyActions?: boolean
}) {
  return <TableContainer role="region" aria-label={label} tabIndex={0}
    sx={{ maxWidth: '100%', overflowX: 'auto', '&:focus-visible': { outline: '2px solid', outlineColor: 'primary.main', outlineOffset: -2 } }}>
    <Table size="small" aria-label={label} sx={{ minWidth, '& td, & th': { overflowWrap: 'anywhere' },
      ...(stickyActions ? { '& tr > :last-child': { position: 'sticky', insetInlineEnd: 0, bgcolor: 'background.paper', zIndex: 1 }, '& thead tr > :last-child': { zIndex: 2 } } : {}),
      '& .MuiTableBody-root > .MuiTableRow-root:hover:not(.Mui-selected)': { bgcolor: 'action.hover' } }}>
      <TableHead sx={{ bgcolor: 'action.hover' }}>
        <TableRow>{headers.map((header) => <TableCell key={header} scope="col" sx={{ typography: typographyRoles.tableHeader }}>{header}</TableCell>)}</TableRow>
      </TableHead>
      <TableBody>
        {children}
        {empty && <TableRow><TableCell colSpan={headers.length} sx={{ py: 3 }}>
          <Typography variant={typographyRoles.supportingText} color="text.secondary">{emptyMessage}</Typography>
        </TableCell></TableRow>}
      </TableBody>
    </Table>
  </TableContainer>
}
