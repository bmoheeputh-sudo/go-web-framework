import { useEffect, useState } from 'react'
import {
  AppBar,
  Toolbar,
  Typography,
  Container,
  Paper,
  Box,
  Chip,
  CircularProgress,
} from '@mui/material'

function App() {
  const [status, setStatus] = useState('Checking...')

  useEffect(() => {
    fetch('/api/health')
      .then((response) => {
        if (!response.ok) throw new Error('API unavailable')
        return response.json()
      })
      .then((data) => setStatus(data.status === 'ok' ? 'Connected' : 'Error'))
      .catch(() => setStatus('Disconnected'))
  }, [])

  return (
    <>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6">Go Web Framework</Typography>
        </Toolbar>
      </AppBar>

      <Container maxWidth="lg" sx={{ mt: 4 }}>
        <Typography variant="h4" gutterBottom>
          Dashboard
        </Typography>

        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            Backend Status
          </Typography>

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            {status === 'Checking...' ? (
              <CircularProgress size={24} />
            ) : (
              <Chip
                label={status}
                color={status === 'Connected' ? 'success' : 'error'}
              />
            )}
          </Box>
        </Paper>
      </Container>
    </>
  )
}

export default App
