import { useEffect, useRef, useState } from 'react'
import ContentCopy from '@mui/icons-material/ContentCopy'
import {
  Alert, Box, CircularProgress,
  IconButton, MenuItem, Stack, TextField, Tooltip, Typography,
} from '@mui/material'
import { useTranslation } from 'react-i18next'
import type { OIDCProviderSetupMetadata } from '../api/authConfiguration'
import { useNotifications } from '../notifications/notifications'

type ProviderTemplate = 'okta' | 'auth0' | 'entra' | 'google' | 'generic'

const templates: readonly ProviderTemplate[] = ['okta', 'auth0', 'entra', 'google', 'generic']

function CopyValue({ label, value }: { label: string; value: string }) {
  const { t } = useTranslation('auth')
  const notify = useNotifications()
  async function copy() {
    try {
      if (!navigator.clipboard?.writeText) throw new Error('clipboard unavailable')
      await navigator.clipboard.writeText(value)
      notify({ severity: 'success', messageKey: 'auth:setupCopied', values: { field: label } })
    } catch {
      notify({ severity: 'error', messageKey: 'auth:setupCopyFailed', values: { field: label } })
    }
  }
  return <Box sx={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto', gap: 1, alignItems: 'center' }}>
    <Box sx={{ minWidth: 0 }}>
      <Typography variant="caption" color="text.secondary" component="div">{label}</Typography>
      <Typography component="div" sx={{ overflowWrap: 'anywhere' }}><bdi>{value}</bdi></Typography>
    </Box>
    <Tooltip title={t('copySetupValue', { field: label })}>
      <IconButton onClick={() => void copy()} aria-label={t('copySetupValue', { field: label })} size="small">
        <ContentCopy fontSize="small" />
      </IconButton>
    </Tooltip>
  </Box>
}

export default function OIDCProviderSetup({ metadata, loading, error }: {
  metadata?: OIDCProviderSetupMetadata
  loading: boolean
  error: string
}) {
  const { t } = useTranslation(['auth', 'common'])
  const notify = useNotifications()
  const [template, setTemplate] = useState<ProviderTemplate>('okta')
  const reported = useRef(false)
  useEffect(() => {
    if (error && !reported.current) {
      notify({ severity: 'warning', messageKey: 'auth:setupUnavailable' })
      reported.current = true
    } else if (!error) reported.current = false
  }, [error, notify])

  const labels: Record<ProviderTemplate, string> = {
    okta: t('setupProviderOkta'), auth0: t('setupProviderAuth0'), entra: t('setupProviderEntra'),
    google: t('setupProviderGoogle'), generic: t('setupProviderGeneric'),
  }
  return <Stack component="section" role="region" aria-label={t('setupTitle')} spacing={2.5}>
      <Typography variant="body2" color="text.secondary">{t('setupSummary')}</Typography>
      {loading && <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}><CircularProgress size={20} /><Typography>{t('common:loading')}</Typography></Stack>}
      {error && <Alert severity="warning">{t('setupUnavailable')}</Alert>}
      {metadata && <Stack spacing={3}>
        <Box>
          <Typography component="h3" variant="subtitle1" sx={{ mb: 1, fontWeight: 600 }}>{t('setupStepProvider')}</Typography>
          <TextField select fullWidth label={t('setupProvider')} value={template} onChange={(event) => setTemplate(event.target.value as ProviderTemplate)}>
            {templates.map((item) => <MenuItem key={item} value={item}>{labels[item]}</MenuItem>)}
          </TextField>
          <Alert severity="info" sx={{ mt: 1 }}>{t(`setupProviderHelp_${template}`)}</Alert>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>{t('setupSharedEngine')}</Typography>
        </Box>

        <Box>
          <Typography component="h3" variant="subtitle1" sx={{ mb: 1, fontWeight: 600 }}>{t('setupStepRegister')}</Typography>
          <Stack spacing={1.5}>
            <CopyValue label={t('setupApplicationName')} value={metadata.application_name} />
            <CopyValue label={t('setupApplicationType')} value={t('setupConfidentialWebApplication')} />
            <CopyValue label={t('setupNormalCallback')} value={metadata.normal_callback_url} />
            <CopyValue label={t('setupTestCallback')} value={metadata.test_callback_url} />
            <CopyValue label={t('setupGrant')} value={metadata.grant_types.join(' ')} />
            <CopyValue label={t('setupPKCE')} value={metadata.pkce_methods.join(' ')} />
            <CopyValue label={t('setupScopes')} value={metadata.scopes.join(' ')} />
            <CopyValue label={t('setupClientAuthentication')} value={metadata.client_authentication_methods.join(' ')} />
          </Stack>
          <Alert severity={metadata.development_http ? 'warning' : 'success'} sx={{ mt: 2 }}>
            {t(metadata.development_http ? 'setupDevelopmentHTTP' : 'setupHTTPSCallbacks')}
          </Alert>
          <Typography variant="body2" sx={{ mt: 1 }}>{t('setupClientAuthenticationHelp')}</Typography>
        </Box>

        <Box>
          <Typography component="h3" variant="subtitle1" sx={{ fontWeight: 600 }}>{t('setupStepDraft')}</Typography>
          <Typography>{t('setupDraftHelp')}</Typography>
        </Box>
      </Stack>}
  </Stack>
}
