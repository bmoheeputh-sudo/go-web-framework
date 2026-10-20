import type { ReactNode } from 'react'
import { Button, Dialog, DialogActions, DialogContent, DialogTitle, Step, StepLabel, Stepper } from '@mui/material'
import { useTranslation } from 'react-i18next'

export type ActivationStep = 'prepare' | 'evidence' | 'confirm'

export default function ActivationWizardDialog({ open, busy, step, onClose, actions, children }: {
  open: boolean
  busy: boolean
  step: ActivationStep
  onClose: () => void
  actions?: ReactNode
  children: ReactNode
}) {
  const { t } = useTranslation(['auth', 'common'])
  const steps = [t('activationPrepare'), t('activationEvidenceStatus'), t('activationReview')]
  const activeStep = step === 'prepare' ? 0 : step === 'evidence' ? 1 : 2
  return <Dialog open={open} onClose={busy ? undefined : onClose} fullWidth maxWidth="md" aria-labelledby="activation-wizard-title">
    <DialogTitle id="activation-wizard-title">{t('activationWorkflowTitle')}</DialogTitle>
    <DialogContent dividers>
      <Stepper activeStep={activeStep} alternativeLabel sx={{ mb: 3, '& .MuiStepLabel-label': { overflowWrap: 'anywhere' } }}>
        {steps.map((label) => <Step key={label}><StepLabel>{label}</StepLabel></Step>)}
      </Stepper>
      {children}
    </DialogContent>
    <DialogActions>{actions ?? <Button disabled={busy} onClick={onClose}>{t('common:close')}</Button>}</DialogActions>
  </Dialog>
}
