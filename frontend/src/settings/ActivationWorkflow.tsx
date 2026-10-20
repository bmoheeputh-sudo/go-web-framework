import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Accordion, AccordionDetails, AccordionSummary, Alert, Button, CircularProgress, LinearProgress, Stack, Typography,
} from '@mui/material'
import ExpandMore from '@mui/icons-material/ExpandMore'
import { useTranslation } from 'react-i18next'
import type { User } from '../api/client'
import { APIError } from '../api/client'
import {
  activateOIDC, approveAuthRevision, AuthConfigurationError, cancelActivationPreparation, cancelCurrentActivationPreparation,
  findEnrolledOIDCAdministrator, getActivationPreparation,
  getActivationStatus, getRecoveryReadiness, prepareActivation, reconcileActivation, startNormalReadiness, validateAuthRevision,
} from '../api/authConfiguration'
import type {
  ActivationPreparation, ActivationResult, ActivationStatus, AuthRevision, ConnectionTest, RecoveryReadiness,
} from '../api/authConfiguration'
import { useSession } from '../auth/session'
import { useAuthenticationCacheSync } from '../api/authCache'
import { formatDate, formatNumber } from '../i18n'
import { useNotifications } from '../notifications/notifications'
import ActivationConfirmationStep from './ActivationConfirmationStep'
import { emptyActivationConfirmation, validActivationConfirmation } from './activationConfirmation'
import type { ActivationConfirmation } from './activationConfirmation'
import ActivationOutcomePanel from './ActivationOutcomePanel'
import type { DisplayedOutcome } from './ActivationOutcomePanel'
import ActivationWizardDialog from './ActivationWizardDialog'
import SectionCard from '../components/common/SectionCard'
import StatusBadge from '../components/common/StatusBadge'
import TwoColumnKeyValue from '../components/common/TwoColumnKeyValue'
import OIDCConnectionTest from './OIDCConnectionTest'
import type { OIDCConnectionTestHandle } from './OIDCConnectionTest'

type WorkflowState =
  | { kind: 'idle' }
  | { kind: 'preparing' }
  | { kind: 'prepared'; preparation: ActivationPreparation }
  | { kind: 'readiness_pending'; preparation: ActivationPreparation }
  | { kind: 'ready_to_confirm'; preparation: ActivationPreparation }
  | { kind: 'activating'; preparation: ActivationPreparation }
  | { kind: 'outcome'; result: DisplayedOutcome }
  | { kind: 'expired'; preparation: ActivationPreparation }
  | { kind: 'blocked'; reason: 'affinity' | 'wrong_instance' | 'provider_unavailable' | 'popup_closed' | 'readiness_failed' | 'preparation_conflict'; preparation?: ActivationPreparation }

type ReadinessRun = {
  popup: Window
  controller: AbortController
  stopped: boolean
  attempts: number
  timer?: ReturnType<typeof setTimeout>
}

const preparationOf = (state: WorkflowState) => 'preparation' in state ? state.preparation : undefined
const evidenceFresh = (test: ConnectionTest | null, at = Date.now()) => Boolean(test?.status === 'succeeded' && test.evidence_id && test.evidence_expires_at && Date.parse(test.evidence_expires_at) > at)
const validPreparation = (preparation: ActivationPreparation) => Date.parse(preparation.expires_at) > Date.now()

function stopReadiness(run: ReadinessRun) {
  run.stopped = true
  clearTimeout(run.timer)
  run.controller.abort()
  try { run.popup.close() } catch { /* COOP may sever the window reference. */ }
}

export default function ActivationWorkflow({ revision: selectedRevision, isolatedTest, enrolledUser, disabled, onIsolatedTestResult, onResolvedUser, onRevisionChange, onOutcomeChange, open, onClose }: {
  revision: AuthRevision | null
  isolatedTest: ConnectionTest | null
  enrolledUser: User | null
  disabled: boolean
  onIsolatedTestResult: (result: ConnectionTest | null) => void
  onResolvedUser: (user: User | null) => void
  onRevisionChange?: (revision: AuthRevision) => void
  onOutcomeChange?: (outcome: DisplayedOutcome | null) => void
  open?: boolean
  onClose?: () => void
}) {
  const { t, i18n } = useTranslation(['auth', 'common'])
  const notify = useNotifications()
  const { refreshViews, refreshAfterChange } = useAuthenticationCacheSync()
  const { expire } = useSession()
  const [status, setStatus] = useState<ActivationStatus | null>(null)
  const [progressedRevision, setProgressedRevision] = useState<AuthRevision | null>(null)
  const [statusError, setStatusError] = useState(false)
  const [state, setState] = useState<WorkflowState>({ kind: 'idle' })
  const [confirming, setConfirming] = useState(false)
  const [confirmation, setConfirmation] = useState<ActivationConfirmation>(emptyActivationConfirmation)
  const [recovery, setRecovery] = useState<RecoveryReadiness | null>(null)
  const [recoveryError, setRecoveryError] = useState(false)
  const [recoveryNotApplicable, setRecoveryNotApplicable] = useState(false)
  const [now, setNow] = useState(Date.now())
  const [canceling, setCanceling] = useState(false)
  const [isolatedBusy, setIsolatedBusy] = useState(false)
  const requestSequence = useRef(0)
  const submitting = useRef(false)
  const cancelingRef = useRef(false)
  const testRef = useRef<OIDCConnectionTestHandle>(null)
  const guidedPopup = useRef<Window | null>(null)
  const guidedStart = useRef(false)
  const guidedTestLaunched = useRef(false)
  const readiness = useRef<ReadinessRun | null>(null)
  const polling = useRef<{ controller: AbortController; timer?: ReturnType<typeof setTimeout>; attempts: number } | null>(null)
  const preparation = preparationOf(state)
  const revision = progressedRevision && selectedRevision && progressedRevision.id === selectedRevision.id && progressedRevision.generation >= selectedRevision.generation
    ? progressedRevision : selectedRevision
  const language = i18n.resolvedLanguage || 'en'

  const loadStatus = useCallback(async (signal?: AbortSignal) => {
    const sequence = ++requestSequence.current
    try {
      const value = await getActivationStatus(signal)
      if (sequence !== requestSequence.current || signal?.aborted) return null
      setStatus(value); setStatusError(false)
      return value
    } catch (error) {
      if (signal?.aborted || sequence !== requestSequence.current) return null
      if (error instanceof APIError && error.status === 401) expire()
      setStatusError(true)
      return null
    }
  }, [expire])

  useEffect(() => {
    const controller = new AbortController()
    const timer = setTimeout(() => void loadStatus(controller.signal), 0)
    return () => { clearTimeout(timer); controller.abort() }
  }, [loadStatus])

  useEffect(() => {
    const deadline = Math.min(...[
      preparation?.expires_at, isolatedTest?.evidence_expires_at, preparation?.normal_evidence_expires_at,
    ].filter(Boolean).map((value) => Date.parse(value!)))
    if (!Number.isFinite(deadline)) return
    const update = () => {
      const current = Date.now()
      setNow(current)
      if (preparation && Date.parse(preparation.expires_at) <= current && state.kind !== 'expired') {
        setState({ kind: 'expired', preparation })
        setConfirming(false)
      }
    }
    const timer = setInterval(update, 1000)
    return () => clearInterval(timer)
  }, [preparation, state.kind, isolatedTest?.evidence_expires_at])

  useEffect(() => {
    if (!isolatedTest?.tested_identity || isolatedTest.status !== 'succeeded' || isolatedTest.revision_id !== revision?.id || isolatedTest.generation !== revision?.generation || enrolledUser && enrolledUser.issuer === isolatedTest.tested_identity.issuer && enrolledUser.subject === isolatedTest.tested_identity.subject) return
    const controller = new AbortController()
    void findEnrolledOIDCAdministrator(isolatedTest.tested_identity.issuer, isolatedTest.tested_identity.subject, controller.signal)
      .then((user) => { if (!controller.signal.aborted) onResolvedUser(user) })
      .catch((error) => { if (error instanceof APIError && error.status === 401) expire() })
    return () => controller.abort()
  }, [isolatedTest, enrolledUser, onResolvedUser, expire, revision])

  useEffect(() => () => {
    if (readiness.current && !readiness.current.stopped) stopReadiness(readiness.current)
    try { guidedPopup.current?.close() } catch { /* COOP may sever the window reference. */ }
    if (polling.current) { polling.current.controller.abort(); clearTimeout(polling.current.timer) }
  }, [])

  useEffect(() => {
    if (state.kind !== 'outcome' || state.result.outcome !== 'committed_not_applied') return
    const run = { controller: new AbortController(), attempts: 0 } as { controller: AbortController; timer?: ReturnType<typeof setTimeout>; attempts: number }
    polling.current = run
    const poll = async () => {
      if (run.controller.signal.aborted || run.attempts >= 10) return
      run.attempts++
      const value = await loadStatus(run.controller.signal)
      if (value?.reconciled || run.controller.signal.aborted) return
      run.timer = setTimeout(() => void poll(), 3000)
    }
    run.timer = setTimeout(() => void poll(), 3000)
    return () => { run.controller.abort(); clearTimeout(run.timer); if (polling.current === run) polling.current = null }
  }, [state, loadStatus])

  const isolatedEligible = useMemo(() => Boolean(revision && isolatedTest?.revision_id === revision.id && isolatedTest.generation === revision.generation && isolatedTest.tested_identity && evidenceFresh(isolatedTest, now)), [revision, isolatedTest, now])
  const enrolledEligible = Boolean(isolatedTest?.tested_identity && enrolledUser?.active && enrolledUser.permissions.includes('admin.manage') && enrolledUser.issuer === isolatedTest.tested_identity.issuer && enrolledUser.subject === isolatedTest.tested_identity.subject)
  const normalEligible = Boolean(preparation?.normal_callback_status === 'succeeded' && preparation.normal_evidence_id && preparation.normal_evidence_expires_at && Date.parse(preparation.normal_evidence_expires_at) > now)
  const ready = Boolean(preparation && validPreparation(preparation) && isolatedEligible && enrolledEligible && normalEligible && preparation.revision_id === revision?.id && preparation.revision_generation === revision.generation)

  function startGuidedTest() {
    if (!revision || revision.provider !== 'oidc' || !['draft', 'validated', 'approved'].includes(revision.status) ||
      disabled || guidedStart.current || submitting.current || state.kind === 'preparing' || state.kind === 'readiness_pending' || state.kind === 'activating' || state.kind === 'outcome') return
    // Open synchronously from the user gesture. The same popup is used for both
    // verified OIDC handshakes after the existing lifecycle transitions commit.
    const popup = window.open('about:blank', '_blank', 'popup,width=520,height=720')
    if (!popup) { notify({ severity: 'warning', messageKey: 'auth:testPopupBlocked' }); return }
    popup.opener = null
    guidedStart.current = true
    guidedTestLaunched.current = false
    guidedPopup.current = popup
    setConfirming(false)
    setState({ kind: 'preparing' })
    onIsolatedTestResult(null)
    onResolvedUser(null)
    void (async () => {
      let handedOff = false
      try {
        if (preparation) {
          try { await cancelActivationPreparation(preparation.preparation_id) }
          catch (error) {
            if (error instanceof AuthConfigurationError && error.code === 'activation_preparation_wrong_instance') throw error
            if (!(error instanceof AuthConfigurationError && error.status === 404)) throw error
            if (validPreparation(preparation)) {
              const unknown: DisplayedOutcome = { outcome: 'outcome_unknown', desired_generation: preparation.target_activation_generation, revision_id: preparation.revision_id }
              setState({ kind: 'outcome', result: unknown }); onOutcomeChange?.(unknown)
              return
            }
          }
        }
        let next = revision
        if (next.status === 'draft') {
          next = await validateAuthRevision(next.id, next.generation)
          if (next.status !== 'validated') throw new Error('unexpected validation result')
          setProgressedRevision(next); onRevisionChange?.(next)
        }
        if (next.status === 'validated') {
          next = await approveAuthRevision(next.id, next.generation)
          if (next.status !== 'approved') throw new Error('unexpected approval result')
          setProgressedRevision(next); onRevisionChange?.(next)
        }
        if (next.status !== 'approved') throw new Error('revision is not approved')
        const authoritative = await getActivationStatus()
        setStatus(authoritative); setStatusError(false)
        if (!authoritative.preparation_enabled) {
          setState({ kind: 'blocked', reason: 'affinity' }); return
        }
        const value = await prepareActivation(next.id, next.generation, authoritative.authoritative_generation)
        if (value.revision_id !== next.id || value.revision_generation !== next.generation) {
          await cancelActivationPreparation(value.preparation_id)
          throw new Error('preparation revision mismatch')
        }
        handedOff = true
        setState({ kind: 'prepared', preparation: value })
      } catch (error) {
        if (error instanceof AuthConfigurationError && error.code === 'activation_preparation_wrong_instance') setState({ kind: 'blocked', reason: 'wrong_instance' })
        else if (error instanceof AuthConfigurationError && error.code === 'recovery_provider_unavailable') setState({ kind: 'blocked', reason: 'provider_unavailable' })
        else if (error instanceof AuthConfigurationError && error.code === 'activation_affinity_required') setState({ kind: 'blocked', reason: 'affinity' })
        else if (error instanceof AuthConfigurationError && error.code === 'activation_preparation_conflict') setState({ kind: 'blocked', reason: 'preparation_conflict' })
        else if (error instanceof AuthConfigurationError && error.status === 409) {
          setState({ kind: 'idle' }); notify({ severity: 'warning', messageKey: 'auth:revisionConflict' }); void loadStatus()
        }
        else {
          if (error instanceof APIError && error.status === 401) expire()
          setState({ kind: 'idle' }); notify({ severity: 'error', messageKey: 'auth:settingsUnavailable' })
        }
      } finally {
        guidedStart.current = false
        if (guidedPopup.current === popup && !handedOff) { try { popup.close() } catch { /* COOP may sever the window reference. */ }; guidedPopup.current = null }
      }
    })()
  }

  useEffect(() => {
    if (state.kind !== 'prepared' || !guidedPopup.current || guidedTestLaunched.current || !revision || revision.status !== 'approved') return
    guidedTestLaunched.current = true
    testRef.current?.start(guidedPopup.current)
  }, [state, revision])

  async function pollReadiness(run: ReadinessRun, preparationID: string) {
    if (run.stopped) return
    if (run.attempts >= 150) {
      stopReadiness(run)
      if (preparation) setState({ kind: 'expired', preparation })
      return
    }
    run.attempts++
    try {
      const value = await getActivationPreparation(preparationID, run.controller.signal)
      if (run.stopped) return
      if (value.normal_callback_status === 'succeeded' && value.normal_evidence_id) {
        stopReadiness(run); setState({ kind: 'ready_to_confirm', preparation: value }); return
      }
      if (value.normal_callback_status === 'failed' || value.normal_callback_status === 'expired' || !validPreparation(value)) {
        stopReadiness(run); setState(value.normal_callback_status === 'expired' || !validPreparation(value) ? { kind: 'expired', preparation: value } : { kind: 'blocked', reason: 'readiness_failed', preparation: value }); return
      }
      run.timer = setTimeout(() => void pollReadiness(run, preparationID), 2000)
    } catch (error) {
      if (run.stopped) return
      stopReadiness(run)
      if (error instanceof AuthConfigurationError && error.code === 'activation_preparation_wrong_instance') setState({ kind: 'blocked', reason: 'wrong_instance', preparation })
      else setState({ kind: 'blocked', reason: 'readiness_failed', preparation })
    }
  }

  async function beginReadiness(existingPopup?: Window) {
    if (!preparation || state.kind !== 'prepared') {
      try { existingPopup?.close() } catch { /* COOP may sever the window reference. */ }
      return
    }
    const popup = existingPopup ?? window.open('about:blank', '_blank', 'popup,width=520,height=720')
    if (!popup) { notify({ severity: 'warning', messageKey: 'auth:testPopupBlocked' }); return }
    popup.opener = null
    const run: ReadinessRun = { popup, controller: new AbortController(), stopped: false, attempts: 0 }
    readiness.current = run; setState({ kind: 'readiness_pending', preparation })
    try {
      const started = await startNormalReadiness(preparation.preparation_id, run.controller.signal)
      if (run.stopped) return
      const location = new URL(started.authorization_url)
      const issuer = new URL(revision!.issuer_url)
      if (location.protocol !== 'https:' || location.origin !== issuer.origin || location.username || location.password) throw new Error('unsafe authorization URL')
      popup.location.replace(location.href)
      run.timer = setTimeout(() => void pollReadiness(run, preparation.preparation_id), 1000)
    } catch (error) {
      if (!run.stopped) stopReadiness(run)
      if (error instanceof AuthConfigurationError && error.code === 'activation_preparation_wrong_instance') setState({ kind: 'blocked', reason: 'wrong_instance', preparation })
      else setState({ kind: 'blocked', reason: 'readiness_failed', preparation })
    }
  }

  async function openConfirmation() {
    if (!preparation || !ready) return
    try {
      const current = await getActivationPreparation(preparation.preparation_id)
      if (!validPreparation(current)) { setState({ kind: 'expired', preparation: current }); return }
      if (current.normal_callback_status !== 'succeeded' || !current.normal_evidence_id) { setState({ kind: 'blocked', reason: 'readiness_failed', preparation: current }); return }
      setState({ kind: 'ready_to_confirm', preparation: current })
      setConfirmation(emptyActivationConfirmation)
      setConfirming(true)
    } catch (error) {
      if (error instanceof AuthConfigurationError && error.code === 'activation_preparation_wrong_instance') setState({ kind: 'blocked', reason: 'wrong_instance', preparation })
      else setState({ kind: 'expired', preparation })
    }
  }

  async function activate(confirmation: ActivationConfirmation) {
    if (submitting.current || !revision || !preparation || !isolatedTest?.evidence_id || !preparation.normal_evidence_id || !enrolledUser || !ready) return
    submitting.current = true; setConfirming(false); setState({ kind: 'activating', preparation })
    try {
      const result = await activateOIDC(preparation.preparation_id, {
        revision_id: revision.id,
        expected_revision_generation: revision.generation,
        expected_activation_generation: preparation.expected_activation_generation,
        isolated_evidence_id: isolatedTest.evidence_id,
        normal_evidence_id: preparation.normal_evidence_id,
        enrolled_user_id: enrolledUser.id,
        transition_seconds: confirmation.transitionSeconds,
        acknowledge_reauthentication: confirmation.acknowledgeReauthentication,
        acknowledge_emergency_recovery: confirmation.acknowledgeEmergencyRecovery,
        confirm: true,
        reason: confirmation.reason,
      })
      setState({ kind: 'outcome', result })
      onOutcomeChange?.(result)
      if (result.outcome === 'committed_applied' || result.outcome === 'committed_not_applied') refreshAfterChange()
      if (result.outcome !== 'commit_uncertain') void loadStatus()
    } catch (error) {
      if (error instanceof AuthConfigurationError && error.activation) {
        setState({ kind: 'outcome', result: error.activation })
        onOutcomeChange?.(error.activation)
        if (error.activation.outcome === 'committed_applied' || error.activation.outcome === 'committed_not_applied') refreshAfterChange()
      }
      else {
        const unknown: DisplayedOutcome = { outcome: 'outcome_unknown', desired_generation: preparation.target_activation_generation, revision_id: revision.id }
        setState({ kind: 'outcome', result: unknown })
        onOutcomeChange?.(unknown)
        if (error instanceof APIError && (error.status === 401 || error.status === 403)) expire()
      }
    } finally { submitting.current = false }
  }

  async function inspect() {
    const value = await loadStatus()
    if (!value || state.kind !== 'outcome') return
    // An ambiguous HTTP response does not invalidate cached configuration.
    // Refresh it only after this explicit authoritative read succeeds.
    refreshViews()
    const result = state.result
    if (result.outcome === 'outcome_unknown' || result.outcome === 'commit_uncertain') {
      if (value.authoritative_generation === result.desired_generation && value.authoritative_revision_id === result.revision_id) {
        const known: ActivationResult = {
          outcome: value.reconciled ? 'committed_applied' : 'committed_not_applied', commit_persisted: true,
          authoritative_state_known: true, authoritative_generation: value.authoritative_generation,
          authoritative_revision_id: value.authoritative_revision_id, desired_generation: result.desired_generation,
          applied_generation: value.local_applied_generation, revision_id: result.revision_id, applied: value.reconciled,
          commit_uncertain: false, reconciliation_required: !value.reconciled, automatic_retry_allowed: false,
        }
        setState({ kind: 'outcome', result: known })
        onOutcomeChange?.(known)
      }
    }
  }

  async function reconcile() {
    if (!status || !status.reconciliation_required) return
    try {
      const value = await reconcileActivation(status.authoritative_generation)
      setStatus(value)
      refreshAfterChange()
    } catch (error) {
      if (error instanceof APIError && error.status === 401) expire()
      setStatusError(true)
    }
  }

  async function checkRecovery() {
    if (!revision) return
    setRecoveryError(false)
    setRecoveryNotApplicable(false)
    try { setRecovery(await getRecoveryReadiness(revision.id)) }
    catch (error) {
      setRecovery(null)
      if (error instanceof AuthConfigurationError && error.status === 404) setRecoveryNotApplicable(true)
      else setRecoveryError(true)
      if (error instanceof APIError && error.status === 401) expire()
    }
  }

  async function abandon(close = false) {
    if (submitting.current || cancelingRef.current || state.kind === 'outcome') return
    try { guidedPopup.current?.close() } catch { /* COOP may sever the window reference. */ }
    guidedPopup.current = null; guidedTestLaunched.current = false
    const current = preparationOf(state)
    if (!current && state.kind !== 'blocked') {
      setState({ kind: 'idle' }); setConfirming(false); if (close) onClose?.()
      return
    }
    if (readiness.current && !readiness.current.stopped) stopReadiness(readiness.current)
    cancelingRef.current = true; setCanceling(true)
    try {
      if (current) await cancelActivationPreparation(current.preparation_id)
      else if (state.kind === 'blocked' && state.reason === 'preparation_conflict') await cancelCurrentActivationPreparation()
      else { setState({ kind: 'idle' }); if (close) onClose?.(); return }
      setState({ kind: 'idle' }); setConfirming(false); if (close) onClose?.()
    } catch (error) {
      if (error instanceof AuthConfigurationError && error.code === 'activation_preparation_wrong_instance') {
        setState({ kind: 'blocked', reason: 'wrong_instance', preparation: current })
      } else if (error instanceof AuthConfigurationError && error.status === 404) {
        // The server uses 404 for expired, missing, and already claimed items.
        // Only a locally expired known preparation is safe to forget. A fresh
        // 404 may represent a claimed activation with an unknown commit result.
        if (current && !validPreparation(current)) {
          setState({ kind: 'idle' }); setConfirming(false); if (close) onClose?.()
        } else if (current) {
          const unknown: DisplayedOutcome = { outcome: 'outcome_unknown', desired_generation: current.target_activation_generation, revision_id: current.revision_id }
          setState({ kind: 'outcome', result: unknown }); onOutcomeChange?.(unknown)
        } else notify({ severity: 'warning', messageKey: 'auth:activationCancelFailed' })
      } else {
        if (error instanceof APIError && error.status === 401) expire()
        notify({ severity: 'error', messageKey: 'auth:activationCancelFailed' })
      }
    } finally { cancelingRef.current = false; setCanceling(false) }
  }

  const countdown = preparation ? Math.max(0, Math.ceil((Date.parse(preparation.expires_at) - now) / 1000)) : 0
  const outcome = state.kind === 'outcome' ? state.result : null
  const wizardOpen = (open ?? Boolean(revision)) && Boolean(revision) && !outcome
  const wizardBusy = state.kind === 'preparing' || state.kind === 'readiness_pending' || state.kind === 'activating' || canceling || isolatedBusy
  const wizardStep = confirming ? 'confirm' : 'test'
  function closeWizard() {
    if (state.kind === 'preparing' || state.kind === 'activating' || canceling || confirming || outcome) return
    void abandon(true)
  }
  return <Stack spacing={2}>
    <SectionCard title={t('activationStatusTitle')}>
      <Stack spacing={1.5}>
        {statusError && <Alert severity="warning">{t('settingsUnavailable')}</Alert>}
        {!status && !statusError && <LinearProgress aria-label={t('common:loading')} />}
        {status && <>
          <Typography variant="body2" color="text.secondary">{t(status.local_provider === 'oidc' ? 'providerOidc' : 'providerLocal')}</Typography>
          <Stack direction="row" sx={{ gap: 1, flexWrap: 'wrap' }}>
            <StatusBadge tone={status.listener_connected ? 'success' : 'warning'} label={t(status.listener_connected ? 'activationListenerConnected' : 'activationListenerDisconnected')} />
            <StatusBadge tone={status.synchronization_degraded ? 'warning' : 'success'} label={t(status.synchronization_degraded ? 'activationSynchronizationDegraded' : 'activationSynchronizationHealthy')} />
            <StatusBadge tone={status.reconciliation_required ? 'warning' : 'success'} label={t(status.reconciliation_required ? 'activationReconciliationRequired' : 'activationReconciled')} />
          </Stack>
          {status.reconciliation_required && !statusError && !outcome && <Button variant="outlined" sx={{ alignSelf: 'flex-start' }} onClick={() => void reconcile()}>{t('activationReconcile')}</Button>}
          {!status.preparation_enabled && <Alert severity="warning">{t('activationAffinityUnavailable')}</Alert>}
          <Accordion disableGutters variant="outlined" sx={{ '&::before': { display: 'none' } }}>
            <AccordionSummary expandIcon={<ExpandMore />}>{t('advancedTroubleshooting')}</AccordionSummary>
            <AccordionDetails><TwoColumnKeyValue items={[
              { label: t('activationAuthoritativeGeneration'), value: formatNumber(status.authoritative_generation, language) },
              { label: t('activationLocalGeneration'), value: formatNumber(status.local_applied_generation, language) },
              { label: t('activationAffinityMode'), value: status.preparation_affinity_mode === 'single_instance' ? t('affinitySingleInstance') : status.preparation_affinity_mode === 'session_affinity' ? t('affinitySessionAffinity') : t('common:none') },
              { label: t('activationAuthoritativeSource'), value: t(status.authoritative_source === 'database' ? 'sourceDatabase' : 'sourceEnvironment') },
              { label: t('activationAuthoritativeRevision'), value: <bdi>{status.authoritative_revision_id || t('common:none')}</bdi> },
              { label: t('activationLocalState', { source: t(status.local_source === 'database' ? 'sourceDatabase' : 'sourceEnvironment'), generation: formatNumber(status.local_applied_generation, language) }), value: t(status.local_provider === 'oidc' ? 'providerOidc' : 'providerLocal') },
              { label: t('activationLocalRevision'), value: <bdi>{status.local_revision_id || t('common:none')}</bdi> },
              { label: t('activationListenerConnected'), value: t(status.listener_connected ? 'yes' : 'no') },
            ]} /></AccordionDetails>
          </Accordion>
        </>}
      </Stack>
    </SectionCard>

    {revision && !outcome && <ActivationWizardDialog open={wizardOpen} busy={wizardBusy || confirming} step={wizardStep} onClose={closeWizard}
      actions={confirming && preparation ? <>
        <Button disabled={wizardBusy} onClick={() => setConfirming(false)}>{t('common:cancel')}</Button>
        <Button variant="contained" disabled={wizardBusy || !ready || !validActivationConfirmation(confirmation, preparation, false)}
          onClick={() => void activate({ ...confirmation, reason: confirmation.reason.trim(),
            transitionSeconds: preparation.requires_reauthentication ? 0 : confirmation.transitionSeconds,
            acknowledgeReauthentication: preparation.requires_reauthentication && confirmation.acknowledgeReauthentication,
            acknowledgeEmergencyRecovery: preparation.requires_reauthentication && confirmation.acknowledgeEmergencyRecovery,
          })}>{t('activationConfirmAction')}</Button>
      </> : undefined}>
      <Stack spacing={2}>
        {!confirming && <Typography variant="body2" color="text.secondary">{t('revisionLabel', { version: revision.configuration_version })} · {t('providerOidc')}</Typography>}
        {!confirming && (revision.status === 'draft' || revision.status === 'validated') && <Alert severity="info">{t('testWillApprove')}</Alert>}
        {confirming && preparation && isolatedTest?.tested_identity && enrolledUser && <ActivationConfirmationStep
          revision={revision} preparation={preparation} identity={isolatedTest.tested_identity}
          enrolledUserID={enrolledUser.id} expired={!ready} busy={state.kind === 'activating'}
          value={confirmation} onChange={setConfirmation} />}
        {!confirming && <>
        {state.kind !== 'activating' && <Button variant={ready ? 'outlined' : 'contained'} disabled={disabled || wizardBusy || !status?.preparation_enabled || state.kind === 'blocked' && state.reason === 'preparation_conflict'} onClick={startGuidedTest}>{t('testConnection')}</Button>}
        {state.kind === 'preparing' && <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}><CircularProgress size={20} /><Typography role="status">{t('activationPreparing')}</Typography></Stack>}
        {preparation && <>
          <Typography role="status">{t('activationIsolatedEvidence')}: {isolatedEligible ? t('activationEvidenceReady') : t('activationEvidenceMissing')}</Typography>
          {isolatedEligible && <Typography role="status">{t('activationNormalEvidence')}: {normalEligible ? t('activationEvidenceReady') : t('activationEvidenceMissing')}</Typography>}
          {!isolatedEligible && <Alert severity="info">{t(isolatedTest?.evidence_expires_at && Date.parse(isolatedTest.evidence_expires_at) <= now ? 'activationIsolatedExpiredBlocker' : 'activationIsolatedMissingBlocker')}</Alert>}
          {isolatedEligible && !enrolledEligible && <Alert severity="info">{t('activationEnrollmentBlocker')}</Alert>}
          {isolatedEligible && enrolledEligible && !normalEligible && preparation.normal_evidence_expires_at && <Alert severity="warning">{t('activationNormalExpiredBlocker')}</Alert>}
          {state.kind === 'readiness_pending' && <Typography role="status">{t('activationNormalTestPending')}</Typography>}
          {state.kind === 'readiness_pending' && <Button disabled={canceling} onClick={() => void abandon()}>{t('testCancel')}</Button>}
          {ready && (state.kind === 'ready_to_confirm' || state.kind === 'prepared') && <Button variant="contained" disabled={disabled || wizardBusy} onClick={() => void openConfirmation()}>{t('activationReview')}</Button>}
          <Accordion disableGutters variant="outlined" sx={{ '&::before': { display: 'none' } }}>
            <AccordionSummary expandIcon={<ExpandMore />}>{t('technicalDetails')}</AccordionSummary>
            <AccordionDetails><Stack spacing={1}>
              <Typography>{t('activationSelectedRevision')}: <bdi>{revision.id}</bdi></Typography>
              <Typography>{t('activationTargetGeneration')}: {preparation.target_activation_generation}</Typography>
              <Typography>{t('activationCurrentRuntime', { provider: preparation.current_provider, source: preparation.current_source })}</Typography>
              <Typography>{t('activationMaximumTransition', { seconds: preparation.maximum_transition_seconds })}</Typography>
              <Typography role="timer" aria-live="polite">{t('activationExpiresCountdown', { seconds: countdown })}</Typography>
              <Typography>{t('activationPreparationExpiry', { date: formatDate(preparation.expires_at, language) })}</Typography>
              <Typography>{t('activationIsolatedExpiry', { date: isolatedTest?.evidence_expires_at ? formatDate(isolatedTest.evidence_expires_at, language) : t('common:none') })}</Typography>
              <Typography>{t('activationNormalExpiry', { date: preparation.normal_evidence_expires_at ? formatDate(preparation.normal_evidence_expires_at, language) : t('common:none') })}</Typography>
              <Typography>{t('activationEnrolledAdministrator')}: {enrolledEligible ? <bdi>{enrolledUser!.id}</bdi> : t('activationEnrollmentMissing')}</Typography>
            </Stack></AccordionDetails>
          </Accordion>
        </>}
        {revision.status === 'approved' && <OIDCConnectionTest key={revision.id} ref={testRef} revision={revision} disabled={disabled || state.kind !== 'prepared'} externalTrigger inlineEnrollment guided showEnrollment={!enrolledEligible}
          onBusyChange={setIsolatedBusy} onResult={onIsolatedTestResult} onEnrolled={onResolvedUser}
          onVerifiedPopup={(popup, result) => {
            if (!evidenceFresh(result) || result.revision_id !== revision.id || result.generation !== revision.generation) {
              try { popup.close() } catch { /* COOP may sever the window reference. */ }
              if (preparation) setState({ kind: 'blocked', reason: 'readiness_failed', preparation })
              return
            }
            void beginReadiness(popup)
          }} />}
        {state.kind === 'expired' && <Alert severity="error">{t('activationPreparationExpired')}</Alert>}
        {state.kind === 'blocked' && <Alert severity="error">{t(`activationBlocked_${state.reason}`)}</Alert>}
        {state.kind === 'blocked' && !preparation && state.reason !== 'preparation_conflict' && <Button disabled={canceling} onClick={() => void abandon()}>{t('activationStartOver')}</Button>}
        {state.kind === 'activating' && <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}><CircularProgress size={20} /><Typography role="status">{t('activationSubmitting')}</Typography></Stack>}
        <Accordion disableGutters variant="outlined" sx={{ '&::before': { display: 'none' } }}>
          <AccordionSummary expandIcon={<ExpandMore />}>{t('advancedTroubleshooting')}</AccordionSummary>
          <AccordionDetails><Stack spacing={1}>
        {state.kind !== 'activating' && <Button disabled={canceling || wizardBusy} onClick={() => void abandon()}>{t('activationAbandon')}</Button>}
        {state.kind === 'blocked' && state.reason === 'preparation_conflict' && <Button disabled={canceling} onClick={() => void abandon()}>{t('activationDiscardExisting')}</Button>}
        <Button variant="text" onClick={() => void checkRecovery()}>{t('recoveryCheckReadiness')}</Button>
        {recovery && <Alert severity={recovery.ready_for_portal_activation ? 'success' : 'info'}>
          {t('recoveryEvidenceReadiness', {
            configuration: t(recovery.configuration_pre_staged ? 'yes' : 'no'),
            administrator: t(recovery.enrolled_administrator_ready ? 'yes' : 'no'),
            isolated: t(recovery.fresh_isolated_evidence ? 'yes' : 'no'), normal: t(recovery.fresh_normal_callback_evidence ? 'yes' : 'no'),
          })}
          <br />{t('recoveryNotLiveHealth')}
        </Alert>}
        {recoveryError && <Alert severity="info">{t('recoveryReadinessUnavailable')}</Alert>}
        {recoveryNotApplicable && <Typography variant="body2" color="text.secondary">{t('recoveryReadinessNotApplicable')}</Typography>}
          </Stack></AccordionDetails>
        </Accordion>
        </>}
      </Stack>
    </ActivationWizardDialog>}

    {outcome && <ActivationOutcomePanel outcome={outcome} status={statusError ? undefined : status || undefined} busy={false}
      onInspect={() => void inspect()} onReconcile={() => void reconcile()} onReset={() => {
        setState({ kind: 'idle' }); onOutcomeChange?.(null); onClose?.()
      }} />}
  </Stack>
}
