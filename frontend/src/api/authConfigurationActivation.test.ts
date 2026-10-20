import { afterEach, expect, it, vi } from 'vitest'
import {
  activateOIDC, createRecoveryDraft, getActivationPreparation, getActivationStatus,
  getRecoveryReadiness, prepareActivation, reconcileActivation, startNormalReadiness,
} from './authConfiguration'

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

it('uses the committed activation endpoint contracts and explicit confirmation fields', async () => {
  const fetcher = vi.fn(async () => Response.json({}))
  vi.stubGlobal('fetch', fetcher)
  await prepareActivation('revision/1', 2, 3)
  await startNormalReadiness('instance/preparation')
  await getActivationPreparation('instance/preparation')
  await activateOIDC('instance/preparation', {
    revision_id: 'revision/1', expected_revision_generation: 2, expected_activation_generation: 3,
    isolated_evidence_id: 'isolated', normal_evidence_id: 'normal', enrolled_user_id: 'user', transition_seconds: 0,
    acknowledge_reauthentication: true, acknowledge_emergency_recovery: true, confirm: true, reason: 'Approved cutover',
  })
  await getActivationStatus()
  await reconcileActivation(4)
  await createRecoveryDraft('revision/1', 9, 'Approved recovery')
  await getRecoveryReadiness('revision/1')
  const calls = fetcher.mock.calls as unknown as [string, RequestInit][]
  expect(calls.map(([path]) => path)).toEqual([
    '/api/admin/auth/settings/revision%2F1/activation/prepare',
    '/api/admin/auth/activation-preparations/instance%2Fpreparation/readiness',
    '/api/admin/auth/activation-preparations/instance%2Fpreparation',
    '/api/admin/auth/activation-preparations/instance%2Fpreparation/activate',
    '/api/admin/auth/activation/status', '/api/admin/auth/activation/reconcile',
    '/api/admin/auth/settings/revision%2F1/rollback', '/api/admin/auth/settings/revision%2F1/recovery-readiness',
  ])
  expect(JSON.parse(calls[5][1].body as string)).toEqual({ expected_desired_generation: 4, confirm: true })
})

it('retains a structured non-2xx activation outcome without retaining arbitrary server details', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({
    error: 'auth_activation_runtime_mismatch', outcome: 'committed_not_applied', commit_persisted: true,
    authoritative_state_known: true, authoritative_generation: 4, authoritative_revision_id: 'revision-1',
    desired_generation: 4, applied_generation: 3, revision_id: 'revision-1', applied: false,
    commit_uncertain: false, reconciliation_required: true, automatic_retry_allowed: false,
    provider_secret: 'must-not-be-kept',
  }, { status: 503 })))
  const request = activateOIDC('preparation', {
    revision_id: 'revision-1', expected_revision_generation: 2, expected_activation_generation: 3,
    isolated_evidence_id: 'i', normal_evidence_id: 'n', enrolled_user_id: 'u', transition_seconds: 0,
    acknowledge_reauthentication: true, acknowledge_emergency_recovery: true, confirm: true, reason: 'Approved cutover',
  })
  const error = await request.catch((value: unknown) => value)
  expect(error).toMatchObject({
    status: 503, code: 'auth_activation_runtime_mismatch', activation: {
      outcome: 'committed_not_applied', commit_persisted: true, desired_generation: 4,
      reconciliation_required: true, automatic_retry_allowed: false,
    },
  })
  expect(error).not.toHaveProperty('activation.provider_secret')
})
