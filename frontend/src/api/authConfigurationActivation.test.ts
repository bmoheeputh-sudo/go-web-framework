import { afterEach, expect, it, vi } from 'vitest'
import {
  activateOIDC, AuthConfigurationError, createRecoveryDraft, getActivationPreparation, getActivationStatus,
  getRecoveryReadiness, prepareActivation, reconcileActivation, startNormalReadiness,
} from './authConfiguration'

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

const activationRequest = {
  revision_id: 'revision-1', expected_revision_generation: 2, expected_activation_generation: 3,
  isolated_evidence_id: 'i', normal_evidence_id: 'n', enrolled_user_id: 'u', transition_seconds: 0,
  acknowledge_reauthentication: true, acknowledge_emergency_recovery: true, confirm: true as const, reason: 'Approved cutover',
}
const applied = {
  outcome: 'committed_applied', commit_persisted: true, authoritative_state_known: true,
  authoritative_generation: 4, authoritative_revision_id: 'revision-1', desired_generation: 4,
  applied_generation: 4, revision_id: 'revision-1', applied: true, commit_uncertain: false,
  reconciliation_required: false, automatic_retry_allowed: false,
}

it('uses the committed activation endpoint contracts and explicit confirmation fields', async () => {
  const fetcher = vi.fn(async () => Response.json(applied))
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

it.each([502, 504])('handles proxy HTTP %i HTML without JSON parsing exceptions', async (status) => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response('<html>upstream unavailable</html>', {
    status, headers: { 'Content-Type': 'text/html' },
  })))
  const error = await activateOIDC('preparation', activationRequest).catch((value: unknown) => value)
  expect(error).toBeInstanceOf(AuthConfigurationError)
  expect(error).toMatchObject({ status, activation: undefined })
})

it('handles a proxy JSON null response as an unstructured failure', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => Response.json(null, { status: 502 })))
  const error = await activateOIDC('preparation', activationRequest).catch((value: unknown) => value)
  expect(error).toBeInstanceOf(AuthConfigurationError)
  expect(error).toMatchObject({ status: 502, activation: undefined })
})

it('rejects truncated or malformed successful responses without treating them as activation success', async () => {
  const fetcher = vi.fn()
    .mockResolvedValueOnce(new Response('{"outcome":', { status: 200 }))
    .mockResolvedValueOnce(Response.json({ outcome: 'committed_applied' }))
  vi.stubGlobal('fetch', fetcher)
  await expect(activateOIDC('preparation', activationRequest)).rejects.toThrow()
  await expect(activateOIDC('preparation', activationRequest)).rejects.toThrow('invalid activation response')
  expect(fetcher).toHaveBeenCalledTimes(2) // One request per explicit invocation; no internal retry.
})

it('propagates a disconnected activation request without retrying it', async () => {
  const fetcher = vi.fn(async () => { throw new TypeError('network disconnected') })
  vi.stubGlobal('fetch', fetcher)
  await expect(activateOIDC('preparation', activationRequest)).rejects.toThrow('network disconnected')
  expect(fetcher).toHaveBeenCalledTimes(1)
})
