import { APIError } from './client'
import type { Identity, User } from './client'

export type AuthProvider = Identity['provider']
export type RevisionStatus = 'draft' | 'validated' | 'approved' | 'active' | 'superseded'
export type AuthSettings = {
  provider: AuthProvider; issuer_url: string; client_id: string; redirect_uri: string
  iap_audience: string; allow_http_development: boolean
}
// Metadata has no credential/ciphertext fields. Never use a revision to fill a secret input.
export type AuthRevision = AuthSettings & {
  id: string; deployment_id: string; environment: 'development' | 'test' | 'production'
  configuration_version: number; status: RevisionStatus; generation: number
  created_by: string; created_at: string; updated_by: string; updated_at: string
  validation: { check?: 'static'; version?: number }
  validated_at?: string; approved_at?: string; activated_at?: string; superseded_at?: string
  has_secret: boolean
}
export type AuthStatus = {
  runtime_provider: AuthProvider; runtime_source: 'environment' | 'database'; management_only: boolean; activation_api_available: boolean
  validation_mode: 'offline_static'; latest_revision: AuthRevision | null; database_active_revision: AuthRevision | null
}
export type AuthHistory = { revisions: AuthRevision[]; next_before_version: number }
export type NewAuthDraft = { expected_latest_version: number } & (
  | { provider: 'oidc'; issuer_url: string; client_id: string; client_secret: string; redirect_uri: string; allow_http_development: boolean }
  | { provider: 'google_iap'; iap_audience: string }
  | { provider: 'local_dev' }
)
export const authSettingsPath = '/api/admin/auth/settings'
export const authStatusPath = '/api/admin/auth/status' // No query parameters on this endpoint.
export const authProviderSetupPath = '/api/admin/auth/provider-setup'

export type OIDCProviderSetupMetadata = {
  application_name: 'Vopak Enterprise Security'
  application_type: 'confidential_web_application'
  normal_callback_url: string
  test_callback_url: string
  grant_types: readonly ['authorization_code']
  pkce_methods: readonly ['S256']
  scopes: readonly ['openid', 'profile', 'email']
  client_authentication_methods: readonly ['client_secret_basic']
  environment: 'development' | 'test' | 'production'
  development_http: boolean
}

export type ConnectionTest = {
  id: string; revision_id: string; configuration_version: number; generation: number
  status: 'checking' | 'pending' | 'processing' | 'succeeded' | 'failed' | 'cancelled' | 'expired'
  expires_at: string; callback_uri: string; reason?: string; tested_identity?: Identity
  evidence_id?: string; evidence_expires_at?: string
}
export type StartedConnectionTest = ConnectionTest & { authorization_url?: string }

export type ActivationOutcome = 'committed_applied' | 'committed_not_applied' | 'commit_uncertain' | 'not_committed'
export type ActivationResult = {
  outcome: ActivationOutcome
  commit_persisted: boolean | null
  authoritative_state_known: boolean
  authoritative_generation: number
  authoritative_revision_id?: string
  desired_generation: number
  applied_generation: number
  revision_id: string
  applied: boolean
  commit_uncertain: boolean
  reconciliation_required: boolean
  automatic_retry_allowed: boolean
}
export type ActivationStatus = {
  authoritative_source: 'environment' | 'database'
  authoritative_generation: number
  authoritative_revision_id?: string
  local_source: 'environment' | 'database'
  local_provider: AuthProvider
  local_applied_generation: number
  local_desired_generation: number
  local_revision_id?: string
  transition_deadline?: string
  listener_connected: boolean
  synchronization_degraded: boolean
  reconciled: boolean
  reconciliation_required: boolean
  preparation_affinity_mode?: 'single_instance' | 'session_affinity'
  preparation_enabled: boolean
  automatic_activation_retry: false
}
export type ActivationPreparation = {
  preparation_id: string
  revision_id: string
  revision_generation: number
  expected_activation_generation: number
  target_activation_generation: number
  expires_at: string
  current_provider: AuthProvider
  current_source: 'environment' | 'database'
  requires_reauthentication: boolean
  maximum_transition_seconds: number
  warning?: 'immediate_reauthentication_required'
  emergency_recovery_required: boolean
  offline_recovery_procedure?: 'auth-recovery-cli'
  normal_callback_status: 'not_started' | 'pending' | 'succeeded' | 'failed' | 'expired'
  normal_evidence_id?: string
  normal_evidence_expires_at?: string
}
export type NormalReadinessStart = {
  preparation_id: string
  status: 'pending'
  authorization_url: string
  callback_url: string
  expires_at: string
}
export type ActivateRequest = {
  revision_id: string
  expected_revision_generation: number
  expected_activation_generation: number
  isolated_evidence_id: string
  normal_evidence_id: string
  enrolled_user_id: string
  transition_seconds: number
  acknowledge_reauthentication: boolean
  acknowledge_emergency_recovery: boolean
  confirm: true
  reason: string
}
export type RecoveryReadiness = {
  revision_id: string
  source_revision_id: string
  status: RevisionStatus
  configuration_pre_staged: boolean
  enrolled_administrator_ready: boolean
  fresh_isolated_evidence: boolean
  fresh_normal_callback_evidence: boolean
  ready_for_portal_activation: boolean
  live_provider_required: boolean
  offline_recovery_procedure: 'auth-recovery-cli'
}
export type RecoveryDraftResponse = { revision: AuthRevision; activation_required: true }

type SafeFailure = Partial<ActivationResult> & {
  error?: string
  offline_recovery_procedure?: string
  recovery_provider_must_be_available?: boolean
  required_configuration?: string
}

export class AuthConfigurationError extends APIError {
  code: string
  activation?: ActivationResult
  offlineRecoveryProcedure?: string
  constructor(status: number, failure: SafeFailure = {}) {
    super(status)
    this.code = typeof failure.error === 'string' ? failure.error : ''
    this.offlineRecoveryProcedure = typeof failure.offline_recovery_procedure === 'string' ? failure.offline_recovery_procedure : undefined
    this.activation = parseActivationResult(failure)
  }
}

function parseActivationResult(value: Partial<ActivationResult>): ActivationResult | undefined {
  const valid = ['committed_applied', 'committed_not_applied', 'commit_uncertain', 'not_committed'].includes(String(value.outcome)) &&
    (typeof value.commit_persisted === 'boolean' || value.commit_persisted === null) &&
    typeof value.authoritative_state_known === 'boolean' && typeof value.authoritative_generation === 'number' &&
    typeof value.desired_generation === 'number' && typeof value.applied_generation === 'number' &&
    typeof value.revision_id === 'string' && typeof value.applied === 'boolean' && typeof value.commit_uncertain === 'boolean' &&
    typeof value.reconciliation_required === 'boolean' && typeof value.automatic_retry_allowed === 'boolean' &&
    (value.authoritative_revision_id === undefined || typeof value.authoritative_revision_id === 'string')
  if (!valid) return undefined
  return {
    outcome: value.outcome as ActivationOutcome, commit_persisted: value.commit_persisted!,
    authoritative_state_known: value.authoritative_state_known!, authoritative_generation: value.authoritative_generation!,
    authoritative_revision_id: value.authoritative_revision_id, desired_generation: value.desired_generation!,
    applied_generation: value.applied_generation!, revision_id: value.revision_id!, applied: value.applied!,
    commit_uncertain: value.commit_uncertain!, reconciliation_required: value.reconciliation_required!,
    automatic_retry_allowed: value.automatic_retry_allowed!,
  }
}

async function configurationRequest<T>(path: string, method = 'GET', body?: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    method, credentials: 'same-origin', cache: 'no-store', signal,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) {
    let failure: SafeFailure = {}
    try { failure = await response.json() as SafeFailure } catch { /* Status remains authoritative. */ }
    throw new AuthConfigurationError(response.status, failure)
  }
  return response.status === 204 ? undefined as T : response.json() as Promise<T>
}

export const activationStatusPath = '/api/admin/auth/activation/status'
export const getActivationStatus = (signal?: AbortSignal) => configurationRequest<ActivationStatus>(activationStatusPath, 'GET', undefined, signal)
export const prepareActivation = (id: string, expectedRevisionGeneration: number, expectedActivationGeneration: number, signal?: AbortSignal) =>
  configurationRequest<ActivationPreparation>(`${authSettingsPath}/${encodeURIComponent(id)}/activation/prepare`, 'POST', {
    expected_revision_generation: expectedRevisionGeneration, expected_activation_generation: expectedActivationGeneration,
  }, signal)
export const startNormalReadiness = (preparationID: string, signal?: AbortSignal) =>
  configurationRequest<NormalReadinessStart>(`/api/admin/auth/activation-preparations/${encodeURIComponent(preparationID)}/readiness`, 'POST', {}, signal)
export const getActivationPreparation = (preparationID: string, signal?: AbortSignal) =>
  configurationRequest<ActivationPreparation>(`/api/admin/auth/activation-preparations/${encodeURIComponent(preparationID)}`, 'GET', undefined, signal)
export const activateOIDC = (preparationID: string, request: ActivateRequest, signal?: AbortSignal) =>
  configurationRequest<ActivationResult>(`/api/admin/auth/activation-preparations/${encodeURIComponent(preparationID)}/activate`, 'POST', request, signal)
export const reconcileActivation = (expectedDesiredGeneration: number, signal?: AbortSignal) =>
  configurationRequest<ActivationStatus>('/api/admin/auth/activation/reconcile', 'POST', {
    expected_desired_generation: expectedDesiredGeneration, confirm: true,
  }, signal)
export const createRecoveryDraft = (id: string, expectedLatestVersion: number, reason: string, signal?: AbortSignal) =>
  configurationRequest<RecoveryDraftResponse>(`${authSettingsPath}/${encodeURIComponent(id)}/rollback`, 'POST', {
    expected_latest_version: expectedLatestVersion, confirm: true, reason,
  }, signal)
export const getRecoveryReadiness = (id: string, signal?: AbortSignal) =>
  configurationRequest<RecoveryReadiness>(`${authSettingsPath}/${encodeURIComponent(id)}/recovery-readiness`, 'GET', undefined, signal)

// Exact issuer+subject lookup only. Email is never used for enrollment or activation.
export async function findEnrolledOIDCAdministrator(issuer: string, subject: string, signal?: AbortSignal): Promise<User | null> {
  for (let offset = 0; offset <= 10_000; offset += 100) {
    const users = await configurationRequest<User[]>(`/api/admin/users?offset=${offset}`, 'GET', undefined, signal)
    const match = users.find((user) => user.issuer === issuer && user.subject === subject && user.active && user.permissions.includes('admin.manage'))
    if (match) return match
    if (users.length < 100) return null
  }
  return null
}
