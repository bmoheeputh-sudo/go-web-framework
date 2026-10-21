import { configurationRequest } from './authConfiguration'

export type AccessPolicySettings = {
  mode: 'allow_all' | 'approved_users_only'
  allowed_email_domains: string[]
  default_role: 'Viewer' | 'User'
}
export type AccessPolicy = AccessPolicySettings & {
  deployment_id: string; environment: string; generation: number
  created_by: string; created_at: string; updated_by: string; updated_at: string; reason: string
}
export type PolicySnapshot = {
  policy: AccessPolicy; activation_generation: number; active_issuer: string
  overview: { approved: number; revoked: number; active_oidc_users: number }
}
export type AccessIdentity = {
  user_id: string; issuer: string; subject: string; email: string; display_name: string
  user_active: boolean; roles: string[]; approval_status: 'approved' | 'revoked' | 'not_approved'
  approval_generation: number; updated_at: string; provider_current: boolean
}
export type IdentityPage = { items: AccessIdentity[]; total: number; offset: number; limit: number; policy_generation: number; activation_generation: number }
export type PolicyExpectation = { expected_policy_generation: number; expected_activation_generation: number }
export type PolicyPreview = {
  policy_generation: number; activation_generation: number; affected_users: number; eligible_users: number
  eligible_administrators: number; current_administrator_loses_access: boolean; can_apply: boolean
}
export const accessPolicyPath = '/api/admin/auth/access-policy'
export const readAccessPolicy = (signal?: AbortSignal) => configurationRequest<PolicySnapshot>(accessPolicyPath, 'GET', undefined, signal)
export const listAccessIdentities = (search: string, status: string, offset: number, signal?: AbortSignal) =>
  configurationRequest<IdentityPage>(`${accessPolicyPath}/approvals?${new URLSearchParams({ search, status, offset: String(offset), limit: '20' })}`, 'GET', undefined, signal)
export const readAccessIdentity = (id: string, signal?: AbortSignal) => configurationRequest<AccessIdentity>(`${accessPolicyPath}/approvals/${encodeURIComponent(id)}`, 'GET', undefined, signal)
export const previewAccessPolicy = (settings: AccessPolicySettings, expected: PolicyExpectation) =>
  configurationRequest<PolicyPreview>(`${accessPolicyPath}/preview`, 'POST', { ...settings, ...expected })
export const updateAccessPolicy = (settings: AccessPolicySettings, expected: PolicyExpectation, reason: string, confirmAccessLoss: boolean) =>
  configurationRequest<AccessPolicy>(accessPolicyPath, 'PUT', { ...settings, ...expected, reason, confirm_access_loss: confirmAccessLoss })
export const setUserApproval = (id: string, status: 'approved' | 'revoked', expected: PolicyExpectation, approvalGeneration: number, reason: string) =>
  configurationRequest(`${accessPolicyPath}/approvals/${encodeURIComponent(id)}/${status === 'approved' ? 'approve' : 'revoke'}`, 'POST', { ...expected, expected_approval_generation: approvalGeneration, reason })

export type InvitationStatus = 'pending' | 'claimed' | 'revoked' | 'expired'
export type Invitation = {
  id: string; deployment_id: string; environment: string; issuer: string; client_id: string
  revision_id: string; revision_generation: number; activation_generation: number
  email: string; email_key: string; display_name: string; expires_at: string; status: InvitationStatus
  generation: number; created_by: string; created_at: string; updated_by: string; updated_at: string; reason: string
  source: 'manual' | 'csv'; import_id?: string; binding_current: boolean
  claimed_user_id?: string; claimed_issuer?: string; claimed_subject?: string; claimed_at?: string
}
export type InvitationPage = {
  items: Invitation[]; total: number; offset: number; limit: number; policy_generation: number
  activation_generation: number; revision_id: string; revision_generation: number
}
export type InvitationExpectation = PolicyExpectation & { revision_id: string; expected_revision_generation: number }
export type InvitationInput = { email: string; display_name: string; reason: string; expires_at?: string }
export const invitationsPath = `${accessPolicyPath}/invitations`
export const listInvitations = (search: string, status: string, offset: number, signal?: AbortSignal, importID?: string) =>
  configurationRequest<InvitationPage>(`${invitationsPath}?${new URLSearchParams({ search, status, offset: String(offset), limit: '20', ...(importID ? { import_id: importID } : {}) })}`, 'GET', undefined, signal)
export const readInvitation = (id: string, signal?: AbortSignal) =>
  configurationRequest<Invitation>(`${invitationsPath}/${encodeURIComponent(id)}`, 'GET', undefined, signal)
export const createInvitation = (input: InvitationInput, expected: InvitationExpectation) =>
  configurationRequest<Invitation>(invitationsPath, 'POST', { ...input, ...expected })
export const revokeInvitation = (id: string, expected: InvitationExpectation, generation: number, reason: string) =>
  configurationRequest<Invitation>(`${invitationsPath}/${encodeURIComponent(id)}/revoke`, 'POST', { ...expected, expected_invitation_generation: generation, reason })

export type CSVRowStatus = 'ready' | 'invalid_email' | 'invalid_display_name' | 'duplicate_csv' | 'existing_pending' | 'already_claimed' | 'existing_user_review' | 'blocked_domain' | 'stale_configuration_or_policy'
export type CSVPreviewRow = { row: number; email: string; display_name: string; status: CSVRowStatus }
export type CSVPreviewInput = InvitationExpectation & { csv: string; selected_rows?: number[]; expiration_days: number }
export type CSVPreview = InvitationExpectation & {
  rows: CSVPreviewRow[]; selected_rows: number[]; total_rows: number; ready_rows: number; skipped_rows: number; invalid_rows: number; will_create: number
  expiration_days: number; content_digest: string; preview_digest: string; preview_expires_at: string; max_rows: number; max_bytes: number
}
export type CSVImportInput = CSVPreviewInput & { selected_rows: number[]; import_id: string; idempotency_key: string; preview_digest: string; preview_expires_at: string; reason: string; confirm: true }
export type ImportReceipt = InvitationExpectation & {
  id: string; deployment_id: string; environment: string; actor_user_id: string; content_digest: string; expiration_days: number
  total_rows: number; selected_rows: number[]; created_count: number; skipped_count: number; rejected_count: number; created_invitation_ids: string[]
  created_at: string; completed_at: string; outcome: 'completed'; reason: string
}
const importUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu
const importDigest = /^[0-9a-f]{64}$/iu
const record = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === 'object' && !Array.isArray(value)
const count = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 500
const date = (value: unknown): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value))
function validImportExpectation(value: Record<string, unknown>) {
  return ['expected_policy_generation', 'expected_activation_generation', 'expected_revision_generation'].every((key) => typeof value[key] === 'number' && Number.isSafeInteger(value[key]) && Number(value[key]) > 0) && typeof value.revision_id === 'string' && importUUID.test(value.revision_id)
}
function validSelection(value: unknown, total: number): value is number[] {
  return Array.isArray(value) && value.length <= total && new Set(value).size === value.length && value.every((n) => count(n) && n >= 1 && n <= total)
}
function validReceipt(value: unknown): value is ImportReceipt {
  if (!record(value) || !validImportExpectation(value) || typeof value.id !== 'string' || !importUUID.test(value.id) || value.outcome !== 'completed' || typeof value.content_digest !== 'string' || !importDigest.test(value.content_digest)) return false
  if (!count(value.total_rows) || !count(value.created_count) || value.created_count < 1 || !count(value.skipped_count) || !count(value.rejected_count) || value.created_count + value.skipped_count + value.rejected_count !== value.total_rows || !validSelection(value.selected_rows, value.total_rows) || value.selected_rows.length !== value.created_count) return false
  return count(value.expiration_days) && value.expiration_days >= 1 && value.expiration_days <= 30 && Array.isArray(value.created_invitation_ids) && value.created_invitation_ids.length === value.created_count && new Set(value.created_invitation_ids).size === value.created_count && value.created_invitation_ids.every((id) => typeof id === 'string' && importUUID.test(id)) && date(value.created_at) && date(value.completed_at) && Date.parse(value.completed_at) >= Date.parse(value.created_at)
}
function validPreview(value: unknown): value is CSVPreview {
  if (!record(value) || !validImportExpectation(value) || !count(value.total_rows) || !count(value.ready_rows) || !count(value.skipped_rows) || !count(value.invalid_rows) || !count(value.will_create) || !validSelection(value.selected_rows, value.total_rows) || value.selected_rows.length !== value.will_create || value.will_create + value.skipped_rows + value.invalid_rows !== value.total_rows || !date(value.preview_expires_at)) return false
  const statuses = ['ready', 'invalid_email', 'invalid_display_name', 'duplicate_csv', 'existing_pending', 'already_claimed', 'existing_user_review', 'blocked_domain', 'stale_configuration_or_policy']
  return value.max_rows === 500 && value.max_bytes === 1048576 && count(value.expiration_days) && value.expiration_days >= 1 && value.expiration_days <= 30 && typeof value.content_digest === 'string' && importDigest.test(value.content_digest) && typeof value.preview_digest === 'string' && (importDigest.test(value.preview_digest) || (value.preview_digest === '' && value.will_create === 0)) && Array.isArray(value.rows) && value.rows.length === value.total_rows && value.rows.every((row, index) => record(row) && row.row === index + 1 && typeof row.email === 'string' && typeof row.display_name === 'string' && typeof row.status === 'string' && statuses.includes(row.status)) && value.selected_rows.every((n) => (value.rows as CSVPreviewRow[])[n - 1].status === 'ready')
}
export async function previewInvitationCSV(input: CSVPreviewInput, signal?: AbortSignal): Promise<CSVPreview> {
  const value = await configurationRequest<unknown>(`${invitationsPath}/import/preview`, 'POST', input, signal)
  if (!validPreview(value)) throw new Error('invalid CSV preview response')
  return value
}
export async function importInvitationCSV(input: CSVImportInput): Promise<ImportReceipt> {
  const value = await configurationRequest<unknown>(`${invitationsPath}/import`, 'POST', input)
  // A 2xx proxy response without the receipt contract cannot establish whether
  // this mutation committed. The caller must inspect its original import UUID.
  if (!validReceipt(value) || value.id.toLowerCase() !== input.import_id.toLowerCase()) throw new Error('invalid import receipt response')
  return value
}
export async function readImportReceipt(id: string, signal?: AbortSignal): Promise<ImportReceipt> {
  const value = await configurationRequest<unknown>(`${invitationsPath}/imports/${encodeURIComponent(id)}`, 'GET', undefined, signal)
  if (!validReceipt(value) || value.id.toLowerCase() !== id.toLowerCase()) throw new Error('invalid import receipt response')
  return value
}
