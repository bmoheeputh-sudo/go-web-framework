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
