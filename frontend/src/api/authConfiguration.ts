import type { Identity } from './client'

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
  runtime_provider: AuthProvider; runtime_source: 'environment'; management_only: true
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

export type ConnectionTest = {
  id: string; revision_id: string; configuration_version: number; generation: number
  status: 'checking' | 'pending' | 'processing' | 'succeeded' | 'failed' | 'cancelled' | 'expired'
  expires_at: string; callback_uri: string; reason?: string; tested_identity?: Identity
  evidence_id?: string; evidence_expires_at?: string
}
export type StartedConnectionTest = ConnectionTest & { authorization_url?: string }
