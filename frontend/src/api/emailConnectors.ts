import { configurationRequest } from './authConfiguration'

export const emailConnectorsPath = '/api/admin/notifications/email-connectors'
export type ConnectorStatus = 'configured' | 'ready' | 'authentication_failed' | 'sender_not_verified' | 'permission_denied' | 'quota_unavailable' | 'provider_unavailable'
export type EmailConnector = {
  id: string; provider: 'gmail' | 'ses'; sender: string; region: string; enabled: boolean; default: boolean
  per_minute: number; per_day: number; generation: number; failure_count: number; last_error: string
  readiness: { status: ConnectorStatus; code: string; quota_known: boolean; remaining_24_hours: number; max_per_second: number }
  tested_at?: string; expires_at?: string; has_authorization: boolean
}
export type ConnectorPage = { items: EmailConnector[]; total: number; offset: number; limit: number; gmail_authorization_available: boolean; gmail_callback_url: string; gmail_scopes: string[] }
export type ConnectorCreate = { id: string; provider: 'gmail' | 'ses'; sender: string; region: string; per_minute: number; per_day: number; reason: string }
export type ConnectorUpdate = { expected_generation: number; enabled: boolean; default: boolean; per_minute: number; per_day: number; reason: string }
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu
const statuses: ConnectorStatus[] = ['configured', 'ready', 'authentication_failed', 'sender_not_verified', 'permission_denied', 'quota_unavailable', 'provider_unavailable']
function connector(value: unknown): EmailConnector {
  const row = value as EmailConnector
  if (!row || !uuid.test(row.id) || !['gmail', 'ses'].includes(row.provider) || typeof row.sender !== 'string' || typeof row.region !== 'string' || typeof row.enabled !== 'boolean' || typeof row.default !== 'boolean' || !Number.isInteger(row.generation) || row.generation < 1 || !Number.isInteger(row.per_minute) || !Number.isInteger(row.per_day) || !row.readiness || !statuses.includes(row.readiness.status) || typeof row.readiness.code !== 'string' || typeof row.has_authorization !== 'boolean') throw new Error('invalid connector response')
  return row
}
export async function listEmailConnectors(offset: number, signal?: AbortSignal): Promise<ConnectorPage> {
  const data = await configurationRequest<ConnectorPage>(`${emailConnectorsPath}?offset=${offset}&limit=20`, 'GET', undefined, signal)
  if (!data || !Array.isArray(data.items) || !Number.isInteger(data.total) || typeof data.gmail_authorization_available !== 'boolean' || !Array.isArray(data.gmail_scopes)) throw new Error('invalid connector page')
  data.items.forEach(connector); return data
}
export async function readEmailConnector(id: string) { return connector(await configurationRequest(`${emailConnectorsPath}/${encodeURIComponent(id)}`)) }
export async function createEmailConnector(input: ConnectorCreate) { return connector(await configurationRequest(emailConnectorsPath, 'POST', input)) }
export async function configureEmailConnector(id: string, input: ConnectorUpdate) { return connector(await configurationRequest(`${emailConnectorsPath}/${encodeURIComponent(id)}/configure`, 'POST', input)) }
export async function testEmailConnector(id: string, generation: number, reason: string) { return connector(await configurationRequest(`${emailConnectorsPath}/${encodeURIComponent(id)}/test`, 'POST', { expected_generation: generation, reason })) }
export async function authorizeGmail(id: string, generation: number, mailbox: string, reason: string) {
  const data = await configurationRequest<{ authorization_url: string }>(`${emailConnectorsPath}/${encodeURIComponent(id)}/gmail/authorize`, 'POST', { expected_generation: generation, mailbox, reason, confirm_sender_settings: true })
  const url = new URL(data.authorization_url)
  if (url.origin !== 'https://accounts.google.com' || url.pathname !== '/o/oauth2/v2/auth') throw new Error('invalid authorization response')
  return url.href
}
