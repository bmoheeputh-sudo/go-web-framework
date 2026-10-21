import { configurationRequest } from './authConfiguration'

export const notificationsPath = '/api/admin/notifications'
export type NotificationKind = 'invitation' | 'reminder'
export type OnboardingCategory = 'onboarded' | 'pending' | 'unobserved' | 'inactive'
export type QueueStatus = 'queued' | 'leased' | 'dispatching' | 'sent' | 'failed' | 'needs_inspection' | 'cancelled'
export type OnboardingTarget = { target: string; email: string; display_name: string; category: OnboardingCategory; code: string; first_successful_oidc_login_at?: string; last_successful_oidc_login_at?: string; claim_evidence: boolean; expires_at?: string; import_id?: string }
export type OnboardingPage = { items: OnboardingTarget[]; counts: Record<OnboardingCategory, number>; total: number; offset: number; limit: number; communication_configured: boolean; delivery_enabled: false; max_batch: 100; access_mode: 'allow_all' | 'approved_users_only' }
export type NotificationPreviewInput = { request_id: string; type: NotificationKind; locale: string; connector_id: string; targets: string[] }
export type NotificationExpected = { expected_policy_generation: number; expected_activation_generation: number; revision_id: string; expected_revision_generation: number }
export type NotificationPreviewRow = { target: string; email: string; display_name: string; code: string; subject?: string; text?: string }
export type NotificationPreview = { input: NotificationPreviewInput; expected: NotificationExpected; connector_generation: number; sender: string; template_version: string; rows: NotificationPreviewRow[]; selected_targets: string[]; ready_count: number; skipped_count: number; preview_digest: string; preview_expires_at: string; delivery_enabled: false }
export type NotificationEnqueueInput = { input: NotificationPreviewInput; expected: NotificationExpected; connector_generation: number; selected_targets: string[]; preview_digest: string; preview_expires_at: string; idempotency_key: string; reason: string; confirm: true }
export type NotificationEnqueueResult = { request_id: string; job_count: number; outcome: 'queued'; delivery_enabled: false }
export type HistoryItem = { id: string; request_id: string; target: string; recipient: string; display_name: string; type: NotificationKind; connector_id: string; provider: 'gmail' | 'ses'; sender: string; actor_id: string; actor_name: string; status: QueueStatus; attempt_outcome: '' | 'in_progress' | 'accepted' | 'rejected' | 'uncertain'; disposition: string; created_at: string; generation: number; attempt_count: number }
export type HistoryPage = { items: HistoryItem[]; total: number; offset: number; limit: number; delivery_enabled: false }
export type NotificationReceipt = { id: string; actor_id: string; type: NotificationKind; connector_id: string; sender: string; template_version: string; locale: string; reason: string; job_count: number; outcome: 'enqueued'; created_at: string; jobs: HistoryPage; delivery_enabled: false }
export type NotificationAttempt = { number: number; adapter: 'gmail' | 'ses'; outcome: 'in_progress' | 'accepted' | 'rejected' | 'uncertain'; provider_message_id: string; code: string; started_at: string; completed_at?: string }
export type JobDetail = { item: HistoryItem; attempts: NotificationAttempt[]; delivery_enabled: false }
export type Suppression = { target: string; active: boolean; generation: number; reason: string }
export const notificationUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u
const reference = /^(?:user|invitation):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u
const statuses: QueueStatus[] = ['queued', 'leased', 'dispatching', 'sent', 'failed', 'needs_inspection', 'cancelled']
const count = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0
const date = (s: unknown): s is string => typeof s === 'string' && Number.isFinite(Date.parse(s))
const object = (s: unknown): s is Record<string, unknown> => Boolean(s) && typeof s === 'object' && !Array.isArray(s)
const strings = (s: unknown): s is string[] => Array.isArray(s) && s.every((item) => typeof item === 'string')
function invalid(): never { throw new Error('invalid notification response') }
function historyItem(value: unknown): value is HistoryItem {
  if (!object(value)) return false
  return ['id', 'request_id', 'connector_id', 'actor_id'].every((key) => typeof value[key] === 'string' && notificationUUID.test(value[key] as string)) && typeof value.target === 'string' && reference.test(value.target) && ['recipient', 'display_name', 'sender', 'actor_name', 'disposition'].every((key) => typeof value[key] === 'string') && ['invitation', 'reminder'].includes(String(value.type)) && ['gmail', 'ses'].includes(String(value.provider)) && statuses.includes(value.status as QueueStatus) && ['', 'in_progress', 'accepted', 'rejected', 'uncertain'].includes(String(value.attempt_outcome)) && count(value.generation) && value.generation >= 1 && count(value.attempt_count) && date(value.created_at)
}
function historyPage(value: unknown): value is HistoryPage {
  return object(value) && value.delivery_enabled === false && count(value.total) && count(value.offset) && count(value.limit) && value.limit <= 100 && Array.isArray(value.items) && value.items.length <= value.limit && value.items.every(historyItem)
}
export async function listOnboarding(category: OnboardingCategory, search: string, importID: string, offset: number, signal?: AbortSignal): Promise<OnboardingPage> {
  const value = await configurationRequest<unknown>(`${notificationsPath}/onboarding?${new URLSearchParams({ category, search, ...(importID ? { import_id: importID } : {}), offset: String(offset), limit: '20' })}`, 'GET', undefined, signal)
  if (!object(value) || value.delivery_enabled !== false || typeof value.communication_configured !== 'boolean' || value.max_batch !== 100 || !['allow_all', 'approved_users_only'].includes(String(value.access_mode)) || !count(value.total) || !count(value.offset) || value.limit !== 20 || !object(value.counts) || !['onboarded', 'pending', 'unobserved', 'inactive'].every((key) => count((value.counts as Record<string, unknown>)[key])) || !Array.isArray(value.items) || value.items.length > 20 || !value.items.every((item) => object(item) && typeof item.target === 'string' && reference.test(item.target) && typeof item.email === 'string' && typeof item.display_name === 'string' && item.category === category && typeof item.code === 'string' && typeof item.claim_evidence === 'boolean')) invalid()
  return value as OnboardingPage
}
export async function previewNotifications(input: NotificationPreviewInput, signal?: AbortSignal): Promise<NotificationPreview> {
  const value = await configurationRequest<unknown>(`${notificationsPath}/preview`, 'POST', input, signal)
  if (!object(value) || value.delivery_enabled !== false || !object(value.input) || value.input.request_id !== input.request_id || value.input.connector_id !== input.connector_id || value.input.type !== input.type || value.input.locale !== input.locale || !strings(value.input.targets) || [...value.input.targets].sort().join('|') !== [...input.targets].sort().join('|') || !object(value.expected) || !notificationUUID.test(String(value.expected.revision_id)) || !['expected_policy_generation', 'expected_activation_generation', 'expected_revision_generation'].every((key) => count((value.expected as Record<string, unknown>)[key]) && Number((value.expected as Record<string, unknown>)[key]) >= 1) || !count(value.connector_generation) || value.connector_generation < 1 || typeof value.sender !== 'string' || value.template_version !== 'onboarding.v1' || !date(value.preview_expires_at) || !/^[0-9a-f]{64}$/u.test(String(value.preview_digest)) || !count(value.ready_count) || !count(value.skipped_count) || !strings(value.selected_targets) || value.selected_targets.length !== value.ready_count || new Set(value.selected_targets).size !== value.ready_count || !Array.isArray(value.rows) || value.rows.length !== input.targets.length || value.ready_count + value.skipped_count !== value.rows.length) invalid()
  const p = value as NotificationPreview
  if (new Set(p.rows.map((row) => row.target)).size !== p.rows.length || p.rows.filter((row) => row.code === '').length !== p.ready_count || !p.rows.every((row) => reference.test(row.target) && input.targets.includes(row.target) && typeof row.email === 'string' && typeof row.display_name === 'string' && typeof row.code === 'string' && (row.code !== '' || typeof row.subject === 'string' && typeof row.text === 'string')) || p.selected_targets.some((target) => !p.rows.some((row) => row.target === target && row.code === ''))) invalid()
  return p
}
export async function enqueueNotifications(input: NotificationEnqueueInput): Promise<NotificationEnqueueResult> {
  const value = await configurationRequest<unknown>(`${notificationsPath}/enqueue`, 'POST', input)
  if (!object(value) || value.delivery_enabled !== false || value.request_id !== input.input.request_id || value.outcome !== 'queued' || value.job_count !== input.selected_targets.length) invalid()
  return value as NotificationEnqueueResult
}
export async function listNotificationHistory(search: string, status: string, offset: number, signal?: AbortSignal): Promise<HistoryPage> {
  const value = await configurationRequest<unknown>(`${notificationsPath}/history?${new URLSearchParams({ search, status, offset: String(offset), limit: '20' })}`, 'GET', undefined, signal)
  if (!historyPage(value)) invalid(); return value
}
export async function readNotificationReceipt(id: string, offset = 0, signal?: AbortSignal): Promise<NotificationReceipt> {
  const value = await configurationRequest<unknown>(`${notificationsPath}/requests/${encodeURIComponent(id)}?offset=${offset}&limit=20`, 'GET', undefined, signal)
  if (!object(value) || value.id !== id || value.delivery_enabled !== false || value.outcome !== 'enqueued' || !['actor_id', 'connector_id'].every((key) => typeof value[key] === 'string' && notificationUUID.test(value[key] as string)) || !['invitation', 'reminder'].includes(String(value.type)) || typeof value.sender !== 'string' || value.template_version !== 'onboarding.v1' || typeof value.locale !== 'string' || !count(value.job_count) || value.job_count < 1 || value.job_count > 100 || !historyPage(value.jobs) || value.jobs.total !== value.job_count || value.jobs.items.some((item) => item.request_id !== id) || typeof value.reason !== 'string' || !date(value.created_at)) invalid()
  return value as NotificationReceipt
}
export async function readNotificationJob(id: string): Promise<JobDetail> {
  const value = await configurationRequest<unknown>(`${notificationsPath}/jobs/${encodeURIComponent(id)}`)
  if (!object(value) || value.delivery_enabled !== false || !historyItem(value.item) || value.item.id !== id || !Array.isArray(value.attempts) || value.attempts.length > 10 || !value.attempts.every((attempt) => object(attempt) && count(attempt.number) && attempt.number >= 1 && ['gmail', 'ses'].includes(String(attempt.adapter)) && ['in_progress', 'accepted', 'rejected', 'uncertain'].includes(String(attempt.outcome)) && typeof attempt.provider_message_id === 'string' && typeof attempt.code === 'string' && date(attempt.started_at))) invalid()
  return value as JobDetail
}
export async function cancelNotification(id: string, generation: number, reason: string) {
  const value = await configurationRequest<unknown>(`${notificationsPath}/jobs/${encodeURIComponent(id)}/cancel`, 'POST', { expected_generation: generation, reason })
  if (!object(value) || value.id !== id || value.outcome !== 'cancelled') invalid()
}
function suppression(value: unknown, target: string): Suppression {
  if (!object(value) || value.target !== target || typeof value.active !== 'boolean' || !count(value.generation) || typeof value.reason !== 'string') invalid()
  return value as Suppression
}
export async function readNotificationSuppression(target: string) { return suppression(await configurationRequest(`${notificationsPath}/suppressions?${new URLSearchParams({ target })}`), target) }
export async function setNotificationSuppression(target: string, generation: number, active: boolean, reason: string) { return suppression(await configurationRequest(`${notificationsPath}/suppressions`, 'POST', { target, expected_generation: generation, active, reason }), target) }
