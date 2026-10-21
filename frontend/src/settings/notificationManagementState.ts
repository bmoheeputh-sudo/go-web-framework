import { AuthConfigurationError } from '../api/authConfiguration'
import type { QueueStatus } from '../api/notificationManagement'

export const queueStates: QueueStatus[] = ['queued', 'leased', 'dispatching', 'sent', 'failed', 'needs_inspection', 'cancelled']
export const queueTones = { queued: 'info', leased: 'info', dispatching: 'warning', sent: 'success', failed: 'error', needs_inspection: 'warning', cancelled: 'neutral' } as const
export const validNotificationReason = (value: string) => new TextEncoder().encode(value.trim()).length >= 8 && new TextEncoder().encode(value).length <= 512 && [...value].every((char) => { const code = char.codePointAt(0)!; return code >= 32 && (code < 127 || code > 159) })
export function notificationErrorKey(failure: unknown, mutation: boolean) {
  const status = failure instanceof AuthConfigurationError ? failure.status : 0
  return status === 401 || status === 403 ? 'nmDenied' : status === 404 ? 'nmNotFound' : status === 409 ? 'nmConflict' : status === 400 ? 'nmInvalid' : mutation ? 'nmUncertain' : 'nmUnavailable'
}
export function notificationDiagnostic(code: string) {
  const known = ['invitation_unavailable', 'stale_configuration', 'inactive_user', 'revoked_identity', 'onboarded', 'recipient_changed', 'domain_blocked', 'review_required', 'suppressed', 'communication_unavailable', 'administrator_cancelled', 'provider_rejected', 'provider_uncertain', 'lease_expired', 'adapter_unavailable', 'invalid_result']
  return code === '' ? 'nmEligible' : known.includes(code) ? `nmCode_${code}` : 'nmUnavailable'
}
