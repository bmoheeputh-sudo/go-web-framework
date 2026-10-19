export type Identity = {
  issuer: string; subject: string; email: string; email_verified: boolean; display_name: string
  provider: 'oidc' | 'google_iap' | 'local_dev'
}
export type User = {
  id: string; issuer: string; subject: string; email: string; display_name: string
  active: boolean; roles: string[]; permissions: string[]; account_ids: string[]
}
export type Account = { id: string; name: string; active: boolean }
export type Role = { name: string; permissions: string[] }
export type Audit = { id: string; created_at: string; actor_id: string; action: string; target_id: string; details: unknown }

export class APIError extends Error {
  status: number
  constructor(status: number) {
    const keys: Record<number, string> = { 401: 'errorUnauthenticated', 403: 'errorForbidden', 409: 'errorConflict', 400: 'errorInvalid' }
    super(keys[status] || 'errorUnavailable')
    this.status = status
  }
}
export function errorKey(error: unknown) { return error instanceof APIError ? error.message : 'errorRequest' }

// HTTP status codes are the contract; never render server error prose or tokens.
export async function api<T>(path: string, method = 'GET', body?: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    method, credentials: 'same-origin', cache: 'no-store', signal,
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) throw new APIError(response.status)
  return response.status === 204 ? undefined as T : response.json() as Promise<T>
}

export type CatalogPermission = {
  name: string; description: string; module: string; enabled: boolean
  registered: boolean; known: boolean; roles: string[]
}
export type PermissionCatalog = { permissions: CatalogPermission[]; roles: string[]; revision: string }
export type PermissionChange = { permission: string; role: string; assigned: boolean }
