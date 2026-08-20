import { CLOUDFLARE_PROFILE_ID, PROVIDER_CLOUDFLARE, ROUTE_VERIFY_ONLY } from '../core/constants.mjs'
import { fetchJwksDocument } from '../auth/jwks.mjs'

const ACCESS_CHALLENGE_MARKERS = [
  'cloudflareaccess.com',
  'cf-access-domain',
  'cf-team-domain',
  '/cdn-cgi/access/login',
]

function looksLikeGatewayDenial(status, body) {
  return status === 403 && typeof body === 'string' && body.includes('403 Forbidden')
}

function looksLikeAccessChallenge(status, headers, body) {
  const location = headers.get?.('location') ?? headers.location
  const joined = `${location ?? ''}\n${body ?? ''}\n${headers.get?.('cf-access-domain') ?? ''}`
  if (ACCESS_CHALLENGE_MARKERS.some(marker => joined.toLowerCase().includes(marker))) return true
  if (status === 302 && typeof location === 'string' && location.includes('cloudflareaccess.com')) return true
  return false
}

export async function probeAccessAttachment(externalOrigin, { fetchImpl = fetch } = {}) {
  let response
  try {
    response = await fetchImpl(externalOrigin, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(5_000),
      headers: { accept: 'text/html' },
    })
  } catch {
    return { kind: 'uncertain', reason: 'external origin was not reachable for an Access attachment probe' }
  }
  const body = await response.text().catch(() => '')
  if (looksLikeGatewayDenial(response.status, body)) {
    return { kind: 'unprotected', reason: 'unauthenticated request reached the gateway; Access is not attached' }
  }
  if (looksLikeAccessChallenge(response.status, response.headers, body)) {
    return { kind: 'access-challenge', reason: 'unauthenticated request received an Access challenge' }
  }
  return { kind: 'uncertain', reason: 'Access attachment could not be distinguished from this probe' }
}

export const cloudflareAccessProvider = {
  id: PROVIDER_CLOUDFLARE,
  identityCapability() {
    return { kind: 'signed-jwt', profileId: CLOUDFLARE_PROFILE_ID }
  },
  requiredExecutables() {
    return []
  },
  async inspect(config, runtime = {}) {
    if (config.provider.routeManagement !== ROUTE_VERIFY_ONLY) {
      return { kind: 'conflict', reason: 'cloudflare-access only supports verify-only route management' }
    }
    try {
      await fetchJwksDocument(config.provider.teamOrigin, { fetchImpl: runtime.fetchImpl })
    } catch (error) {
      return { kind: 'conflict', reason: `signing metadata is unavailable: ${error instanceof Error ? error.message : String(error)}` }
    }
    return {
      kind: 'verify-only',
      reason: 'Cloudflare Access is verify-only: local JWT validation is mandatory; Access attachment is not provider-state-verified',
    }
  },
  plan(_config, observed) {
    if (observed.kind === 'conflict') {
      return { kind: 'conflict', operations: [], receipt: observed, reason: observed.reason }
    }
    return { kind: 'unchanged', operations: [], receipt: observed }
  },
  async apply(_config, plan) {
    if (plan.kind === 'conflict') throw new Error(`Cloudflare Access conflict: ${plan.reason}`)
    return { action: 'unchanged', detail: 'verify-only (local JWT validation; Access attachment is operator-confirmed)' }
  },
  async verify(config, runtime = {}) {
    try {
      await fetchJwksDocument(config.provider.teamOrigin, { fetchImpl: runtime.fetchImpl })
      return { ok: true, receipt: { kind: 'verify-only' } }
    } catch (error) {
      return { ok: false, reasonCode: error instanceof Error ? error.message : 'jwks_unavailable' }
    }
  },
}
