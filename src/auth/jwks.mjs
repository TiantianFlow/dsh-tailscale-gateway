import { createLocalJWKSet } from 'jose'
import {
  JWKS_FRESH_MS,
  JWKS_MAX_BYTES,
  JWKS_STALE_MS,
  JWKS_TIMEOUT_MS,
} from '../core/constants.mjs'

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function jwksUrlFor(teamOrigin) {
  return new URL('/cdn-cgi/access/certs', teamOrigin)
}

export function validateJwksDocument(document) {
  if (!isRecord(document) || !Array.isArray(document.keys)) {
    throw new Error('jwks_malformed')
  }
  const kids = new Set()
  const keys = []
  for (const key of document.keys) {
    if (!isRecord(key)) throw new Error('jwks_malformed')
    if (typeof key.kid !== 'string' || key.kid.length === 0) throw new Error('jwks_missing_kid')
    if (kids.has(key.kid)) throw new Error('jwks_duplicate_kid')
    kids.add(key.kid)
    if (key.kty !== 'RSA' || (key.alg && key.alg !== 'RS256') || (key.use && key.use !== 'sig')) continue
    if (typeof key.n !== 'string' || typeof key.e !== 'string') continue
    keys.push(key)
  }
  if (keys.length === 0) throw new Error('jwks_no_usable_keys')
  return { keys }
}

export async function fetchJwksDocument(teamOrigin, { fetchImpl = fetch, now = Date.now } = {}) {
  const url = jwksUrlFor(teamOrigin)
  if (url.protocol !== 'https:' || url.hostname !== new URL(teamOrigin).hostname) {
    throw new Error('jwks_url_invalid')
  }
  let response
  try {
    response = await fetchImpl(url, {
      method: 'GET',
      redirect: 'error',
      signal: AbortSignal.timeout(JWKS_TIMEOUT_MS),
      headers: { accept: 'application/json' },
    })
  } catch (error) {
    if (error?.name === 'TimeoutError' || error?.name === 'AbortError') throw new Error('jwks_timeout')
    throw new Error('jwks_fetch_failed')
  }
  if (!response.ok) throw new Error('jwks_fetch_failed')
  const contentType = String(response.headers.get('content-type') ?? '')
  if (!contentType.toLowerCase().startsWith('application/json')) throw new Error('jwks_content_type')
  const buffer = Buffer.from(await response.arrayBuffer())
  if (buffer.length === 0 || buffer.length > JWKS_MAX_BYTES) throw new Error('jwks_oversized')
  let parsed
  try {
    parsed = JSON.parse(buffer.toString('utf8'))
  } catch {
    throw new Error('jwks_malformed')
  }
  const document = validateJwksDocument(parsed)
  return { document, fetchedAt: now() }
}

export function createJwksCache({ teamOrigin, fetchImpl = fetch, freshMs = JWKS_FRESH_MS, staleMs = JWKS_STALE_MS, now = Date.now } = {}) {
  let current
  let inflight

  async function refresh() {
    const fetched = await fetchJwksDocument(teamOrigin, { fetchImpl, now })
    current = {
      ...fetched,
      keySet: createLocalJWKSet(fetched.document),
    }
    return current
  }

  return {
    async get() {
      const timestamp = now()
      if (current) {
        if (timestamp - current.fetchedAt <= freshMs) return current
        if (timestamp - current.fetchedAt <= freshMs + staleMs) {
          if (!inflight) inflight = refresh().finally(() => { inflight = undefined })
          return current
        }
        current = undefined
      }
      if (!inflight) inflight = refresh().finally(() => { inflight = undefined })
      return inflight
    },
    async readiness() {
      try {
        await this.get()
        return { ready: true }
      } catch (error) {
        return { ready: false, reasonCode: error instanceof Error ? error.message : 'jwks_unavailable' }
      }
    },
  }
}
