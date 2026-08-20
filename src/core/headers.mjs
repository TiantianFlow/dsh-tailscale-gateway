import {
  UPSTREAM_AUTHORITY,
  UPSTREAM_ORIGIN,
} from './constants.mjs'

const HOP_BY_HOP_HEADERS = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
])
const REQUEST_STRIP_HEADERS = new Set([
  ...HOP_BY_HOP_HEADERS,
  'authorization', 'cookie', 'host', 'origin', 'forwarded', 'via',
  'x-real-ip', 'x-original-forwarded-for',
])
const RESPONSE_STRIP_HEADERS = new Set([
  ...HOP_BY_HOP_HEADERS,
  'set-cookie', 'www-authenticate', 'content-security-policy',
  'x-frame-options', 'referrer-policy', 'permissions-policy',
  'strict-transport-security',
])
const WEBSOCKET_ALLOWED = new Set([
  'sec-websocket-key', 'sec-websocket-version', 'sec-websocket-protocol',
  'sec-websocket-extensions', 'user-agent', 'accept-language',
])

export function isHeaderValue(value) {
  return typeof value === 'string' && !/[\r\n\0]/.test(value)
}

function headerEntries(headers) {
  return Object.entries(headers ?? {})
}

export function rawHeaderPairs(rawHeaders) {
  if (!Array.isArray(rawHeaders) || rawHeaders.length % 2 !== 0) return []
  const pairs = []
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index]
    const value = rawHeaders[index + 1]
    if (typeof name !== 'string' || !isHeaderValue(value)) return []
    pairs.push([name.toLowerCase(), value])
  }
  return pairs
}

/** Return a header only when it appeared exactly once in the raw request. */
export function exactlyOneRawHeader(rawHeaders, expectedName) {
  const target = String(expectedName).toLowerCase()
  const values = rawHeaderPairs(rawHeaders)
    .filter(([name]) => name === target)
    .map(([, value]) => value)
  return values.length === 1 ? values[0] : undefined
}

export function rawHeaderExists(rawHeaders, expectedName) {
  const target = String(expectedName).toLowerCase()
  for (let index = 0; index < (rawHeaders?.length ?? 0); index += 2) {
    if (typeof rawHeaders[index] === 'string' && rawHeaders[index].toLowerCase() === target) return true
  }
  return false
}

export function rawHeaderValues(rawHeaders, expectedName) {
  const target = String(expectedName).toLowerCase()
  return rawHeaderPairs(rawHeaders)
    .filter(([name]) => name === target)
    .map(([, value]) => value)
}

function connectionTokens(headers) {
  const value = headers?.connection
  if (typeof value !== 'string') return new Set()
  return new Set(value.split(',').map(part => part.trim().toLowerCase()).filter(Boolean))
}

function stripRequestHeader(name, dynamicHopHeaders, extraStripNames) {
  return (
    REQUEST_STRIP_HEADERS.has(name) || dynamicHopHeaders.has(name) || extraStripNames.has(name) ||
    name.startsWith('x-') || name.startsWith('tailscale-') || name.startsWith('proxy-') ||
    name.startsWith('cf-access-') ||
    name.includes('auth') || name.includes('token') || name.includes('credential') || name.includes('cookie')
  )
}

/** Build an upstream request header set with no client identity or credentials. */
export function rewriteUpstreamHeaders(headers = {}, { extraStripNames = [] } = {}) {
  const dynamicHopHeaders = connectionTokens(headers)
  const extra = new Set(extraStripNames.map(name => String(name).toLowerCase()))
  const rewritten = {}
  for (const [originalName, value] of headerEntries(headers)) {
    const name = originalName.toLowerCase()
    if (!isHeaderValue(value) || stripRequestHeader(name, dynamicHopHeaders, extra)) continue
    rewritten[name] = value
  }
  rewritten.host = UPSTREAM_AUTHORITY
  rewritten.origin = UPSTREAM_ORIGIN
  return rewritten
}

/** WebSocket upgrades use a deliberate handshake-only client header allowlist. */
export function rewriteWebSocketHeaders(headers = {}) {
  const rewritten = {}
  for (const [originalName, value] of headerEntries(headers)) {
    const name = originalName.toLowerCase()
    if (WEBSOCKET_ALLOWED.has(name) && isHeaderValue(value)) rewritten[name] = value
  }
  return {
    ...rewritten,
    host: UPSTREAM_AUTHORITY,
    origin: UPSTREAM_ORIGIN,
    connection: 'Upgrade',
    upgrade: 'websocket',
  }
}

function rewriteLocation(value, externalOrigin) {
  if (!isHeaderValue(value)) return undefined
  try {
    const url = new URL(value, UPSTREAM_ORIGIN)
    if (url.origin !== UPSTREAM_ORIGIN) return value
    return new URL(`${url.pathname}${url.search}${url.hash}`, externalOrigin).href
  } catch {
    return undefined
  }
}

/** Strip upstream credentials/CORS/proxy controls and add frame-safe headers. */
export function rewriteDownstreamHeaders(headers = {}, externalOrigin) {
  const dynamicHopHeaders = connectionTokens(headers)
  const rewritten = {}
  for (const [originalName, value] of headerEntries(headers)) {
    const name = originalName.toLowerCase()
    if (
      !isHeaderValue(value) || RESPONSE_STRIP_HEADERS.has(name) || dynamicHopHeaders.has(name) ||
      name.startsWith('access-control-') || name.startsWith('proxy-')
    ) continue
    if (name === 'location') {
      const replacement = rewriteLocation(value, externalOrigin)
      if (replacement) rewritten.location = replacement
      continue
    }
    rewritten[name] = value
  }
  rewritten['content-security-policy'] = "frame-ancestors 'none'; base-uri 'none'"
  rewritten['x-frame-options'] = 'DENY'
  rewritten['x-content-type-options'] = 'nosniff'
  rewritten['referrer-policy'] = 'no-referrer'
  rewritten['permissions-policy'] = 'camera=(), microphone=(), geolocation=()'
  rewritten['strict-transport-security'] = 'max-age=31536000; includeSubDomains'
  return rewritten
}
