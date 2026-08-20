import { timingSafeEqual } from 'node:crypto'
import {
  GATEWAY_HOST,
  GATEWAY_PORT,
  READINESS_PATH,
} from './constants.mjs'
import { parseActivationToken, readinessRequestTarget } from './config.mjs'
import { exactlyOneRawHeader, rawHeaderExists } from './headers.mjs'

function sameToken(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false
  const a = Buffer.from(left)
  const b = Buffer.from(right)
  return a.length === b.length && timingSafeEqual(a, b)
}

const REMOTE_EVIDENCE_HEADERS = [
  'tailscale-user-login',
  'cf-access-jwt-assertion',
  'cf-access-authenticated-user-email',
]

export function requestPathname(request) {
  try {
    return new URL(request.url, `http://${GATEWAY_HOST}:${GATEWAY_PORT}`).pathname
  } catch {
    return undefined
  }
}

export function isReadinessPath(request) {
  return requestPathname(request) === READINESS_PATH
}

export function isLocalReadinessRequest(request, config) {
  if (!config.activationToken || request.method !== 'GET' || request.socket.remoteAddress !== GATEWAY_HOST) return false
  for (const header of REMOTE_EVIDENCE_HEADERS) {
    if (rawHeaderExists(request.rawHeaders, header)) return false
  }
  if (exactlyOneRawHeader(request.rawHeaders, 'host') !== `${GATEWAY_HOST}:${GATEWAY_PORT}`) return false
  return sameToken(request.url, readinessRequestTarget(config.activationToken))
}

export function writeReadiness(response, ready, token) {
  response.writeHead(ready ? 200 : 503, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "frame-ancestors 'none'; base-uri 'none'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  })
  const payload = ready
    ? { version: 1, ready: true, activationToken: parseActivationToken(token) }
    : { version: 1, ready: false }
  response.end(JSON.stringify(payload))
}
