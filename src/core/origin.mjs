import { GATEWAY_HOST } from './constants.mjs'
import { exactlyOneRawHeader, isHeaderValue, rawHeaderPairs } from './headers.mjs'

export function isLiteralLoopbackPeer(remoteAddress) {
  return remoteAddress === GATEWAY_HOST
}

function authorityOrigin(value) {
  if (!isHeaderValue(value) || /[\s,]/.test(value)) return undefined
  try {
    const url = new URL(`https://${value}`)
    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) return undefined
    return url.origin
  } catch {
    return undefined
  }
}

export function isExpectedHost(rawHeaders, externalOrigin) {
  const host = exactlyOneRawHeader(rawHeaders, 'host')
  return authorityOrigin(host) === externalOrigin
}

export function isExpectedOrigin(rawHeaders, externalOrigin, required = false) {
  const pairs = rawHeaderPairs(rawHeaders).filter(([name]) => name === 'origin')
  if (pairs.length === 0) return !required
  return pairs.length === 1 && pairs[0][1] === externalOrigin
}

export function isAllowedFetchSite(rawHeaders) {
  const values = rawHeaderPairs(rawHeaders)
    .filter(([name]) => name === 'sec-fetch-site')
    .map(([, value]) => value)
  return values.length === 0 || (values.length === 1 && (values[0] === 'same-origin' || values[0] === 'same-site' || values[0] === 'none'))
}

export function isUnsafeMethod(method = 'GET') {
  return !['GET', 'HEAD', 'OPTIONS'].includes(String(method).toUpperCase())
}

export function isApiPath(path) {
  return path === '/api' || path.startsWith('/api/')
}

/** Reject proxy-form, CONNECT, malformed, and cross-origin request targets. */
export function normalizedProxyPath(method, requestTarget, externalOrigin) {
  if (String(method).toUpperCase() === 'CONNECT' || typeof requestTarget !== 'string' || requestTarget.length === 0) return undefined
  if (!requestTarget.startsWith('/') || requestTarget.startsWith('//') || requestTarget.includes('\\') || /[\r\n\0]/.test(requestTarget)) return undefined
  try {
    const url = new URL(requestTarget, externalOrigin)
    if (url.origin !== externalOrigin || url.hash) return undefined
    return `${url.pathname}${url.search}`
  } catch {
    return undefined
  }
}

export function httpsPortFromOrigin(externalOrigin) {
  const url = new URL(externalOrigin)
  const port = url.port === '' ? 443 : Number(url.port)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('dsh-one-gateway: externalOrigin must use an HTTPS port between 1 and 65535')
  }
  return port
}
