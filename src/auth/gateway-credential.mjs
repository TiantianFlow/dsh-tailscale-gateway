import {
  AUTH_GATEWAY_CREDENTIAL,
  LOGIN_PATH,
  MAX_LOGIN_BODY_BYTES,
  SESSION_COOKIE_NAME,
} from '../core/constants.mjs'
import { exactlyOneRawHeader, rawHeaderValues } from '../core/headers.mjs'
import { isAllowedFetchSite, isExpectedHost, isExpectedOrigin, normalizedProxyPath } from '../core/origin.mjs'
import { createLoginLimiter } from './abuse-controls.mjs'
import { denyAuth, handledResponse, notReady, okPrincipal, readyOk, unhandled } from './contract.mjs'
import { lookupCredential, readCredentialStore } from './credential-store.mjs'
import { createSessionStore } from './sessions.mjs'
import { allowlistContains } from './timing.mjs'

function sessionCookie(id) {
  return `${SESSION_COOKIE_NAME}=${id}; Path=/; Secure; HttpOnly; SameSite=Strict`
}

function parseCookiePairs(header) {
  if (typeof header !== 'string' || header.length === 0) return []
  return header.split(';').map(part => part.trim()).filter(Boolean).map(part => {
    const index = part.indexOf('=')
    if (index <= 0) return undefined
    return [part.slice(0, index).trim(), part.slice(index + 1).trim()]
  }).filter(Boolean)
}

function sessionIdFromCookies(rawHeaders) {
  const headers = rawHeaderValues(rawHeaders, 'cookie')
  if (headers.length !== 1) return { kind: headers.length === 0 ? 'missing' : 'duplicate' }
  const pairs = parseCookiePairs(headers[0])
  const matches = pairs.filter(([name]) => name === SESSION_COOKIE_NAME)
  if (matches.length !== 1) return { kind: matches.length === 0 ? 'missing' : 'duplicate' }
  const value = matches[0][1]
  if (typeof value !== 'string' || value.length < 32 || value.length > 128 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return { kind: 'malformed' }
  }
  return { kind: 'ok', value }
}

const LOGIN_PAGE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DSH One Gateway</title>
</head>
<body>
<form method="post" action="/.dsh-one-gateway/login">
<label for="credential">Credential</label>
<input id="credential" name="credential" type="password" autocomplete="off" required>
<button type="submit">Sign in</button>
</form>
</body>
</html>
`

function loginSuccessHeaders(sessionId) {
  return {
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "frame-ancestors 'none'; base-uri 'none'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Set-Cookie': sessionCookie(sessionId),
  }
}

function uniformLoginDenied(response) {
  response.writeHead(401, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "frame-ancestors 'none'; base-uri 'none'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  })
  response.end('401 Unauthorized\n')
}

function loginPage(response) {
  response.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  })
  response.end(LOGIN_PAGE_HTML)
}

function loginSucceeded(response, sessionId) {
  response.writeHead(204, loginSuccessHeaders(sessionId))
  response.end()
}

function loginFormSucceeded(response, sessionId) {
  response.writeHead(303, {
    ...loginSuccessHeaders(sessionId),
    Location: '/',
  })
  response.end()
}

async function readLoginBody(request) {
  const chunks = []
  let size = 0
  for await (const chunk of request) {
    size += chunk.length
    if (size > MAX_LOGIN_BODY_BYTES) {
      const error = new Error('oversized')
      error.code = 'oversized'
      throw error
    }
    chunks.push(chunk)
  }
  return Buffer.concat(chunks).toString('utf8')
}

function parseCredentialBody(contentType, body) {
  const type = String(contentType ?? '').split(';')[0].trim().toLowerCase()
  if (type === 'application/json') {
    let parsed
    try {
      parsed = JSON.parse(body)
    } catch {
      return undefined
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || typeof parsed.credential !== 'string') {
      return undefined
    }
    return parsed.credential
  }
  if (type === 'application/x-www-form-urlencoded') {
    const params = new URLSearchParams(body)
    const values = params.getAll('credential')
    return values.length === 1 ? values[0] : undefined
  }
  return undefined
}

export function createGatewayCredentialAuth({
  trustedPrincipals,
  storePath,
  loadStore = readCredentialStore,
  sessions = createSessionStore(),
  limiter = createLoginLimiter(),
  externalOrigin,
}) {
  let cachedStore
  const consumedCookies = Object.freeze([SESSION_COOKIE_NAME])

  async function store() {
    cachedStore = await loadStore(storePath)
    return cachedStore
  }

  return {
    mode: AUTH_GATEWAY_CREDENTIAL,
    async authenticate(requestContext) {
      try {
        const cookie = sessionIdFromCookies(requestContext.rawHeaders)
        if (cookie.kind !== 'ok') return denyAuth(`session_${cookie.kind}`)
        const session = sessions.get(cookie.value)
        if (!session) return denyAuth('session_invalid')
        if (!allowlistContains(trustedPrincipals, session.principalId)) return denyAuth('identity_not_allowlisted')
        const document = await store()
        const entry = document.credentials.find(item => item.principalId === session.principalId)
        if (!entry || entry.revoked === true) {
          sessions.revokePrincipal(session.principalId)
          return denyAuth('credential_revoked')
        }
        return okPrincipal({ id: session.principalId, kind: 'gateway-credential' }, { consumedCookies })
      } catch {
        return denyAuth('auth_exception')
      }
    },
    async handleReservedRequest(requestContext, request, response) {
      const path = normalizedProxyPath(requestContext.method, requestContext.url, externalOrigin)
      if (path !== LOGIN_PATH) return unhandled()
      if (!response) return unhandled()
      const sourceKey = requestContext.remoteAddress ?? 'unknown'
      if (requestContext.method === 'GET') {
        if (!isExpectedHost(requestContext.rawHeaders, externalOrigin)) {
          uniformLoginDenied(response)
          return handledResponse(response)
        }
        if (!isAllowedFetchSite(requestContext.rawHeaders)) {
          uniformLoginDenied(response)
          return handledResponse(response)
        }
        loginPage(response)
        return handledResponse(response)
      }
      if (requestContext.method !== 'POST') {
        uniformLoginDenied(response)
        return handledResponse(response)
      }
      if (!isExpectedHost(requestContext.rawHeaders, externalOrigin)) {
        uniformLoginDenied(response)
        return handledResponse(response)
      }
      if (!isExpectedOrigin(requestContext.rawHeaders, externalOrigin, true)) {
        uniformLoginDenied(response)
        return handledResponse(response)
      }
      if (!isAllowedFetchSite(requestContext.rawHeaders)) {
        uniformLoginDenied(response)
        return handledResponse(response)
      }
      const fetchSite = exactlyOneRawHeader(requestContext.rawHeaders, 'sec-fetch-site')
      if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') {
        uniformLoginDenied(response)
        return handledResponse(response)
      }
      const admitted = await limiter.admit(sourceKey)
      if (!admitted.ok) {
        uniformLoginDenied(response)
        return handledResponse(response)
      }
      try {
        const body = await readLoginBody(request)
        const secret = parseCredentialBody(request.headers?.['content-type'], body)
        if (typeof secret !== 'string' || secret.length < 32) {
          limiter.recordFailure(sourceKey)
          uniformLoginDenied(response)
          return handledResponse(response)
        }
        const document = await store()
        const entry = lookupCredential(document, secret)
        if (!entry || !allowlistContains(trustedPrincipals, entry.principalId)) {
          limiter.recordFailure(sourceKey)
          uniformLoginDenied(response)
          return handledResponse(response)
        }
        limiter.recordSuccess(sourceKey)
        const sessionId = sessions.create(entry.principalId)
        const type = String(request.headers?.['content-type'] ?? '').split(';')[0].trim().toLowerCase()
        if (type === 'application/x-www-form-urlencoded') {
          loginFormSucceeded(response, sessionId)
        } else {
          loginSucceeded(response, sessionId)
        }
        return handledResponse(response)
      } catch {
        limiter.recordFailure(sourceKey)
        if (!response.headersSent) uniformLoginDenied(response)
        return handledResponse(response)
      }
    },
    async readiness() {
      try {
        const document = await store()
        if (trustedPrincipals.length === 0) return notReady('empty_allowlist')
        return document ? readyOk() : notReady('credential_store_unreadable')
      } catch (error) {
        const message = error instanceof Error ? error.message : 'credential_store_unreadable'
        if (message.includes('permissions')) return notReady('credential_store_permissions')
        if (message.includes('malformed') || message.includes('JSON')) return notReady('credential_store_malformed')
        return notReady('credential_store_unreadable')
      }
    },
    async close() {
      await sessions.close?.()
    },
  }
}
