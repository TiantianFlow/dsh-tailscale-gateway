import assert from 'node:assert/strict'
import test from 'node:test'
import { createTrustedHeaderAuth, TAILSCALE_HEADER_PROFILE } from '../src/auth/trusted-header.mjs'
import { authorizeRequest } from '../src/core/authorize.mjs'
import { assertSafeConfig } from '../src/core/config.mjs'
import { GATEWAY_HOST, UPSTREAM_AUTHORITY, UPSTREAM_ORIGIN } from '../src/core/constants.mjs'
import { rewriteDownstreamHeaders, rewriteUpstreamHeaders, rewriteWebSocketHeaders } from '../src/core/headers.mjs'
import { normalizedProxyPath } from '../src/core/origin.mjs'
import { OPERATOR_LOGIN, rawHeaders, request, TAILSCALE_ORIGIN, tailscaleConfig } from './helpers.mjs'

function config() {
  return assertSafeConfig(tailscaleConfig({
    auth: {
      mode: 'trusted-header',
      trustedPrincipals: [OPERATOR_LOGIN, 'login:admin@example.invalid'],
    },
  }))
}

function authFor(safe) {
  return createTrustedHeaderAuth({
    profile: TAILSCALE_HEADER_PROFILE,
    trustedPrincipals: safe.auth.trustedPrincipals,
  })
}

test('the gateway requires a loopback peer, one exact raw Tailscale login, and one canonical Host', async () => {
  const safe = config()
  const auth = authFor(safe)
  assert.equal((await authorizeRequest(request(), safe, auth)).ok, true)
  assert.equal((await authorizeRequest(request({ rawHeaders: rawHeaders({ login: 'OPERATOR@example.invalid' }) }), safe, auth)).ok, false)
  assert.equal((await authorizeRequest(request({ rawHeaders: rawHeaders({ login: 'not-allowed@example.invalid' }) }), safe, auth)).ok, false)
  assert.equal((await authorizeRequest(request({ rawHeaders: rawHeaders({ extra: ['tailscale-user-login', 'admin@example.invalid'] }) }), safe, auth)).ok, false)
  assert.equal((await authorizeRequest(request({ rawHeaders: rawHeaders({ host: 'gateway.example-tailnet.ts.net' }) }), safe, auth)).ok, false)
  assert.equal((await authorizeRequest(request({ remoteAddress: '::1' }), safe, auth)).ok, false)
  assert.equal((await authorizeRequest(request({ remoteAddress: '203.0.113.2' }), safe, auth)).ok, false)
})

test('origin policy protects unsafe HTTP, APIs, WebSockets, and cross-site fetches', async () => {
  const safe = config()
  const auth = authFor(safe)
  assert.equal((await authorizeRequest(request({ method: 'GET', url: '/assets/app.js' }), safe, auth)).ok, true)
  assert.equal((await authorizeRequest(request({ method: 'POST', url: '/' }), safe, auth)).ok, false)
  assert.equal((await authorizeRequest(request({
    method: 'POST', url: '/', rawHeaders: rawHeaders({ origin: TAILSCALE_ORIGIN, fetchSite: 'same-origin' }),
  }), safe, auth)).ok, true)
  assert.equal((await authorizeRequest(request({ method: 'GET', url: '/api/settings' }), safe, auth)).ok, false)
  assert.equal((await authorizeRequest(request({
    method: 'GET', url: '/api/settings', rawHeaders: rawHeaders({ origin: TAILSCALE_ORIGIN }),
  }), safe, auth)).ok, true)
  assert.equal((await authorizeRequest(request({ method: 'GET', url: '/socket' }), safe, auth, { websocket: true })).ok, false)
  assert.equal((await authorizeRequest(request({
    method: 'GET', url: '/socket', rawHeaders: rawHeaders({ origin: TAILSCALE_ORIGIN }),
  }), safe, auth, { websocket: true })).ok, true)
  assert.equal((await authorizeRequest(request({ rawHeaders: rawHeaders({ fetchSite: 'cross-site' }) }), safe, auth)).ok, false)
  assert.equal((await authorizeRequest(request({
    rawHeaders: rawHeaders({ fetchSite: 'same-origin', extra: ['Sec-Fetch-Site', 'cross-site'] }),
  }), safe, auth)).ok, false)
  assert.equal((await authorizeRequest(request({ rawHeaders: rawHeaders({ origin: 'https://evil.example.invalid' }) }), safe, auth)).ok, false)
  assert.equal((await authorizeRequest(request({
    rawHeaders: rawHeaders({ origin: TAILSCALE_ORIGIN, extra: ['Origin', TAILSCALE_ORIGIN] }),
  }), safe, auth)).ok, false)
})

test('proxy targets reject CONNECT, absolute forms, and origin escapes', () => {
  assert.equal(normalizedProxyPath('GET', '/a?b=c', TAILSCALE_ORIGIN), '/a?b=c')
  assert.equal(normalizedProxyPath('CONNECT', 'example.invalid:443', TAILSCALE_ORIGIN), undefined)
  assert.equal(normalizedProxyPath('GET', 'http://127.0.0.1:3080/', TAILSCALE_ORIGIN), undefined)
  assert.equal(normalizedProxyPath('GET', '//evil.example.invalid/', TAILSCALE_ORIGIN), undefined)
  assert.equal(normalizedProxyPath('GET', '/\\evil.example.invalid', TAILSCALE_ORIGIN), undefined)
  assert.equal(normalizedProxyPath('GET', '', TAILSCALE_ORIGIN), undefined)
})

test('HTTP upstream header rewrite removes client credentials, identity, and proxy headers', () => {
  const headers = rewriteUpstreamHeaders({
    host: 'gateway.example-tailnet.ts.net:8443',
    origin: TAILSCALE_ORIGIN,
    authorization: 'Bearer browser-token',
    cookie: '__Host-dsh-gateway-session=abc; session=browser-cookie',
    forwarded: 'for=203.0.113.1',
    'x-forwarded-for': '203.0.113.1',
    'x-api-key': 'do-not-forward',
    'tailscale-user-login': 'operator@example.invalid',
    'tailscale-app-capabilities': '{}',
    'cf-access-jwt-assertion': 'header.payload.sig',
    connection: 'keep-alive, x-untrusted-hop',
    'x-untrusted-hop': 'bad',
    accept: 'application/json',
  }, { extraStripNames: ['tailscale-user-login'] })
  assert.deepEqual(headers, {
    accept: 'application/json',
    host: UPSTREAM_AUTHORITY,
    origin: UPSTREAM_ORIGIN,
  })
})

test('WebSocket rewriting uses only handshake headers', () => {
  const headers = rewriteWebSocketHeaders({
    cookie: 'session=browser-cookie',
    authorization: 'Bearer browser-token',
    'tailscale-user-login': 'operator@example.invalid',
    'cf-access-jwt-assertion': 'header.payload.sig',
    'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
    'sec-websocket-version': '13',
    'sec-websocket-protocol': 'dsh-v1',
    'sec-websocket-extensions': 'permessage-deflate',
    'x-forwarded-for': '203.0.113.1',
  })
  assert.deepEqual(headers, {
    'sec-websocket-key': 'dGhlIHNhbXBsZSBub25jZQ==',
    'sec-websocket-version': '13',
    'sec-websocket-protocol': 'dsh-v1',
    'sec-websocket-extensions': 'permessage-deflate',
    host: UPSTREAM_AUTHORITY,
    origin: UPSTREAM_ORIGIN,
    connection: 'Upgrade',
    upgrade: 'websocket',
  })
})

test('downstream headers cannot create browser credentials or cross-origin authority', () => {
  const headers = rewriteDownstreamHeaders({
    'set-cookie': ['session=from-upstream'],
    'www-authenticate': 'Basic realm="DSH"',
    'access-control-allow-origin': '*',
    connection: 'keep-alive',
    'x-frame-options': 'SAMEORIGIN',
    location: 'http://127.0.0.1:3080/api/redirect?next=1',
    'content-type': 'application/json',
  }, TAILSCALE_ORIGIN)
  assert.equal(headers['set-cookie'], undefined)
  assert.equal(headers['www-authenticate'], undefined)
  assert.equal(headers['access-control-allow-origin'], undefined)
  assert.equal(headers.location, `${TAILSCALE_ORIGIN}/api/redirect?next=1`)
  assert.equal(headers['content-security-policy'], "frame-ancestors 'none'; base-uri 'none'")
  assert.equal(headers['x-frame-options'], 'DENY')
})

test('auth exceptions become denial, never anonymous success', async () => {
  const safe = config()
  const exploding = {
    authenticate: async () => { throw new Error('boom') },
  }
  const verdict = await authorizeRequest(request(), safe, exploding)
  assert.equal(verdict.ok, false)
  assert.equal(verdict.reasonCode, 'auth_exception')
  assert.equal(verdict.principal, undefined)
})

test('reserved gateway paths are not proxied to DSH', async () => {
  const safe = config()
  const auth = authFor(safe)
  assert.equal((await authorizeRequest(request({ url: '/.dsh-gateway/ready' }), safe, auth)).ok, false)
  assert.equal((await authorizeRequest(request({ url: '/.dsh-gateway/login' }), safe, auth)).ok, false)
  void GATEWAY_HOST
})
