import assert from 'node:assert/strict'
import test from 'node:test'
import { createAuth } from '../src/auth/create.mjs'
import { createTrustedHeaderAuth, TAILSCALE_HEADER_PROFILE } from '../src/auth/trusted-header.mjs'
import { assertSafeConfig } from '../src/core/config.mjs'
import { rawHeaders, request, tailscaleConfig } from './helpers.mjs'

function auth() {
  return createTrustedHeaderAuth({
    profile: TAILSCALE_HEADER_PROFILE,
    trustedPrincipals: ['login:operator@example.invalid'],
  })
}

test('trusted-header denies absent, empty, malformed, oversized, duplicate, and non-allowlisted identity', async () => {
  const module = auth()
  assert.equal((await module.authenticate(request({ rawHeaders: rawHeaders({ login: null }) }))).ok, false)
  assert.equal((await module.authenticate(request({ rawHeaders: ['Host', 'gateway.example-tailnet.ts.net:8443'] }))).reasonCode, 'identity_missing_or_duplicate')
  assert.equal((await module.authenticate(request({ rawHeaders: rawHeaders({ login: '' }) }))).ok, false)
  assert.equal((await module.authenticate(request({ rawHeaders: rawHeaders({ login: 'ab' }) }))).reasonCode, 'identity_malformed')
  assert.equal((await module.authenticate(request({ rawHeaders: rawHeaders({ login: 'x'.repeat(300) }) }))).reasonCode, 'identity_malformed')
  assert.equal((await module.authenticate(request({
    rawHeaders: rawHeaders({ extra: ['Tailscale-User-Login', 'operator@example.invalid'] }),
  }))).reasonCode, 'identity_missing_or_duplicate')
  assert.equal((await module.authenticate(request({ rawHeaders: rawHeaders({ login: 'other@example.invalid' }) }))).reasonCode, 'identity_not_allowlisted')
  const ok = await module.authenticate(request())
  assert.equal(ok.ok, true)
  assert.equal(ok.principal.id, 'login:operator@example.invalid')
  assert.deepEqual(ok.consumedHeaders, ['tailscale-user-login'])
})

test('a user-configured header name is impossible and identityCapability none cannot construct the mode', async () => {
  assert.throws(() => createTrustedHeaderAuth({
    profile: { profileId: 'custom', headerName: 'x-user', principalNamespace: 'login' },
    trustedPrincipals: ['login:operator@example.invalid'],
  }), /unknown trusted-header profile/)
  const constructed = await createAuth(assertSafeConfig(tailscaleConfig()))
  assert.equal(constructed.mode, 'trusted-header')
})

test('comma-coalesced Node headers are ignored; only raw pairs count', async () => {
  const module = auth()
  const context = request({
    rawHeaders: rawHeaders({ extra: ['Tailscale-User-Login', 'other@example.invalid'] }),
    headers: { 'tailscale-user-login': 'operator@example.invalid, other@example.invalid' },
  })
  assert.equal((await module.authenticate(context)).ok, false)
})
