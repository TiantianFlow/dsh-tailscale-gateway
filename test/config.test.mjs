import assert from 'node:assert/strict'
import test from 'node:test'
import { assertSafeConfig } from '../src/core/config.mjs'
import { GATEWAY_HOST, GATEWAY_PORT } from '../src/core/constants.mjs'
import { cloudflareConfig, TAILSCALE_ORIGIN, tailscaleConfig } from './helpers.mjs'

test('enabled Tailscale configuration pins loopback endpoints and rejects overrides', () => {
  const safe = assertSafeConfig(tailscaleConfig())
  assert.equal(safe.listenHost, GATEWAY_HOST)
  assert.equal(safe.listenPort, GATEWAY_PORT)
  assert.deepEqual(safe.upstream, { host: '127.0.0.1', port: 3080 })
  assert.equal(safe.externalOrigin, TAILSCALE_ORIGIN)
  assert.equal(safe.auth.mode, 'trusted-header')
  assert.deepEqual(assertSafeConfig({ enabled: false }), { enabled: false })
  assert.throws(() => assertSafeConfig(tailscaleConfig({ externalOrigin: 'http://gateway.example-tailnet.ts.net:8443' })), /HTTPS/)
  assert.throws(() => assertSafeConfig(tailscaleConfig({ externalOrigin: 'https://gateway.example.invalid:8443' })), /\.ts\.net/)
  assert.throws(() => assertSafeConfig(tailscaleConfig({ listenHost: '0.0.0.0' })), /must not contain listenHost/)
  assert.throws(() => assertSafeConfig(tailscaleConfig({ upstream: { host: 'localhost', port: 1 } })), /must not contain upstream/)
  assert.throws(() => assertSafeConfig(tailscaleConfig({ headerName: 'X-User' })), /must not contain headerName/)
  assert.throws(() => assertSafeConfig(tailscaleConfig({ publicOrigin: TAILSCALE_ORIGIN })), /must not contain publicOrigin/)
  assert.throws(() => assertSafeConfig(tailscaleConfig({ tls: {} })), /must not contain tls/)
  assert.throws(() => assertSafeConfig(tailscaleConfig({ funnel: true })), /must not contain funnel/)
  assert.throws(() => assertSafeConfig(tailscaleConfig({ extra: true })), /unsupported configuration key/)
})

test('empty, duplicate, invalid, and wrong-namespace principal allowlists fail', () => {
  assert.throws(() => assertSafeConfig(tailscaleConfig({ auth: { mode: 'trusted-header', trustedPrincipals: [] } })), /at least one/)
  assert.throws(() => assertSafeConfig(tailscaleConfig({
    auth: { mode: 'trusted-header', trustedPrincipals: ['login:operator@example.invalid', 'login:operator@example.invalid'] },
  })), /duplicates/)
  assert.throws(() => assertSafeConfig(tailscaleConfig({
    auth: { mode: 'trusted-header', trustedPrincipals: ['operator@example.invalid'] },
  })), /login:/)
  assert.throws(() => assertSafeConfig(tailscaleConfig({
    auth: { mode: 'trusted-header', trustedPrincipals: ['email:operator@example.invalid'] },
  })), /login:/)
})

test('incompatible provider/auth pairings and easytier fail before bind', () => {
  assert.throws(() => assertSafeConfig(tailscaleConfig({
    auth: { mode: 'signed-jwt', trustedPrincipals: ['email:operator@example.invalid'] },
  })), /trusted-header/)
  assert.throws(() => assertSafeConfig(tailscaleConfig({
    auth: { mode: 'gateway-credential', trustedPrincipals: ['credential:operator-1'], credentialStorePath: '/path/to/dsh-gateway/credentials.json' },
  })), /trusted-header/)
  assert.throws(() => assertSafeConfig({
    enabled: true,
    externalOrigin: 'https://gateway.example.invalid:8443',
    provider: { type: 'easytier', routeManagement: 'verify-only', forwardName: 'dsh-gateway' },
    auth: { mode: 'gateway-credential', trustedPrincipals: ['credential:operator-1'], credentialStorePath: '/path/to/dsh-gateway/credentials.json' },
  }), /easytier is not supported/)
  assert.throws(() => assertSafeConfig({
    enabled: true,
    externalOrigin: 'https://gateway.example.invalid:8443',
    provider: { type: 'headscale' },
    auth: { mode: 'trusted-header', trustedPrincipals: ['login:operator@example.invalid'] },
  }), /tailscale-serve or cloudflare-access/)
})

test('Cloudflare configuration requires verify-only, team origin, audience, and rejects quick tunnels', () => {
  const safe = assertSafeConfig(cloudflareConfig())
  assert.equal(safe.provider.type, 'cloudflare-access')
  assert.equal(safe.provider.routeManagement, 'verify-only')
  assert.equal(safe.auth.mode, 'signed-jwt')
  assert.throws(() => assertSafeConfig(cloudflareConfig({
    provider: { type: 'cloudflare-access', routeManagement: 'ensure', teamOrigin: 'https://team.example.invalid', applicationAudience: 'aud' },
  })), /verify-only/)
  assert.throws(() => assertSafeConfig(cloudflareConfig({
    externalOrigin: 'https://random.trycloudflare.com',
  })), /quick tunnels/)
  assert.throws(() => assertSafeConfig(cloudflareConfig({
    provider: { type: 'cloudflare-access', routeManagement: 'verify-only', jwksUrl: 'https://team.example.invalid/cdn-cgi/access/certs', teamOrigin: 'https://team.example.invalid', applicationAudience: 'aud' },
  })), /jwksUrl/)
  assert.throws(() => assertSafeConfig(cloudflareConfig({
    provider: { type: 'cloudflare-access', routeManagement: 'verify-only', teamOrigin: 'https://team.example.invalid' },
  })), /applicationAudience/)
  assert.deepEqual(assertSafeConfig(cloudflareConfig({ activationToken: 'A'.repeat(43) })).activationToken, 'A'.repeat(43))
  assert.throws(() => assertSafeConfig(cloudflareConfig({ activationToken: 'too-short' })), /activationToken/)
})
