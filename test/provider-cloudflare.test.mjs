import assert from 'node:assert/strict'
import test from 'node:test'
import { exportJWK, generateKeyPair } from 'jose'
import { assertSafeConfig } from '../src/core/config.mjs'
import { cloudflareAccessProvider, probeAccessAttachment } from '../src/providers/cloudflare-access.mjs'
import { APPLICATION_AUDIENCE, cloudflareConfig, TEAM_ORIGIN } from './helpers.mjs'

async function jwk() {
  const pair = await generateKeyPair('RS256', { extractable: true })
  return { ...await exportJWK(pair.publicKey), kid: 'current', alg: 'RS256', use: 'sig' }
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

test('Cloudflare adapter is verify-only and never persists API credentials', async () => {
  const key = await jwk()
  const config = assertSafeConfig(cloudflareConfig())
  const runtime = { fetchImpl: async () => jsonResponse({ keys: [key] }) }
  const observed = await cloudflareAccessProvider.inspect(config, runtime)
  assert.equal(observed.kind, 'verify-only')
  const plan = cloudflareAccessProvider.plan(config, observed)
  assert.equal(plan.kind, 'unchanged')
  const applied = await cloudflareAccessProvider.apply(config, plan, runtime)
  assert.equal(applied.action, 'unchanged')
  const verified = await cloudflareAccessProvider.verify(config, runtime)
  assert.equal(verified.ok, true)
  assert.deepEqual(cloudflareAccessProvider.requiredExecutables(), [])
  assert.equal(JSON.stringify(config).includes('apiToken'), false)
  assert.equal(JSON.stringify(config).includes('CF_API'), false)
  void APPLICATION_AUDIENCE
  void TEAM_ORIGIN
})

test('missing signing metadata, mismatched ensure mode, and JWKS failure fail closed', async () => {
  const config = assertSafeConfig(cloudflareConfig())
  const failing = await cloudflareAccessProvider.inspect(config, {
    fetchImpl: async () => { throw new Error('network') },
  })
  assert.equal(failing.kind, 'conflict')
  const verified = await cloudflareAccessProvider.verify(config, {
    fetchImpl: async () => new Response('nope', { status: 500, headers: { 'content-type': 'application/json' } }),
  })
  assert.equal(verified.ok, false)
})

test('Access probe distinguishes a gateway 403 from an Access challenge and otherwise stays uncertain', async () => {
  const unprotected = await probeAccessAttachment('https://dsh.example.invalid', {
    fetchImpl: async () => new Response('403 Forbidden\n', { status: 403 }),
  })
  assert.equal(unprotected.kind, 'unprotected')

  const challenge = await probeAccessAttachment('https://dsh.example.invalid', {
    fetchImpl: async () => new Response('login', {
      status: 302,
      headers: { location: 'https://team.example.invalid/cdn-cgi/access/login' },
    }),
  })
  assert.equal(challenge.kind, 'access-challenge')

  const uncertain = await probeAccessAttachment('https://dsh.example.invalid', {
    fetchImpl: async () => { throw new Error('dns') },
  })
  assert.equal(uncertain.kind, 'uncertain')
})

test('quick tunnels are rejected by config before the adapter runs', () => {
  assert.throws(() => assertSafeConfig(cloudflareConfig({
    externalOrigin: 'https://preview.trycloudflare.com',
  })), /quick tunnels/)
})
