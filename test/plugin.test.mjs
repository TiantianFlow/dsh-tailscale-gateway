import assert from 'node:assert/strict'
import test from 'node:test'
import { apply, inject, name } from '../src/plugin.mjs'
import { HEADSCALE_ORIGIN, TAILSCALE_ORIGIN } from './helpers.mjs'

test('DSH bundle entry remains inert while disabled', () => {
  assert.equal(name, 'dsh-one-gateway')
  assert.deepEqual(inject, ['subprocess'])
  assert.doesNotThrow(() => apply({}, { enabled: false }))
})

test('ensure mode resolves Tailscale in DSH and serializes only its absolute path for the scrubbed sidecar', async () => {
  let spawned
  let resolveSpawn
  const spawnedPromise = new Promise(resolve => { resolveSpawn = resolve })
  const unresolvedDone = new Promise(() => {})
  const ctx = {
    subprocess: {
      resolveExecutable: async command => {
        if (command === 'node') return '/opt/dsh/node'
        if (command === 'tailscale') return '/opt/tailscale/bin/tailscale'
        throw new Error(`unexpected executable: ${command}`)
      },
      spawn: spec => {
        spawned = spec
        resolveSpawn()
        return {
          done: unresolvedDone,
          collected: { stderr: { readFrom: () => ({ text: '' }) } },
          terminate: () => {},
        }
      },
    },
    effect: callback => { void callback() },
  }
  apply(ctx, {
    enabled: true,
    externalOrigin: TAILSCALE_ORIGIN,
    provider: { type: 'tailscale-serve', routeManagement: 'ensure' },
    auth: { mode: 'trusted-header', trustedPrincipals: ['login:operator@example.invalid'] },
  })
  await spawnedPromise
  assert.deepEqual(spawned.argv.slice(0, 1), ['/opt/dsh/node'])
  assert.match(spawned.argv[1], /[/\\]sidecar\.mjs$/)
  assert.deepEqual(Object.keys(spawned.env).sort(), [
    'DSH_GATEWAY_CONFIG',
    'DSH_GATEWAY_TAILSCALE_BINARY',
  ])
  assert.equal(spawned.env.DSH_GATEWAY_TAILSCALE_BINARY, '/opt/tailscale/bin/tailscale')
  assert.equal(spawned.env.PATH, undefined)
})

test('headscale-tcp-serve sidecar env has only the absolute tailscale path and no Headscale token', async () => {
  let spawned
  let resolveSpawn
  const spawnedPromise = new Promise(resolve => { resolveSpawn = resolve })
  const ctx = {
    subprocess: {
      resolveExecutable: async command => {
        if (command === 'node') return '/opt/dsh/node'
        if (command === 'tailscale') return '/opt/tailscale/bin/tailscale'
        throw new Error(`unexpected executable: ${command}`)
      },
      spawn: spec => {
        spawned = spec
        resolveSpawn()
        return {
          done: new Promise(() => {}),
          collected: { stderr: { readFrom: () => ({ text: '' }) } },
          terminate: () => {},
        }
      },
    },
    effect: callback => { void callback() },
  }
  apply(ctx, {
    enabled: true,
    externalOrigin: HEADSCALE_ORIGIN,
    provider: { type: 'headscale-tcp-serve', routeManagement: 'ensure' },
    auth: {
      mode: 'gateway-credential',
      trustedPrincipals: ['credential:operator-1'],
      credentialStorePath: '/path/to/dsh-one-gateway/credentials.json',
    },
    tls: {
      certPath: '/path/to/dsh-one-gateway/cert.pem',
      keyPath: '/path/to/dsh-one-gateway/key.pem',
    },
  })
  await spawnedPromise
  assert.deepEqual(Object.keys(spawned.env).sort(), [
    'DSH_GATEWAY_CONFIG',
    'DSH_GATEWAY_TAILSCALE_BINARY',
  ])
  assert.equal(spawned.env.DSH_GATEWAY_TAILSCALE_BINARY, '/opt/tailscale/bin/tailscale')
  assert.equal(spawned.env.PATH, undefined)
  assert.equal(spawned.env.HEADSCALE_API_KEY, undefined)
  assert.equal(spawned.env.TS_API_KEY, undefined)
})

test('Cloudflare sidecar env does not inherit API tokens or extra executables', async () => {
  let spawned
  let resolveSpawn
  const spawnedPromise = new Promise(resolve => { resolveSpawn = resolve })
  const ctx = {
    subprocess: {
      resolveExecutable: async command => {
        if (command === 'node') return '/opt/dsh/node'
        throw new Error(`unexpected executable: ${command}`)
      },
      spawn: spec => {
        spawned = spec
        resolveSpawn()
        return {
          done: new Promise(() => {}),
          collected: { stderr: { readFrom: () => ({ text: '' }) } },
          terminate: () => {},
        }
      },
    },
    effect: callback => { void callback() },
  }
  apply(ctx, {
    enabled: true,
    externalOrigin: 'https://dsh.example.invalid',
    provider: {
      type: 'cloudflare-access',
      routeManagement: 'verify-only',
      teamOrigin: 'https://team.example.invalid',
      applicationAudience: 'replace-with-access-application-audience',
    },
    auth: { mode: 'signed-jwt', trustedPrincipals: ['email:operator@example.invalid'] },
  })
  await spawnedPromise
  assert.deepEqual(Object.keys(spawned.env), ['DSH_GATEWAY_CONFIG'])
})

test('HMR disposal awaits the old managed sidecar before a replacement may bind the fixed port', async () => {
  let dispose
  let releaseExit
  const done = new Promise(resolve => { releaseExit = resolve })
  const events = []
  const ctx = {
    subprocess: {
      resolveExecutable: async command => command === 'node' ? '/opt/dsh/node' : '/opt/tailscale/bin/tailscale',
      spawn: () => ({
        done,
        collected: { stderr: { readFrom: () => ({ text: '' }) } },
        terminate: async () => { events.push('terminate') },
      }),
    },
    effect: async callback => { dispose = await callback() },
  }
  apply(ctx, {
    enabled: true,
    externalOrigin: TAILSCALE_ORIGIN,
    provider: { type: 'tailscale-serve', routeManagement: 'ensure' },
    auth: { mode: 'trusted-header', trustedPrincipals: ['login:operator@example.invalid'] },
  })
  await new Promise(resolve => setImmediate(resolve))
  const teardown = dispose()
  await new Promise(resolve => setImmediate(resolve))
  assert.deepEqual(events, ['terminate'])
  let settled = false
  teardown.then(() => { settled = true })
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(settled, false)
  releaseExit({ exitCode: 0, signal: null })
  await teardown
  assert.equal(settled, true)
})
