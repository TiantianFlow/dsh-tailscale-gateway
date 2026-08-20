import assert from 'node:assert/strict'
import test from 'node:test'
import { createAuth } from '../src/auth/create.mjs'
import { assertSafeConfig, readinessRequestTarget } from '../src/core/config.mjs'
import { createGatewayServer, start } from '../src/core/server.mjs'
import {
  classifyServeStatus,
  ensureTailscaleServe,
  tailscaleServeProvider,
  tailscaleServeRoute,
} from '../src/providers/tailscale-serve.mjs'
import { stubAuth, TAILSCALE_ORIGIN, tailscaleConfig } from './helpers.mjs'

const route = tailscaleServeRoute(TAILSCALE_ORIGIN)

function exactStatus(overrides = {}) {
  return {
    TCP: { '8443': { HTTPS: true } },
    Web: {
      'gateway.example-tailnet.ts.net:8443': {
        Handlers: { '/': { Proxy: 'http://127.0.0.1:3088' } },
      },
    },
    ...overrides,
  }
}

function commandResult(status, stderr = '') {
  return { exitCode: 0, stdout: JSON.stringify(status), stderr }
}

function scriptedRunner(results) {
  const calls = []
  return {
    calls,
    run: async (binary, argv) => {
      calls.push({ binary, argv })
      const result = results.shift()
      if (result instanceof Error) throw result
      return result
    },
  }
}

test('an exact existing private route is a no-op', async () => {
  const script = scriptedRunner([commandResult(exactStatus())])
  const result = await ensureTailscaleServe({ binary: '/usr/local/bin/tailscale', externalOrigin: TAILSCALE_ORIGIN, run: script.run })
  assert.equal(result.action, 'unchanged')
  assert.deepEqual(result.route, route)
  assert.deepEqual(script.calls, [{ binary: '/usr/local/bin/tailscale', argv: ['serve', 'status', '--json'] }])
})

test('Serve management requires the pre-resolved absolute executable path', async () => {
  await assert.rejects(
    ensureTailscaleServe({ binary: 'tailscale', externalOrigin: TAILSCALE_ORIGIN, run: async () => { throw new Error('must not run') } }),
    /absolute executable/,
  )
})

test('an absent route is configured with private Serve then re-read and verified', async () => {
  const script = scriptedRunner([
    commandResult({}),
    { exitCode: 0, stdout: '', stderr: '' },
    commandResult(exactStatus()),
  ])
  const result = await ensureTailscaleServe({ binary: '/usr/local/bin/tailscale', externalOrigin: TAILSCALE_ORIGIN, run: script.run })
  assert.equal(result.action, 'configured')
  assert.deepEqual(script.calls, [
    { binary: '/usr/local/bin/tailscale', argv: ['serve', 'status', '--json'] },
    { binary: '/usr/local/bin/tailscale', argv: ['serve', '--https=8443', '--bg', 'http://127.0.0.1:3088'] },
    { binary: '/usr/local/bin/tailscale', argv: ['serve', 'status', '--json'] },
  ])
})

test('a root handler, port, or extra handler conflict is rejected without mutation', async () => {
  const conflicts = [
    exactStatus({ Web: { 'gateway.example-tailnet.ts.net:8443': { Handlers: { '/': { Proxy: 'http://127.0.0.1:9999' } } } } }),
    { TCP: { '8443': { HTTPS: false } } },
    exactStatus({ Web: { 'gateway.example-tailnet.ts.net:8443': { Handlers: { '/': { Proxy: 'http://127.0.0.1:3088' }, '/other': { Proxy: 'http://127.0.0.1:9000' } } } } }),
    exactStatus({ Web: { 'other.example-tailnet.ts.net:8443': { Handlers: { '/': { Proxy: 'http://127.0.0.1:3088' } } } } }),
  ]
  for (const status of conflicts) {
    const script = scriptedRunner([commandResult(status)])
    await assert.rejects(
      ensureTailscaleServe({ binary: '/usr/local/bin/tailscale', externalOrigin: TAILSCALE_ORIGIN, run: script.run }),
      /conflict/i,
    )
    assert.equal(script.calls.length, 1)
    assert.deepEqual(script.calls[0].argv, ['serve', 'status', '--json'])
  }
})

test('invalid, Funnel, command failure, and unverifiable status never claim success', async () => {
  const invalid = scriptedRunner([{ exitCode: 0, stdout: 'not json', stderr: '' }])
  await assert.rejects(ensureTailscaleServe({ binary: '/usr/local/bin/tailscale', externalOrigin: TAILSCALE_ORIGIN, run: invalid.run }), /valid JSON/)

  const funnel = scriptedRunner([commandResult(exactStatus({ AllowFunnel: { 'gateway.example-tailnet.ts.net:8443': true } }))])
  await assert.rejects(ensureTailscaleServe({ binary: '/usr/local/bin/tailscale', externalOrigin: TAILSCALE_ORIGIN, run: funnel.run }), /Funnel/)

  const legacyFunnel = scriptedRunner([commandResult(exactStatus({ '#AllowFunnel': { 'gateway.example-tailnet.ts.net:8443': true } }))])
  await assert.rejects(ensureTailscaleServe({ binary: '/usr/local/bin/tailscale', externalOrigin: TAILSCALE_ORIGIN, run: legacyFunnel.run }), /Funnel/)

  const unavailable = scriptedRunner([{ exitCode: 1, stdout: '', stderr: 'tailscaled is not running' }])
  await assert.rejects(ensureTailscaleServe({ binary: '/usr/local/bin/tailscale', externalOrigin: TAILSCALE_ORIGIN, run: unavailable.run }), /tailscaled is not running/)

  const unverifiable = scriptedRunner([
    commandResult({}),
    { exitCode: 0, stdout: '', stderr: '' },
    commandResult({}),
  ])
  await assert.rejects(ensureTailscaleServe({ binary: '/usr/local/bin/tailscale', externalOrigin: TAILSCALE_ORIGIN, run: unverifiable.run }), /verification failed/)
})

test('verify-only refuses an absent route without creating one', async () => {
  const script = scriptedRunner([commandResult({})])
  const config = assertSafeConfig(tailscaleConfig({
    provider: { type: 'tailscale-serve', routeManagement: 'verify-only' },
  }))
  const observed = await tailscaleServeProvider.inspect(config, { tailscaleBinary: '/usr/local/bin/tailscale', run: script.run })
  const plan = tailscaleServeProvider.plan(config, observed)
  assert.equal(plan.kind, 'conflict')
  await assert.rejects(tailscaleServeProvider.apply(config, plan, { tailscaleBinary: '/usr/local/bin/tailscale', run: script.run }), /verify-only/)
  assert.equal(script.calls.length, 1)
})

test('status classification rejects unexpected funnel and listener state', () => {
  assert.equal(classifyServeStatus({}, TAILSCALE_ORIGIN).kind, 'absent')
  assert.equal(classifyServeStatus(exactStatus(), TAILSCALE_ORIGIN).kind, 'exact')
  assert.equal(classifyServeStatus({ AllowFunnel: { '8443': true } }, TAILSCALE_ORIGIN).kind, 'conflict')
  assert.throws(() => classifyServeStatus({ Web: [] }, TAILSCALE_ORIGIN), /invalid Web/)
})

test('ensure mode manages Serve only after an actual sidecar bind with a host-resolved binary', async () => {
  let bound = false
  let closed = false
  let observedBinary
  const fakeServer = {
    once: () => fakeServer,
    listen: (_port, _host, callback) => { bound = true; callback() },
    close: callback => { closed = true; callback() },
  }
  const config = assertSafeConfig(tailscaleConfig())
  const server = await start(config, {
    auth: stubAuth(),
    createGateway: () => fakeServer,
    runtime: {
      tailscaleBinary: '/opt/tailscale/tailscale',
      run: async () => commandResult(exactStatus()),
    },
    logger: { log: () => {} },
  })
  assert.equal(server, fakeServer)
  assert.equal(bound, true)
  assert.equal(closed, false)
  void observedBinary
})

test('ensure startup closes the loopback sidecar when CLI management fails', async () => {
  let closed = false
  const fakeServer = {
    once: () => fakeServer,
    listen: (_port, _host, callback) => callback(),
    close: callback => { closed = true; callback() },
  }
  const config = assertSafeConfig(tailscaleConfig())
  await assert.rejects(start(config, {
    auth: stubAuth(),
    createGateway: () => fakeServer,
    runtime: {
      tailscaleBinary: '/opt/tailscale/tailscale',
      run: async () => { throw new Error('tailscale not found') },
    },
    logger: { log: () => {} },
  }), /after the loopback sidecar bound/)
  assert.equal(closed, true)
})

test('the setup readiness endpoint is token-scoped, loopback-only, and never proxies a remote request', async () => {
  const token = 'A'.repeat(43)
  const safe = assertSafeConfig(tailscaleConfig({ activationToken: token }))
  const auth = await createAuth(safe)
  let ready = false
  const server = createGatewayServer(safe, { isReady: () => ready, auth })
  const invoke = rawHeaders => {
    const result = {}
    server.emit('request', {
      method: 'GET',
      url: readinessRequestTarget(token),
      rawHeaders,
      socket: { remoteAddress: '127.0.0.1' },
    }, {
      writeHead: (statusCode, headers) => { result.statusCode = statusCode; result.headers = headers },
      end: body => { result.body = body },
    })
    return result
  }
  const localHeaders = ['Host', '127.0.0.1:3088']
  const beforeEnsure = invoke(localHeaders)
  assert.equal(beforeEnsure.statusCode, 503)
  ready = true
  const localReady = invoke(localHeaders)
  assert.equal(localReady.statusCode, 200)
  assert.deepEqual(JSON.parse(localReady.body), { version: 1, ready: true, activationToken: token })
  const serveRequest = invoke([...localHeaders, 'Tailscale-User-Login', 'operator@example.invalid'])
  assert.equal(serveRequest.statusCode, 404)
})
