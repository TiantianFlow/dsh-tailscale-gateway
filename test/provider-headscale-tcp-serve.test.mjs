import assert from 'node:assert/strict'
import test from 'node:test'
import { start } from '../src/core/server.mjs'
import {
  classifyTcpServeStatus,
  describeTcpServeStatus,
  ensureHeadscaleTcpServe,
  headscaleTcpServeProvider,
  tcpServeArgv,
  tcpServeRoute,
  TCP_SERVE_PROXY,
} from '../src/providers/headscale-tcp-serve.mjs'
import { stubAuth } from './helpers.mjs'

const ORIGIN = 'https://gateway.example.invalid:8443'
const route = tcpServeRoute(ORIGIN)

function exactStatus(overrides = {}) {
  return {
    TCP: { '8443': { TCPForward: '127.0.0.1:3088' } },
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

test('TCP Serve create argv is the pinned --tcp --bg spelling', () => {
  assert.deepEqual(tcpServeArgv(8443), ['serve', '--tcp', '8443', '--bg', TCP_SERVE_PROXY])
  assert.deepEqual(tcpServeArgv(443), ['serve', '--tcp', '443', '--bg', 'tcp://127.0.0.1:3088'])
})

test('an exact existing private TCP forward is a no-op', async () => {
  const script = scriptedRunner([commandResult(exactStatus())])
  const result = await ensureHeadscaleTcpServe({ binary: '/usr/local/bin/tailscale', externalOrigin: ORIGIN, run: script.run })
  assert.equal(result.action, 'unchanged')
  assert.deepEqual(result.route, route)
  assert.deepEqual(script.calls, [{ binary: '/usr/local/bin/tailscale', argv: ['serve', 'status', '--json'] }])
})

test('TCP Serve management requires the pre-resolved absolute executable path', async () => {
  await assert.rejects(
    ensureHeadscaleTcpServe({ binary: 'tailscale', externalOrigin: ORIGIN, run: async () => { throw new Error('must not run') } }),
    /absolute executable/,
  )
})

test('an absent TCP route is configured then re-read and verified', async () => {
  const script = scriptedRunner([
    commandResult({}),
    { exitCode: 0, stdout: '', stderr: '' },
    commandResult(exactStatus()),
  ])
  const result = await ensureHeadscaleTcpServe({ binary: '/usr/local/bin/tailscale', externalOrigin: ORIGIN, run: script.run })
  assert.equal(result.action, 'configured')
  assert.deepEqual(script.calls, [
    { binary: '/usr/local/bin/tailscale', argv: ['serve', 'status', '--json'] },
    { binary: '/usr/local/bin/tailscale', argv: tcpServeArgv(8443) },
    { binary: '/usr/local/bin/tailscale', argv: ['serve', 'status', '--json'] },
  ])
})

test('same-port, wrong-target, HTTPS/Web, extra-option, and Funnel conflicts refuse mutation', async () => {
  const conflicts = [
    { TCP: { '8443': { TCPForward: '203.0.113.1:3088' } } },
    { TCP: { '8443': { TCPForward: 'localhost:3088' } } },
    { TCP: { '8443': { HTTPS: true } } },
    {
      TCP: { '8443': { HTTPS: true } },
      Web: { 'gateway.example.invalid:8443': { Handlers: { '/': { Proxy: 'http://127.0.0.1:3088' } } } },
    },
    { Web: { 'gateway.example.invalid:8443': { Handlers: { '/': { Proxy: 'http://127.0.0.1:3088' } } } } },
    { TCP: { '8443': { TCPForward: '127.0.0.1:3088', TerminateTLS: 'gateway.example.invalid' } } },
    { TCP: { '8443': { TCPForward: '127.0.0.1:3088', Extra: true } } },
    { TCP: { '8443': { TCPForward: '127.0.0.1:3088' } }, AllowFunnel: { '8443': true } },
    { TCP: { '8443': { TCPForward: '127.0.0.1:3088' } }, '#AllowFunnel': { 'gateway.example.invalid:8443': true } },
    { Funnel: true },
    { TCP: { '8443': 'forward' } },
  ]
  for (const status of conflicts) {
    const script = scriptedRunner([commandResult(status)])
    await assert.rejects(
      ensureHeadscaleTcpServe({ binary: '/usr/local/bin/tailscale', externalOrigin: ORIGIN, run: script.run }),
      /conflict/i,
    )
    assert.equal(script.calls.length, 1)
    assert.deepEqual(script.calls[0].argv, ['serve', 'status', '--json'])
  }
})

test('invalid JSON, unknown shape, command failure, and unverifiable post-state never claim success', async () => {
  const invalid = scriptedRunner([{ exitCode: 0, stdout: 'not json', stderr: '' }])
  await assert.rejects(ensureHeadscaleTcpServe({ binary: '/usr/local/bin/tailscale', externalOrigin: ORIGIN, run: invalid.run }), /valid JSON/)

  await assert.throws(() => classifyTcpServeStatus([], ORIGIN), /not a JSON object/)
  await assert.throws(() => classifyTcpServeStatus({ Web: [] }, ORIGIN), /invalid Web/)
  await assert.throws(() => classifyTcpServeStatus({ TCP: [] }, ORIGIN), /invalid TCP/)

  const unavailable = scriptedRunner([{ exitCode: 1, stdout: '', stderr: 'tailscaled is not running' }])
  await assert.rejects(ensureHeadscaleTcpServe({ binary: '/usr/local/bin/tailscale', externalOrigin: ORIGIN, run: unavailable.run }), /tailscaled is not running/)

  const unverifiable = scriptedRunner([
    commandResult({}),
    { exitCode: 0, stdout: '', stderr: '' },
    commandResult({}),
  ])
  await assert.rejects(ensureHeadscaleTcpServe({ binary: '/usr/local/bin/tailscale', externalOrigin: ORIGIN, run: unverifiable.run }), /verification failed/)
})

test('verify-only refuses an absent TCP route without creating one', async () => {
  const script = scriptedRunner([commandResult({})])
  const config = {
    externalOrigin: ORIGIN,
    provider: { type: 'headscale-tcp-serve', routeManagement: 'verify-only' },
  }
  const observed = await headscaleTcpServeProvider.inspect(config, { tailscaleBinary: '/usr/local/bin/tailscale', run: script.run })
  const plan = headscaleTcpServeProvider.plan(config, observed)
  assert.equal(plan.kind, 'conflict')
  await assert.rejects(headscaleTcpServeProvider.apply(config, plan, { tailscaleBinary: '/usr/local/bin/tailscale', run: script.run }), /verify-only/)
  assert.equal(script.calls.length, 1)
})

test('status classification is absent, exact, or conflict and never treats unknown shapes as absent', () => {
  assert.equal(classifyTcpServeStatus({}, ORIGIN).kind, 'absent')
  assert.equal(classifyTcpServeStatus({ TCP: { '443': { TCPForward: '127.0.0.1:22' } } }, ORIGIN).kind, 'absent')
  assert.equal(classifyTcpServeStatus(exactStatus(), ORIGIN).kind, 'exact')
  assert.equal(classifyTcpServeStatus({ TCP: { '8443': { TCPForward: '203.0.113.1:3088' } } }, ORIGIN).kind, 'conflict')
  assert.equal(classifyTcpServeStatus({ AllowFunnel: { '8443': true } }, ORIGIN).kind, 'conflict')
  assert.throws(() => classifyTcpServeStatus(null, ORIGIN), /not a JSON object/)
})

test('describeTcpServeStatus reports the live TCP receipt', () => {
  const empty = describeTcpServeStatus({})
  assert.deepEqual([...empty.handlers], ['(none)'])
  assert.equal(empty.funnel, false)
  const described = describeTcpServeStatus(exactStatus({ AllowFunnel: { '443': true } }))
  assert.deepEqual([...described.handlers], ['8443 TCPForward=127.0.0.1:3088'])
  assert.equal(described.funnel, true)
})

test('identityCapability is none and requiredExecutables is tailscale', () => {
  assert.deepEqual(headscaleTcpServeProvider.identityCapability(), { kind: 'none' })
  assert.deepEqual(headscaleTcpServeProvider.requiredExecutables(), ['tailscale'])
  assert.equal(headscaleTcpServeProvider.id, 'headscale-tcp-serve')
})

test('verify returns ok only for an exact second receipt', async () => {
  const exact = scriptedRunner([commandResult(exactStatus())])
  const verified = await headscaleTcpServeProvider.verify(
    { externalOrigin: ORIGIN, provider: { type: 'headscale-tcp-serve', routeManagement: 'ensure' } },
    { tailscaleBinary: '/usr/local/bin/tailscale', run: exact.run },
  )
  assert.equal(verified.ok, true)
  assert.equal(verified.receipt.kind, 'exact')

  const absent = scriptedRunner([commandResult({})])
  const missing = await headscaleTcpServeProvider.verify(
    { externalOrigin: ORIGIN, provider: { type: 'headscale-tcp-serve', routeManagement: 'ensure' } },
    { tailscaleBinary: '/usr/local/bin/tailscale', run: absent.run },
  )
  assert.equal(missing.ok, false)
  assert.match(missing.reasonCode, /still absent/)
})

test('provider apply never issues reset, off, Funnel, or tailscaled restart argv', async () => {
  const script = scriptedRunner([
    commandResult({}),
    { exitCode: 0, stdout: '', stderr: '' },
    commandResult(exactStatus()),
  ])
  await ensureHeadscaleTcpServe({ binary: '/usr/local/bin/tailscale', externalOrigin: ORIGIN, run: script.run })
  const joined = script.calls.map(call => call.argv.join(' ')).join('\n')
  assert.doesNotMatch(joined, /\breset\b/)
  assert.doesNotMatch(joined, /\boff\b/)
  assert.doesNotMatch(joined, /funnel/i)
  assert.doesNotMatch(joined, /tailscaled/)
})

test('ensure startup closes the loopback sidecar when TCP Serve management fails', async () => {
  let closed = false
  const fakeServer = {
    once: () => fakeServer,
    listen: (_port, _host, callback) => callback(),
    close: callback => { closed = true; callback() },
  }
  const config = {
    enabled: true,
    externalOrigin: ORIGIN,
    provider: { type: 'headscale-tcp-serve', routeManagement: 'ensure' },
    identity: { identityKind: 'none' },
  }
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
