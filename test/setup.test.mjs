import assert from 'node:assert/strict'
import test from 'node:test'
import { BASELINE_INSTANCE_ID, PACKAGE_NAME, USER_INSTANCE_ID } from '../src/core/constants.mjs'
import { classifyControlPlane, detectProviders, refineDetectedProviders, selectProvider } from '../src/setup/detect.mjs'
import { parseArgs } from '../src/setup/cli.mjs'
import {
  createCloudflarePlan,
  createHeadscaleTcpPlan,
  createTailscalePlan,
  inferHeadscaleNode,
  inferNodeIdentity,
  selectInitialOrigin,
  selectTcpOrigin,
} from '../src/setup/plan.mjs'
import { appendProfileEntry, renderProfileEntry } from '../src/setup/profile.mjs'
import { APPLICATION_AUDIENCE, TEAM_ORIGIN } from './helpers.mjs'

function tailscaleStatus(overrides = {}) {
  return {
    Self: {
      DNSName: 'gateway.example-tailnet.ts.net.',
      UserID: 42,
    },
    User: {
      42: { LoginName: 'owner@example.invalid' },
    },
    ...overrides,
  }
}

function unrelated443Route() {
  return {
    TCP: { '443': { HTTPS: true } },
    Web: {
      'gateway.example-tailnet.ts.net:443': {
        Handlers: { '/': { Proxy: 'http://127.0.0.1:9000' } },
      },
    },
  }
}

test('setup derives the owner login through Self.UserID and removes the DNS trailing dot', () => {
  assert.deepEqual(inferNodeIdentity(tailscaleStatus()), {
    hostname: 'gateway.example-tailnet.ts.net',
    login: 'login:owner@example.invalid',
    loginValue: 'owner@example.invalid',
  })
  assert.throws(
    () => inferNodeIdentity(tailscaleStatus({ Self: { DNSName: 'gateway.example-tailnet.ts.net.', UserID: 42, Tags: ['tag:server'] } })),
    /tagged Tailscale node/,
  )
  assert.throws(() => inferNodeIdentity(tailscaleStatus({ User: {} })), /owner login/)
})

test('setup reuses an exact route or selects an absent safe port without overwriting conflicts', () => {
  const exact8443 = {
    TCP: { '8443': { HTTPS: true } },
    Web: {
      'gateway.example-tailnet.ts.net:8443': {
        Handlers: { '/': { Proxy: 'http://127.0.0.1:3088' } },
      },
    },
  }
  assert.deepEqual(selectInitialOrigin('gateway.example-tailnet.ts.net', exact8443, [443, 8443]), {
    externalOrigin: 'https://gateway.example-tailnet.ts.net:8443', routeState: 'exact',
  })
  assert.deepEqual(selectInitialOrigin('gateway.example-tailnet.ts.net', unrelated443Route(), [443, 8443]), {
    externalOrigin: 'https://gateway.example-tailnet.ts.net:8443', routeState: 'absent',
  })
  assert.throws(
    () => selectInitialOrigin('gateway.example-tailnet.ts.net', unrelated443Route(), [443]),
    /no safe HTTPS port/,
  )
})

test('setup creates an editable one-owner initial profile entry with ensure mode', () => {
  const plan = createTailscalePlan(tailscaleStatus(), unrelated443Route(), { ports: [443, 8443] })
  assert.equal(plan.externalOrigin, 'https://gateway.example-tailnet.ts.net:8443')
  assert.equal(plan.trustedPrincipal, 'login:owner@example.invalid')
  assert.equal(plan.routeState, 'absent')
  const entry = renderProfileEntry(plan.config)
  assert.match(entry, new RegExp(`- id: ${USER_INSTANCE_ID}`))
  assert.match(entry, new RegExp(`name: ${PACKAGE_NAME}`))
  assert.doesNotMatch(entry, new RegExp(`^- id: ${BASELINE_INSTANCE_ID}$`, 'm'))
  assert.match(entry, /trustedPrincipals:/)
  assert.match(entry, /login:owner@example\.invalid/)
  assert.match(entry, /routeManagement: ensure/)
  assert.match(entry, /mode: trusted-header/)
  assert.doesNotMatch(entry, /listenHost/)
  assert.doesNotMatch(entry, /headerName/)
})

test('setup appends a distinct boot-time insert without rewriting a compatible user profile', () => {
  const entry = renderProfileEntry(createTailscalePlan(tailscaleStatus(), {}, { ports: [443] }).config)
  const profile = '# user configuration\n- id: agent-default-model\n  config:\n    model: example\n'
  const appended = appendProfileEntry(profile, entry)
  assert.match(appended, /agent-default-model/)
  assert.match(appended, /- insert:/)
  assert.match(appended, new RegExp(`id: ${USER_INSTANCE_ID}`))
  const initialized = appendProfileEntry('# DSH profile\n[]\n', entry)
  assert.doesNotMatch(initialized, /\[\]/)
  assert.match(initialized, /dsh-one-gateway/)
  assert.throws(() => appendProfileEntry(appended, entry), /already exists/)
  const previous = `- id: dsh-gateway\n  name: dsh-gateway\n  config:\n    enabled: true\n`
  assert.throws(() => appendProfileEntry(previous, entry), /already exists/)
  const previousUser = `- id: dsh-gateway-user-instance\n  config:\n    enabled: true\n`
  assert.throws(() => appendProfileEntry(previousUser, entry), /already exists/)
  const legacy = `- id: dsh-tailscale-gateway\n  config:\n    enabled: true\n`
  assert.throws(() => appendProfileEntry(legacy, entry), /already exists/)
  assert.throws(() => appendProfileEntry('key: value\n', entry), /top-level YAML list/)
})

test('setup detects a previous dsh-gateway profile entry as already present', () => {
  const entry = renderProfileEntry(createTailscalePlan(tailscaleStatus(), {}, { ports: [443] }).config)
  const previous = `- id: dsh-gateway\n  name: dsh-gateway\n  config:\n    enabled: true\n`
  assert.throws(() => appendProfileEntry(previous, entry), /already exists/)
})

test('setup detects a previous dsh-gateway-user-instance profile entry as already present', () => {
  const entry = renderProfileEntry(createTailscalePlan(tailscaleStatus(), {}, { ports: [443] }).config)
  const previousUser = `- id: dsh-gateway-user-instance\n  config:\n    enabled: true\n`
  assert.throws(() => appendProfileEntry(previousUser, entry), /already exists/)
})

test('the shipped disabled baseline remains available after an update', async () => {
  const patch = await import('node:fs/promises').then(fs => fs.readFile(new URL('../cordis.patch.yml', import.meta.url), 'utf8'))
  assert.match(patch, new RegExp(`id: ${BASELINE_INSTANCE_ID}`))
  assert.match(patch, new RegExp(`name: ${PACKAGE_NAME}`))
  assert.match(patch, /enabled: false/)
})

test('provider detection handles zero, one, and multiple executables', () => {
  assert.deepEqual(detectProviders({ hasCommand: () => false }), [])
  assert.deepEqual(selectProvider(detectProviders({ hasCommand: name => name === 'tailscale' })), 'tailscale-serve')
  assert.throws(() => selectProvider([]), /no provider/)
  assert.throws(() => selectProvider([
    { id: 'tailscale-serve' },
    { id: 'cloudflare-access' },
  ]), /multiple providers/)
  assert.equal(selectProvider([], 'cloudflare-access'), 'cloudflare-access')
  assert.equal(selectProvider([], 'headscale-tcp-serve'), 'headscale-tcp-serve')
  assert.throws(() => selectProvider([], 'easytier'), /tailscale-serve, cloudflare-access, or headscale-tcp-serve/)
})

function headscaleStatus(overrides = {}) {
  return {
    BackendState: 'Running',
    Self: {
      DNSName: 'gateway.example.invalid.',
      UserID: 7,
    },
    CurrentTailnet: { MagicDNSSuffix: 'example.invalid' },
    User: { 7: { LoginName: 'owner@example.invalid' } },
    ...overrides,
  }
}

test('control-plane classification distinguishes Tailscale.com from Headscale using live node facts', () => {
  assert.equal(classifyControlPlane(tailscaleStatus()).kind, 'official')
  assert.equal(classifyControlPlane(headscaleStatus()).kind, 'headscale')
  assert.equal(classifyControlPlane(headscaleStatus({ BackendState: 'Stopped' })).kind, 'disconnected')
  assert.equal(classifyControlPlane({}).kind, 'unknown')
  assert.deepEqual(
    refineDetectedProviders([{ id: 'tailscale-serve', reason: 'exe' }], { kind: 'headscale' }),
    [{ id: 'headscale-tcp-serve', reason: 'tailscale executable is present on a Headscale control plane' }],
  )
  assert.deepEqual(
    refineDetectedProviders([{ id: 'headscale-tcp-serve', reason: 'exe' }], { kind: 'official' }),
    [{ id: 'tailscale-serve', reason: 'tailscale executable is present on Tailscale.com' }],
  )
})

test('Headscale TCP plan selects an exact or absent port and writes closed TLS plus credential store paths', () => {
  const exact = {
    TCP: { '8443': { TCPForward: '127.0.0.1:3088' } },
  }
  assert.deepEqual(selectTcpOrigin('gateway.example.invalid', exact, [443, 8443]), {
    externalOrigin: 'https://gateway.example.invalid:8443',
    routeState: 'exact',
  })
  const plan = createHeadscaleTcpPlan(headscaleStatus(), {}, {
    ports: [443, 8443],
    tlsCertPath: '/path/to/dsh-one-gateway/cert.pem',
    tlsKeyPath: '/path/to/dsh-one-gateway/key.pem',
    credentialStorePath: '/path/to/dsh-one-gateway/credentials.json',
  })
  assert.equal(plan.provider, 'headscale-tcp-serve')
  assert.equal(plan.externalOrigin, 'https://gateway.example.invalid')
  assert.equal(plan.trustedPrincipal, 'credential:operator-1')
  assert.equal(plan.routeState, 'absent')
  assert.match(plan.notes.join('\n'), /no user identity/)
  assert.match(plan.notes.join('\n'), /does not generate a CA/)
  assert.match(plan.notes.join('\n'), /tailscale serve --tcp 443 --bg tcp:\/\/127\.0\.0\.1:3088/)
  const entry = renderProfileEntry(plan.config)
  assert.match(entry, /type: headscale-tcp-serve/)
  assert.match(entry, /mode: gateway-credential/)
  assert.match(entry, /credentialStorePath: '\/path\/to\/dsh-one-gateway\/credentials\.json'/)
  assert.match(entry, /certPath: '\/path\/to\/dsh-one-gateway\/cert\.pem'/)
  assert.match(entry, /keyPath: '\/path\/to\/dsh-one-gateway\/key\.pem'/)
  assert.doesNotMatch(entry, /secret/i)
  assert.throws(() => inferHeadscaleNode(tailscaleStatus()), /tailscale-serve/)
  assert.throws(() => inferHeadscaleNode(headscaleStatus({
    Self: { DNSName: 'gateway.example.invalid.', UserID: 7, Tags: ['tag:server'] },
  })), /tagged/)
  assert.throws(() => createHeadscaleTcpPlan(headscaleStatus(), {}, {
    tlsCertPath: '/path/to/dsh-one-gateway/cert.pem',
    tlsKeyPath: '/path/to/dsh-one-gateway/key.pem',
  }), /credential-store/)
})

test('non-TTY without complete flags refuses, and --print does not write', async () => {
  assert.throws(() => parseArgs(['setup', '--yes', '--print']), /cannot be used together/)
  assert.throws(() => parseArgs(['setup', '--unknown']), /unknown option/)
  const plan = createCloudflarePlan({
    externalOrigin: 'https://dsh.example.invalid',
    teamOrigin: TEAM_ORIGIN,
    applicationAudience: APPLICATION_AUDIENCE,
    trustedEmail: 'operator@example.invalid',
  })
  assert.equal(plan.config.provider.routeManagement, 'verify-only')
  assert.match(plan.notes.join('\n'), /verify-only/)
  assert.match(plan.notes.join('\n'), /internet-routable/)
})
