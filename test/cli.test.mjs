import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { PassThrough, Writable } from 'node:stream'
import { main, parseArgs, usage } from '../src/setup/cli.mjs'
import { APPLICATION_AUDIENCE, TEAM_ORIGIN } from './helpers.mjs'

function collectIo({ denyStdin = false } = {}) {
  let stdout = ''
  let stderr = ''
  const stdin = denyStdin
    ? {
        isTTY: false,
        on() { throw new Error('stdin must not be read') },
        once() { throw new Error('stdin must not be read') },
        addListener() { throw new Error('stdin must not be read') },
        read() { throw new Error('stdin must not be read') },
      }
    : { isTTY: false }
  return {
    stdin,
    stdout: new Writable({ write(chunk, _enc, cb) { stdout += chunk; cb() } }),
    stderr: new Writable({ write(chunk, _enc, cb) { stderr += chunk; cb() } }),
    read: () => ({ stdout, stderr }),
  }
}

function collectTtyIo(answers = []) {
  const stdin = new PassThrough()
  stdin.isTTY = true
  let stdout = ''
  let stderr = ''
  const remaining = [...answers]
  let lastFedLength = -1
  let feedScheduled = false

  function isWaitingPrompt(text) {
    if (text.endsWith('\n')) return false
    return text.endsWith(': ') || text.endsWith('? ') || text.endsWith('[y/N] ')
  }

  function feedIfWaiting() {
    if (remaining.length === 0) return
    if (!isWaitingPrompt(stdout)) return
    if (stdout.length === lastFedLength) return
    lastFedLength = stdout.length
    const next = remaining.shift()
    if (next === null) stdin.end()
    else stdin.write(`${next}\n`)
  }

  function scheduleFeed() {
    if (feedScheduled) return
    feedScheduled = true
    setImmediate(() => {
      feedScheduled = false
      feedIfWaiting()
    })
  }

  const stdoutStream = new Writable({
    write(chunk, _enc, cb) {
      stdout += String(chunk)
      scheduleFeed()
      cb()
    },
  })
  stdoutStream.isTTY = true

  return {
    stdin,
    stdout: stdoutStream,
    stderr: new Writable({ write(chunk, _enc, cb) { stderr += chunk; cb() } }),
    read: () => ({ stdout, stderr }),
  }
}

function tailscaleStatus() {
  return {
    Self: { DNSName: 'gateway.example-tailnet.ts.net.', UserID: 1 },
    User: { 1: { LoginName: 'owner@example.invalid' } },
  }
}

function tailscaleJson(argv) {
  return argv[0] === 'status' ? tailscaleStatus() : {}
}

function mustNotWrite() {
  return async () => { throw new Error('must not write') }
}

function cloudflareFlags(overrides = {}) {
  return {
    externalOrigin: 'https://dsh.example.invalid',
    teamOrigin: TEAM_ORIGIN,
    applicationAudience: APPLICATION_AUDIENCE,
    trustedPrincipal: 'email:operator@example.invalid',
    ...overrides,
  }
}

function cloudflareArgs(overrides = {}) {
  const values = cloudflareFlags(overrides)
  const args = []
  if (values.externalOrigin) args.push('--external-origin', values.externalOrigin)
  if (values.teamOrigin) args.push('--team-origin', values.teamOrigin)
  if (values.applicationAudience) args.push('--application-audience', values.applicationAudience)
  if (values.trustedPrincipal) args.push('--trusted-principal', values.trustedPrincipal)
  return args
}

test('--print makes no changes and emits no secret material', async () => {
  const io = collectIo()
  let written = false
  await main([
    'setup', '--print', '--provider', 'tailscale-serve',
    '--trusted-principal', 'operator@example.invalid',
    '--profile', '/path/to/profile.yml',
  ], io, {
    detect: () => [{ id: 'tailscale-serve' }],
    tailscaleJson,
    writeProfile: async () => { written = true },
  })
  const { stdout } = io.read()
  assert.equal(written, false)
  assert.match(stdout, /Proposed DSH Web-profile entry/)
  assert.doesNotMatch(stdout, /-----BEGIN/)
  assert.doesNotMatch(stdout, /secret:/i)
})

test('non-interactive setup without --yes refuses to write', async () => {
  const io = collectIo()
  await assert.rejects(main([
    'setup', '--provider', 'tailscale-serve',
    '--trusted-principal', 'operator@example.invalid',
  ], io, {
    detect: () => [{ id: 'tailscale-serve' }],
    tailscaleJson,
    writeProfile: mustNotWrite(),
  }), /nothing was written/)
})

test('cloudflare --yes requires every security-sensitive value', async () => {
  const io = collectIo()
  await assert.rejects(main([
    'setup', '--yes', '--provider', 'cloudflare-access',
  ], io, {
    detect: () => [],
  }), /requires --external-origin/)
})

test('credential issue/list/revoke round-trip without storing the raw secret in list output', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'dsh-one-gateway-cli-cred-'))
  const store = join(directory, 'credentials.json')
  const io = collectIo()
  const issued = await main(['credential', 'issue', '--store', store, '--name', 'operator-1'], io)
  assert.match(issued.secret, /^[A-Za-z0-9_-]{43}$/)
  const listedIo = collectIo()
  await main(['credential', 'list', '--store', store], listedIo)
  assert.doesNotMatch(listedIo.read().stdout, new RegExp(issued.secret))
  await main(['credential', 'revoke', '--store', store, '--name', 'operator-1'], collectIo())
})

test('parseArgs maps dashed flags and defaults the profile path to a placeholder-safe join', () => {
  const options = parseArgs(['setup', '--provider', 'cloudflare-access', '--trusted-principal', 'email:operator@example.invalid'], {
    defaultProfile: '/path/to/profile.yml',
  })
  assert.equal(options.provider, 'cloudflare-access')
  assert.equal(options.trustedPrincipal, 'email:operator@example.invalid')
  assert.equal(options.profile, '/path/to/profile.yml')
})

test('usage mentions the TTY provider menu', () => {
  assert.match(usage(), /Omitting --provider in a TTY opens a menu/)
})

test('TTY menu still appears with one detected provider and empty input selects the default', { timeout: 5_000 }, async () => {
  const io = collectTtyIo(['', ''])
  const result = await main(['setup', '--print'], io, {
    detect: () => [{ id: 'tailscale-serve' }],
    tailscaleJson,
    writeProfile: mustNotWrite(),
  })
  const { stdout } = io.read()
  assert.match(stdout, /Select the ingress provider to configure/)
  assert.match(stdout, /Detection is a hint only; setup will still validate the selected provider/)
  assert.match(stdout, /1\) Tailscale Serve — private Serve ingress with Tailscale user identity \[detected\]/)
  assert.match(stdout, /2\) Cloudflare Access — existing Access-protected application with signed identity\n/)
  assert.match(stdout, /Provider \[1\]: /)
  assert.doesNotMatch(stdout, /verified configuration/i)
  assert.match(stdout, /Provider: tailscale-serve/)
  assert.equal(result.plan.provider, 'tailscale-serve')
})

test('TTY with zero detections still offers the menu and 1 selects Tailscale planning', { timeout: 5_000 }, async () => {
  const io = collectTtyIo(['1', ''])
  const result = await main(['setup', '--print'], io, {
    detect: () => [],
    tailscaleJson,
    writeProfile: mustNotWrite(),
  })
  const { stdout } = io.read()
  assert.match(stdout, /Provider \(1-2\): /)
  assert.doesNotMatch(stdout, /\[detected\]/)
  assert.equal(result.plan.provider, 'tailscale-serve')
  assert.match(stdout, /Provider: tailscale-serve/)
})

test('TTY with both detected has no default; invalid input retries then 2 selects Cloudflare', { timeout: 5_000 }, async () => {
  const io = collectTtyIo([
    'nope',
    '2',
    'https://dsh.example.invalid',
    TEAM_ORIGIN,
    APPLICATION_AUDIENCE,
    'operator@example.invalid',
  ])
  let writes = 0
  let jwks = 0
  let probes = 0
  const result = await main(['setup', '--print'], io, {
    detect: () => [{ id: 'tailscale-serve' }, { id: 'cloudflare-access' }],
    fetchJwks: async () => { jwks += 1; return {} },
    probeAccess: async () => { probes += 1; return { kind: 'limited', reason: 'test' } },
    writeProfile: async () => { writes += 1 },
  })
  const { stdout } = io.read()
  assert.match(stdout, /1\) Tailscale Serve — private Serve ingress with Tailscale user identity \[detected\]/)
  assert.match(stdout, /2\) Cloudflare Access — existing Access-protected application with signed identity \[detected\]/)
  assert.match(stdout, /Provider \(1-2\): /)
  assert.doesNotMatch(stdout, /Provider \[/)
  assert.match(stdout, /Invalid selection\. Enter 1 or 2\./)
  assert.equal(result.plan.provider, 'cloudflare-access')
  assert.match(stdout, /Provider: cloudflare-access/)
  assert.equal(writes, 0)
  assert.equal(jwks, 1)
  assert.equal(probes, 1)
})

test('explicit --provider suppresses the TTY provider menu', { timeout: 5_000 }, async () => {
  const io = collectTtyIo([])
  await main([
    'setup', '--print', '--provider', 'tailscale-serve',
    '--trusted-principal', 'operator@example.invalid',
  ], io, {
    detect: () => [{ id: 'cloudflare-access' }],
    tailscaleJson,
    writeProfile: mustNotWrite(),
  })
  const { stdout } = io.read()
  assert.doesNotMatch(stdout, /Select the ingress provider/)
  assert.doesNotMatch(stdout, /Provider \[/)
  assert.match(stdout, /Provider: tailscale-serve/)
})

test('EOF before a provider selection fails without planning or writing', { timeout: 5_000 }, async () => {
  const io = collectTtyIo([null])
  let written = false
  let inspected = false
  await assert.rejects(main(['setup'], io, {
    detect: () => [{ id: 'tailscale-serve' }],
    tailscaleJson: argv => {
      inspected = true
      return tailscaleJson(argv)
    },
    writeProfile: async () => { written = true },
  }), /setup ended before a provider was selected; rerun with --provider tailscale-serve or --provider cloudflare-access/)
  assert.equal(written, false)
  assert.equal(inspected, false)
})

test('Tailscale TTY empty login keeps the inferred owner', { timeout: 5_000 }, async () => {
  const io = collectTtyIo([''])
  const result = await main(['setup', '--print', '--provider', 'tailscale-serve'], io, {
    detect: () => [{ id: 'tailscale-serve' }],
    tailscaleJson,
    writeProfile: mustNotWrite(),
  })
  const { stdout } = io.read()
  assert.match(stdout, /Trusted Tailscale login \[owner@example\.invalid\]: /)
  assert.equal(result.plan.trustedPrincipal, 'login:owner@example.invalid')
})

test('Tailscale TTY replacement principal is used instead of the inferred owner', { timeout: 5_000 }, async () => {
  const io = collectTtyIo(['other@example.invalid'])
  const result = await main(['setup', '--print', '--provider', 'tailscale-serve'], io, {
    detect: () => [{ id: 'tailscale-serve' }],
    tailscaleJson,
    writeProfile: mustNotWrite(),
  })
  assert.equal(result.plan.trustedPrincipal, 'login:other@example.invalid')
})

test('Cloudflare TTY prompts for all four missing values in order', { timeout: 5_000 }, async () => {
  const io = collectTtyIo([
    'https://dsh.example.invalid',
    TEAM_ORIGIN,
    APPLICATION_AUDIENCE,
    'operator@example.invalid',
  ])
  const result = await main(['setup', '--print', '--provider', 'cloudflare-access'], io, {
    detect: () => [],
    fetchJwks: async () => ({}),
    probeAccess: async () => ({ kind: 'limited', reason: 'test' }),
    writeProfile: mustNotWrite(),
  })
  const { stdout } = io.read()
  assert.match(stdout, /Cloudflare setup is verify-only\. It will not create a tunnel, DNS record, or Access application\./)
  assert.match(stdout, /Use an existing Access-protected HTTPS application\./)
  const originAt = stdout.indexOf('Existing Access application origin (HTTPS): ')
  const teamAt = stdout.indexOf('Cloudflare Access team origin (HTTPS): ')
  const audienceAt = stdout.indexOf('Cloudflare Access application audience (aud): ')
  const emailAt = stdout.indexOf('Trusted Cloudflare Access email: ')
  assert.ok(originAt >= 0 && teamAt > originAt && audienceAt > teamAt && emailAt > audienceAt)
  assert.equal(result.plan.provider, 'cloudflare-access')
  assert.equal(result.plan.trustedPrincipal, 'email:operator@example.invalid')
})

test('Cloudflare TTY with a subset of flags prompts only for the missing values', { timeout: 5_000 }, async () => {
  const io = collectTtyIo([APPLICATION_AUDIENCE, 'operator@example.invalid'])
  await main([
    'setup', '--print', '--provider', 'cloudflare-access',
    '--external-origin', 'https://dsh.example.invalid',
    '--team-origin', TEAM_ORIGIN,
  ], io, {
    detect: () => [],
    fetchJwks: async () => ({}),
    probeAccess: async () => ({ kind: 'limited', reason: 'test' }),
    writeProfile: mustNotWrite(),
  })
  const { stdout } = io.read()
  assert.doesNotMatch(stdout, /Existing Access application origin/)
  assert.doesNotMatch(stdout, /Cloudflare Access team origin/)
  assert.match(stdout, /Cloudflare Access application audience \(aud\): /)
  assert.match(stdout, /Trusted Cloudflare Access email: /)
})

test('Cloudflare TTY with all flags shows no field prompts', { timeout: 5_000 }, async () => {
  const io = collectTtyIo([])
  await main([
    'setup', '--print', '--provider', 'cloudflare-access',
    ...cloudflareArgs(),
  ], io, {
    detect: () => [],
    fetchJwks: async () => ({}),
    probeAccess: async () => ({ kind: 'limited', reason: 'test' }),
    writeProfile: mustNotWrite(),
  })
  const { stdout } = io.read()
  assert.match(stdout, /Cloudflare setup is verify-only/)
  assert.doesNotMatch(stdout, /Existing Access application origin/)
  assert.doesNotMatch(stdout, /Cloudflare Access team origin/)
  assert.doesNotMatch(stdout, /application audience \(aud\)/)
  assert.doesNotMatch(stdout, /Trusted Cloudflare Access email/)
})

test('empty Cloudflare input re-prompts; quick-tunnel input fails before JWKS, probe, or write', { timeout: 5_000 }, async () => {
  const io = collectTtyIo([
    '',
    'https://random.trycloudflare.com',
    TEAM_ORIGIN,
    APPLICATION_AUDIENCE,
    'operator@example.invalid',
  ])
  let jwks = 0
  let probes = 0
  let writes = 0
  await assert.rejects(main(['setup', '--print', '--provider', 'cloudflare-access'], io, {
    detect: () => [],
    fetchJwks: async () => { jwks += 1; return {} },
    probeAccess: async () => { probes += 1; return { kind: 'limited', reason: 'test' } },
    writeProfile: async () => { writes += 1 },
  }), /quick tunnels/)
  const { stdout } = io.read()
  assert.match(stdout, /A value is required; supply it here or with the corresponding flag\./)
  assert.equal(jwks, 0)
  assert.equal(probes, 0)
  assert.equal(writes, 0)
})

test('malformed Cloudflare origin fails through existing validators before JWKS or write', { timeout: 5_000 }, async () => {
  const io = collectTtyIo([
    'http://dsh.example.invalid',
    TEAM_ORIGIN,
    APPLICATION_AUDIENCE,
    'operator@example.invalid',
  ])
  let jwks = 0
  let writes = 0
  await assert.rejects(main(['setup', '--print', '--provider', 'cloudflare-access'], io, {
    detect: () => [],
    fetchJwks: async () => { jwks += 1; return {} },
    writeProfile: async () => { writes += 1 },
  }), /HTTPS/)
  assert.equal(jwks, 0)
  assert.equal(writes, 0)
})

test('non-TTY zero detections without --provider fail without reading stdin', async () => {
  const io = collectIo({ denyStdin: true })
  await assert.rejects(main(['setup', '--print'], io, {
    detect: () => [],
    writeProfile: mustNotWrite(),
  }), /no provider executable was detected/)
})

test('non-TTY multiple detections without --provider fail without reading stdin', async () => {
  const io = collectIo({ denyStdin: true })
  await assert.rejects(main(['setup', '--yes'], io, {
    detect: () => [{ id: 'tailscale-serve' }, { id: 'cloudflare-access' }],
    writeProfile: mustNotWrite(),
  }), /multiple providers were detected/)
})

test('non-TTY exactly one detection auto-selects without a menu', async () => {
  const io = collectIo({ denyStdin: true })
  const result = await main(['setup', '--print'], io, {
    detect: () => [{ id: 'tailscale-serve' }],
    tailscaleJson,
    writeProfile: mustNotWrite(),
  })
  const { stdout } = io.read()
  assert.doesNotMatch(stdout, /Select the ingress provider/)
  assert.equal(result.plan.provider, 'tailscale-serve')
})

test('non-TTY Tailscale --yes without --trusted-principal fails and does not write', async () => {
  const io = collectIo({ denyStdin: true })
  let written = false
  await assert.rejects(main(['setup', '--yes', '--provider', 'tailscale-serve'], io, {
    detect: () => [{ id: 'tailscale-serve' }],
    tailscaleJson,
    writeProfile: async () => { written = true },
  }), /non-interactive --yes requires --trusted-principal/)
  assert.equal(written, false)
})

test('non-TTY Cloudflare fails for each omitted required flag', async () => {
  const required = [
    ['--external-origin', 'https://dsh.example.invalid'],
    ['--team-origin', TEAM_ORIGIN],
    ['--application-audience', APPLICATION_AUDIENCE],
    ['--trusted-principal', 'email:operator@example.invalid'],
  ]
  for (let omit = 0; omit < required.length; omit += 1) {
    const flags = required.flatMap((pair, index) => (index === omit ? [] : pair))
    const io = collectIo({ denyStdin: true })
    await assert.rejects(main(['setup', '--yes', '--provider', 'cloudflare-access', ...flags], io, {
      detect: () => [],
      fetchJwks: async () => { throw new Error('must not fetch JWKS') },
      writeProfile: mustNotWrite(),
    }), /requires --external-origin/)
  }
})

test('non-TTY Cloudflare --yes with every flag writes once and never prompts', async () => {
  const io = collectIo({ denyStdin: true })
  let writes = 0
  await main(['setup', '--yes', '--provider', 'cloudflare-access', ...cloudflareArgs()], io, {
    detect: () => [{ id: 'cloudflare-access' }],
    fetchJwks: async () => ({}),
    probeAccess: async () => ({ kind: 'limited', reason: 'test' }),
    writeProfile: async () => { writes += 1 },
  })
  const { stdout } = io.read()
  assert.equal(writes, 1)
  assert.doesNotMatch(stdout, /Existing Access application origin/)
  assert.doesNotMatch(stdout, /Select the ingress provider/)
})

test('unsupported provider spellings stay rejected, including with --print', async () => {
  for (const provider of ['easytier', 'operator-managed', 'credential-only']) {
    const io = collectIo({ denyStdin: true })
    await assert.rejects(main(['setup', '--print', '--provider', provider], io, {
      detect: () => [],
      writeProfile: mustNotWrite(),
    }), /tailscale-serve or cloudflare-access/)
  }
})

test('TTY --print may prompt but never writes the profile', { timeout: 5_000 }, async () => {
  const io = collectTtyIo(['', ''])
  let written = false
  await main(['setup', '--print'], io, {
    detect: () => [{ id: 'tailscale-serve' }],
    tailscaleJson,
    writeProfile: async () => { written = true },
  })
  const { stdout } = io.read()
  assert.equal(written, false)
  assert.match(stdout, /Select the ingress provider/)
  assert.doesNotMatch(stdout, /-----BEGIN/)
  assert.doesNotMatch(stdout, /secret:/i)
})

test('TTY --yes still collects omitted values and skips only the write confirmation', { timeout: 5_000 }, async () => {
  const io = collectTtyIo(['', ''])
  let writes = 0
  await main(['setup', '--yes'], io, {
    detect: () => [{ id: 'tailscale-serve' }],
    tailscaleJson,
    writeProfile: async () => { writes += 1 },
  })
  const { stdout } = io.read()
  assert.equal(writes, 1)
  assert.match(stdout, /Select the ingress provider/)
  assert.doesNotMatch(stdout, /Write this profile entry/)
})
