import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { Writable } from 'node:stream'
import { main, parseArgs } from '../src/setup/cli.mjs'

function collectIo() {
  let stdout = ''
  let stderr = ''
  return {
    stdin: { isTTY: false },
    stdout: new Writable({ write(chunk, _enc, cb) { stdout += chunk; cb() } }),
    stderr: new Writable({ write(chunk, _enc, cb) { stderr += chunk; cb() } }),
    read: () => ({ stdout, stderr }),
  }
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
    tailscaleJson: argv => {
      if (argv[0] === 'status') {
        return {
          Self: { DNSName: 'gateway.example-tailnet.ts.net.', UserID: 1 },
          User: { 1: { LoginName: 'owner@example.invalid' } },
        }
      }
      return {}
    },
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
    tailscaleJson: argv => argv[0] === 'status'
      ? { Self: { DNSName: 'gateway.example-tailnet.ts.net.', UserID: 1 }, User: { 1: { LoginName: 'owner@example.invalid' } } }
      : {},
    writeProfile: async () => { throw new Error('must not write') },
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
  const directory = await mkdtemp(join(tmpdir(), 'dsh-gateway-cli-cred-'))
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
