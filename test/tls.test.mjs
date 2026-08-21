import assert from 'node:assert/strict'
import { Server as TlsServer } from 'node:tls'
import { rm } from 'node:fs/promises'
import test from 'node:test'
import { createGatewayServer, start } from '../src/core/server.mjs'
import { loadGatewayTls, needsLoopbackTls } from '../src/core/tls.mjs'
import { stubAuth } from './helpers.mjs'
import { writeFakeTls, writeInvalidPem, writeUnrelatedKey } from './tls-helper.mjs'

const ORIGIN = 'https://gateway.example.invalid:8443'

async function withTls(options, fn) {
  const material = writeFakeTls(options)
  try {
    return await fn(material)
  } finally {
    await rm(material.directory, { recursive: true, force: true })
  }
}

test('loadGatewayTls accepts a matching in-window certificate with restrictive key permissions', async () => {
  await withTls({ hostname: 'gateway.example.invalid' }, async ({ certPath, keyPath }) => {
    const loaded = await loadGatewayTls({ certPath, keyPath }, ORIGIN)
    assert.equal(Buffer.isBuffer(loaded.cert), true)
    assert.equal(Buffer.isBuffer(loaded.key), true)
  })
})

test('loadGatewayTls rejects broad key permissions, mismatched keys, expired certs, and hostname misses', async () => {
  await withTls({ hostname: 'gateway.example.invalid', keyMode: 0o644 }, async ({ certPath, keyPath }) => {
    await assert.rejects(loadGatewayTls({ certPath, keyPath }, ORIGIN), /permissions are too broad/)
  })

  await withTls({ hostname: 'gateway.example.invalid' }, async ({ directory, certPath }) => {
    const otherKey = writeUnrelatedKey(directory)
    await assert.rejects(loadGatewayTls({ certPath, keyPath: otherKey }, ORIGIN), /does not match the private key/)
  })

  await withTls({ hostname: 'other.example.invalid' }, async ({ certPath, keyPath }) => {
    await assert.rejects(loadGatewayTls({ certPath, keyPath }, ORIGIN), /does not cover the externalOrigin hostname/)
  })

  await withTls({
    hostname: 'gateway.example.invalid',
    notBefore: '20000101000000Z',
    notAfter: '20000102000000Z',
  }, async ({ certPath, keyPath }) => {
    await assert.rejects(loadGatewayTls({ certPath, keyPath }, ORIGIN), /expired or not yet valid/)
  })

  await withTls({
    hostname: 'gateway.example.invalid',
    notBefore: '20990101000000Z',
    notAfter: '20990102000000Z',
  }, async ({ certPath, keyPath }) => {
    await assert.rejects(loadGatewayTls({ certPath, keyPath }, ORIGIN), /expired or not yet valid/)
  })
})

test('loadGatewayTls rejects missing files, invalid PEM, relative paths, and IP SAN misses', async () => {
  await assert.rejects(loadGatewayTls({
    certPath: '/path/to/missing-cert.pem',
    keyPath: '/path/to/missing-key.pem',
  }, ORIGIN), /could not be read|tls key/)

  await assert.rejects(loadGatewayTls({
    certPath: 'cert.pem',
    keyPath: '/path/to/key.pem',
  }, ORIGIN), /certPath must be an absolute path/)

  await withTls({ hostname: 'gateway.example.invalid' }, async ({ directory, keyPath }) => {
    const certPath = writeInvalidPem(directory, 'bad-cert.pem', 0o644)
    await assert.rejects(loadGatewayTls({ certPath, keyPath }, ORIGIN), /not a valid X\.509 certificate/)
  })

  await withTls({ hostname: 'gateway.example.invalid', ip: '127.0.0.1' }, async ({ certPath, keyPath }) => {
    const loaded = await loadGatewayTls({ certPath, keyPath }, 'https://127.0.0.1:8443')
    assert.ok(loaded.cert)
  })

  await withTls({ hostname: 'gateway.example.invalid' }, async ({ certPath, keyPath }) => {
    await assert.rejects(loadGatewayTls({ certPath, keyPath }, 'https://127.0.0.1:8443'), /does not cover/)
  })
})

test('needsLoopbackTls is only true for headscale-tcp-serve', () => {
  assert.equal(needsLoopbackTls({ provider: { type: 'headscale-tcp-serve' } }), true)
  assert.equal(needsLoopbackTls({ provider: { type: 'tailscale-serve' } }), false)
  assert.equal(needsLoopbackTls({ provider: { type: 'cloudflare-access' } }), false)
})

test('createGatewayServer uses a TLS server only when tls material is supplied', async () => {
  await withTls({ hostname: 'gateway.example.invalid' }, async ({ certPath, keyPath }) => {
    const tls = await loadGatewayTls({ certPath, keyPath }, ORIGIN)
    const tlsServer = createGatewayServer({
      enabled: true,
      externalOrigin: ORIGIN,
      activationToken: 'A'.repeat(43),
    }, { auth: stubAuth(), tls })
    assert.equal(tlsServer instanceof TlsServer, true)
    const httpServer = createGatewayServer({
      enabled: true,
      externalOrigin: ORIGIN,
      activationToken: 'A'.repeat(43),
    }, { auth: stubAuth() })
    assert.equal(httpServer instanceof TlsServer, false)
  })
})

test('start fails closed before bind when headscale-tcp-serve TLS cannot load', async () => {
  let bound = false
  let closed = false
  const fakeServer = {
    once: () => fakeServer,
    listen: (_port, _host, callback) => { bound = true; callback() },
    close: callback => { closed = true; callback() },
  }
  await assert.rejects(start({
    enabled: true,
    externalOrigin: ORIGIN,
    provider: { type: 'headscale-tcp-serve', routeManagement: 'ensure' },
    tls: { certPath: '/path/to/missing-cert.pem', keyPath: '/path/to/missing-key.pem' },
  }, {
    auth: stubAuth(),
    createGateway: () => fakeServer,
    logger: { log: () => {} },
  }), /tls is not ready/)
  assert.equal(bound, false)
  assert.equal(closed, false)
})

test('start binds TLS then still closes on provider verify failure', async () => {
  await withTls({ hostname: 'gateway.example.invalid' }, async ({ certPath, keyPath }) => {
    let bound = false
    let closed = false
    const logs = []
    const fakeServer = {
      once: () => fakeServer,
      listen: (_port, _host, callback) => { bound = true; callback() },
      close: callback => { closed = true; callback() },
    }
    await assert.rejects(start({
      enabled: true,
      externalOrigin: ORIGIN,
      provider: { type: 'headscale-tcp-serve', routeManagement: 'ensure' },
      tls: { certPath, keyPath },
    }, {
      auth: stubAuth(),
      createGateway: () => fakeServer,
      runtime: {
        tailscaleBinary: '/opt/tailscale/tailscale',
        run: async () => { throw new Error('tailscale not found') },
      },
      logger: { log: line => logs.push(line) },
    }), /after the loopback sidecar bound/)
    assert.equal(bound, true)
    assert.equal(closed, true)
    assert.match(logs.join('\n'), /https:\/\/127\.0\.0\.1:3088/)
  })
})

test('start does not load TLS for tailscale-serve', async () => {
  let bound = false
  const fakeServer = {
    once: () => fakeServer,
    listen: (_port, _host, callback) => { bound = true; callback() },
    close: callback => callback(),
  }
  const server = await start({
    enabled: true,
    externalOrigin: 'https://gateway.example-tailnet.ts.net:8443',
    provider: { type: 'tailscale-serve', routeManagement: 'ensure' },
  }, {
    auth: stubAuth(),
    createGateway: () => fakeServer,
    runtime: {
      tailscaleBinary: '/opt/tailscale/tailscale',
      run: async () => ({
        exitCode: 0,
        stdout: JSON.stringify({
          TCP: { '8443': { HTTPS: true } },
          Web: {
            'gateway.example-tailnet.ts.net:8443': {
              Handlers: { '/': { Proxy: 'http://127.0.0.1:3088' } },
            },
          },
        }),
        stderr: '',
      }),
    },
    logger: { log: () => {} },
  })
  assert.equal(server, fakeServer)
  assert.equal(bound, true)
})

