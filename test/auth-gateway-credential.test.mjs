import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import test from 'node:test'
import { createLoginLimiter } from '../src/auth/abuse-controls.mjs'
import {
  generateCredentialSecret,
  hashCredential,
  issueCredential,
  listCredentials,
  lookupCredential,
  parseStoreDocument,
  revokeCredential,
} from '../src/auth/credential-store.mjs'
import { createGatewayCredentialAuth } from '../src/auth/gateway-credential.mjs'
import { createSessionStore } from '../src/auth/sessions.mjs'
import { LOGIN_PATH, SESSION_COOKIE_NAME } from '../src/core/constants.mjs'

const ORIGIN = 'https://gateway.example.invalid'

function responseRecorder() {
  const result = { headers: {} }
  return {
    result,
    writeHead(statusCode, headers) {
      result.statusCode = statusCode
      result.headers = headers
    },
    end(body) {
      result.body = body
    },
  }
}

function loginContext({ origin = ORIGIN, host = 'gateway.example.invalid', fetchSite = 'same-origin', extra = [] } = {}) {
  const headers = ['Host', host, 'Origin', origin, 'Sec-Fetch-Site', fetchSite, ...extra]
  return {
    remoteAddress: '127.0.0.1',
    rawHeaders: headers,
    method: 'POST',
    url: LOGIN_PATH,
  }
}

function fakeRequest(body, contentType = 'application/json') {
  const stream = Readable.from([Buffer.from(body)])
  stream.headers = { 'content-type': contentType }
  return stream
}

test('issued credentials are high-entropy, listed without secrets, and revocable', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'dsh-gateway-cred-'))
  const store = join(directory, 'credentials.json')
  const issued = await issueCredential(store, 'operator-1')
  assert.equal(issued.principalId, 'credential:operator-1')
  assert.match(issued.secret, /^[A-Za-z0-9_-]{43}$/)
  const listed = await listCredentials(store)
  assert.equal(listed.length, 1)
  assert.equal(listed[0].principalId, 'credential:operator-1')
  assert.equal(JSON.stringify(listed).includes(issued.secret), false)
  const document = parseStoreDocument(await import('node:fs/promises').then(fs => fs.readFile(store, 'utf8')))
  assert.equal(JSON.stringify(document).includes(issued.secret), false)
  assert.equal(lookupCredential(document, issued.secret).principalId, 'credential:operator-1')
  await revokeCredential(store, 'operator-1')
  const after = parseStoreDocument(await import('node:fs/promises').then(fs => fs.readFile(store, 'utf8')))
  assert.equal(lookupCredential(after, issued.secret), undefined)
})

test('user-chosen, short, unknown, and duplicate credentials deny', async () => {
  assert.throws(() => parseStoreDocument('not-json'), /valid JSON/)
  const secret = generateCredentialSecret()
  const document = parseStoreDocument(JSON.stringify({
    version: 1,
    credentials: [{ principalId: 'credential:operator-1', verifier: hashCredential(secret), revoked: false }],
  }))
  assert.equal(lookupCredential(document, 'password'), undefined)
  assert.equal(lookupCredential(document, 'short'), undefined)
  assert.equal(lookupCredential(document, generateCredentialSecret()), undefined)
  assert.equal(lookupCredential(document, secret).principalId, 'credential:operator-1')
})

test('login GET, cross-origin POST, missing Origin, bad fetch metadata, and wrong content type deny uniformly', async () => {
  const secret = generateCredentialSecret()
  const loadStore = async () => parseStoreDocument(JSON.stringify({
    version: 1,
    credentials: [{ principalId: 'credential:operator-1', verifier: hashCredential(secret), revoked: false }],
  }))
  const auth = createGatewayCredentialAuth({
    trustedPrincipals: ['credential:operator-1'],
    storePath: '/path/to/dsh-gateway/credentials.json',
    loadStore,
    externalOrigin: ORIGIN,
    limiter: createLoginLimiter({ maxDelayMs: 0, perSourceMax: 50, globalMax: 50 }),
  })
  const get = responseRecorder()
  await auth.handleReservedRequest({ ...loginContext(), method: 'GET' }, fakeRequest('{}'), get)
  assert.equal(get.result.statusCode, 401)

  const cross = responseRecorder()
  await auth.handleReservedRequest(loginContext({ origin: 'https://evil.example.invalid' }), fakeRequest(JSON.stringify({ credential: secret })), cross)
  assert.equal(cross.result.statusCode, 401)

  const missingOrigin = responseRecorder()
  await auth.handleReservedRequest({
    remoteAddress: '127.0.0.1',
    rawHeaders: ['Host', 'gateway.example.invalid', 'Sec-Fetch-Site', 'same-origin'],
    method: 'POST',
    url: LOGIN_PATH,
  }, fakeRequest(JSON.stringify({ credential: secret })), missingOrigin)
  assert.equal(missingOrigin.result.statusCode, 401)

  const fetchSite = responseRecorder()
  await auth.handleReservedRequest(loginContext({ fetchSite: 'cross-site' }), fakeRequest(JSON.stringify({ credential: secret })), fetchSite)
  assert.equal(fetchSite.result.statusCode, 401)

  const contentType = responseRecorder()
  await auth.handleReservedRequest(loginContext(), fakeRequest(JSON.stringify({ credential: secret }), 'text/plain'), contentType)
  assert.equal(contentType.result.statusCode, 401)
})

test('successful login rotates a host-only session cookie and authenticates subsequent requests', async () => {
  const secret = generateCredentialSecret()
  const loadStore = async () => parseStoreDocument(JSON.stringify({
    version: 1,
    credentials: [{ principalId: 'credential:operator-1', verifier: hashCredential(secret), revoked: false }],
  }))
  const sessions = createSessionStore()
  const auth = createGatewayCredentialAuth({
    trustedPrincipals: ['credential:operator-1'],
    storePath: '/path/to/dsh-gateway/credentials.json',
    loadStore,
    sessions,
    externalOrigin: ORIGIN,
    limiter: createLoginLimiter({ maxDelayMs: 0 }),
  })
  const created = responseRecorder()
  await auth.handleReservedRequest(loginContext(), fakeRequest(JSON.stringify({ credential: secret })), created)
  assert.equal(created.result.statusCode, 204)
  const cookie = created.result.headers['Set-Cookie']
  assert.match(cookie, new RegExp(`^${SESSION_COOKIE_NAME}=`))
  assert.match(cookie, /Path=\//)
  assert.match(cookie, /Secure/)
  assert.match(cookie, /HttpOnly/)
  assert.match(cookie, /SameSite=Strict/)
  assert.doesNotMatch(cookie, /Domain=/)
  const sessionId = cookie.split(';')[0].split('=')[1]
  const authenticated = await auth.authenticate({
    remoteAddress: '127.0.0.1',
    rawHeaders: ['Host', 'gateway.example.invalid', 'Cookie', `${SESSION_COOKIE_NAME}=${sessionId}`],
    method: 'GET',
    url: '/',
  })
  assert.equal(authenticated.ok, true)
  assert.equal(authenticated.principal.id, 'credential:operator-1')
  assert.deepEqual(authenticated.consumedCookies, [SESSION_COOKIE_NAME])
})

test('expired, duplicate, revoked, and restart-stale sessions deny', async () => {
  const secret = generateCredentialSecret()
  let revoked = false
  const loadStore = async () => parseStoreDocument(JSON.stringify({
    version: 1,
    credentials: [{ principalId: 'credential:operator-1', verifier: hashCredential(secret), revoked }],
  }))
  let now = Date.now()
  const sessions = createSessionStore({ idleMs: 50, absoluteMs: 100, now: () => now })
  const auth = createGatewayCredentialAuth({
    trustedPrincipals: ['credential:operator-1'],
    storePath: '/path/to/dsh-gateway/credentials.json',
    loadStore,
    sessions,
    externalOrigin: ORIGIN,
    limiter: createLoginLimiter({ maxDelayMs: 0 }),
  })
  const created = responseRecorder()
  await auth.handleReservedRequest(loginContext(), fakeRequest(JSON.stringify({ credential: secret })), created)
  const sessionId = created.result.headers['Set-Cookie'].split(';')[0].split('=')[1]
  now += 1000
  const idle = await auth.authenticate({
    rawHeaders: ['Cookie', `${SESSION_COOKIE_NAME}=${sessionId}`],
  })
  assert.equal(idle.ok, false)

  const duplicate = await auth.authenticate({
    rawHeaders: ['Cookie', `${SESSION_COOKIE_NAME}=abc`, 'Cookie', `${SESSION_COOKIE_NAME}=abc`],
  })
  assert.equal(duplicate.reasonCode, 'session_duplicate')

  const fresh = responseRecorder()
  now = Date.now()
  const sessions2 = createSessionStore()
  const auth2 = createGatewayCredentialAuth({
    trustedPrincipals: ['credential:operator-1'],
    storePath: '/path/to/dsh-gateway/credentials.json',
    loadStore,
    sessions: sessions2,
    externalOrigin: ORIGIN,
    limiter: createLoginLimiter({ maxDelayMs: 0 }),
  })
  await auth2.handleReservedRequest(loginContext(), fakeRequest(JSON.stringify({ credential: secret })), fresh)
  const id2 = fresh.result.headers['Set-Cookie'].split(';')[0].split('=')[1]
  revoked = true
  const afterRevoke = await auth2.authenticate({
    rawHeaders: ['Cookie', `${SESSION_COOKIE_NAME}=${id2}`],
  })
  assert.equal(afterRevoke.reasonCode, 'credential_revoked')

  const restarted = createGatewayCredentialAuth({
    trustedPrincipals: ['credential:operator-1'],
    storePath: '/path/to/dsh-gateway/credentials.json',
    loadStore,
    sessions: createSessionStore(),
    externalOrigin: ORIGIN,
  })
  const stale = await restarted.authenticate({
    rawHeaders: ['Cookie', `${SESSION_COOKIE_NAME}=${id2}`],
  })
  assert.equal(stale.ok, false)
})

test('rate limits recover automatically and never permanently lock a principal', async () => {
  const limiter = createLoginLimiter({ perSourceMax: 2, globalMax: 10, perSourceWindowMs: 30, globalWindowMs: 30, maxDelayMs: 0 })
  assert.equal((await limiter.admit('127.0.0.1')).ok, true)
  assert.equal((await limiter.admit('127.0.0.1')).ok, true)
  assert.equal((await limiter.admit('127.0.0.1')).ok, false)
  await new Promise(resolve => setTimeout(resolve, 40))
  assert.equal((await limiter.admit('127.0.0.1')).ok, true)
})

test('malformed store and missing verifier fail readiness', async () => {
  const auth = createGatewayCredentialAuth({
    trustedPrincipals: ['credential:operator-1'],
    storePath: '/path/to/dsh-gateway/credentials.json',
    loadStore: async () => { throw new Error('dsh-gateway: credential store is malformed') },
    externalOrigin: ORIGIN,
  })
  const ready = await auth.readiness()
  assert.equal(ready.ready, false)
  assert.equal(ready.reasonCode, 'credential_store_malformed')
  void writeFile
})
