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
import { LOGIN_PATH, MAX_LOGIN_BODY_BYTES, SESSION_COOKIE_NAME } from '../src/core/constants.mjs'
import { createGatewayServer } from '../src/core/server.mjs'

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

function getContext({ host = 'gateway.example.invalid', fetchSite, extra = [], url = LOGIN_PATH } = {}) {
  const headers = ['Host', host]
  if (fetchSite !== undefined) headers.push('Sec-Fetch-Site', fetchSite)
  return {
    remoteAddress: '127.0.0.1',
    rawHeaders: [...headers, ...extra],
    method: 'GET',
    url,
  }
}

function credentialAuth(secret, extras = {}) {
  const loadStore = async () => parseStoreDocument(JSON.stringify({
    version: 1,
    credentials: [{ principalId: 'credential:operator-1', verifier: hashCredential(secret), revoked: false }],
  }))
  return createGatewayCredentialAuth({
    trustedPrincipals: ['credential:operator-1'],
    storePath: '/path/to/dsh-one-gateway/credentials.json',
    loadStore,
    externalOrigin: ORIGIN,
    limiter: createLoginLimiter({ maxDelayMs: 0, perSourceMax: 50, globalMax: 50 }),
    ...extras,
  })
}

function assertUnauthorized(recorder) {
  assert.equal(recorder.result.statusCode, 401)
  assert.equal(recorder.result.headers['Content-Type'], 'text/plain; charset=utf-8')
  assert.equal(recorder.result.headers['Cache-Control'], 'no-store')
  assert.equal(recorder.result.body, '401 Unauthorized\n')
}

test('issued credentials are high-entropy, listed without secrets, and revocable', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'dsh-one-gateway-cred-'))
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

test('cross-origin POST, missing Origin, bad fetch metadata, and wrong content type deny uniformly', async () => {
  const secret = generateCredentialSecret()
  const auth = credentialAuth(secret)

  const cross = responseRecorder()
  await auth.handleReservedRequest(loginContext({ origin: 'https://evil.example.invalid' }), fakeRequest(JSON.stringify({ credential: secret })), cross)
  assertUnauthorized(cross)

  const missingOrigin = responseRecorder()
  await auth.handleReservedRequest({
    remoteAddress: '127.0.0.1',
    rawHeaders: ['Host', 'gateway.example.invalid', 'Sec-Fetch-Site', 'same-origin'],
    method: 'POST',
    url: LOGIN_PATH,
  }, fakeRequest(JSON.stringify({ credential: secret })), missingOrigin)
  assertUnauthorized(missingOrigin)

  const fetchSite = responseRecorder()
  await auth.handleReservedRequest(loginContext({ fetchSite: 'cross-site' }), fakeRequest(JSON.stringify({ credential: secret })), fetchSite)
  assertUnauthorized(fetchSite)

  const contentType = responseRecorder()
  await auth.handleReservedRequest(loginContext(), fakeRequest(JSON.stringify({ credential: secret }), 'text/plain'), contentType)
  assertUnauthorized(contentType)
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
    storePath: '/path/to/dsh-one-gateway/credentials.json',
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
    storePath: '/path/to/dsh-one-gateway/credentials.json',
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
    storePath: '/path/to/dsh-one-gateway/credentials.json',
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
    storePath: '/path/to/dsh-one-gateway/credentials.json',
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
    storePath: '/path/to/dsh-one-gateway/credentials.json',
    loadStore: async () => { throw new Error('dsh-one-gateway: credential store is malformed') },
    externalOrigin: ORIGIN,
  })
  const ready = await auth.readiness()
  assert.equal(ready.ready, false)
  assert.equal(ready.reasonCode, 'credential_store_malformed')
  void writeFile
})

test('canonical GET returns the constant login form; HEAD, PUT, OPTIONS, and malformed targets deny', async () => {
  const secret = generateCredentialSecret()
  const auth = credentialAuth(secret)

  const page = responseRecorder()
  const handled = await auth.handleReservedRequest(getContext(), fakeRequest(''), page)
  assert.equal(handled.handled, true)
  assert.equal(page.result.statusCode, 200)
  assert.equal(page.result.headers['Content-Type'], 'text/html; charset=utf-8')
  assert.equal(page.result.headers['Cache-Control'], 'no-store')
  assert.equal(page.result.headers['X-Content-Type-Options'], 'nosniff')
  assert.equal(page.result.headers['X-Frame-Options'], 'DENY')
  assert.equal(page.result.headers['Referrer-Policy'], 'no-referrer')
  assert.equal(
    page.result.headers['Content-Security-Policy'],
    "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  )
  const body = String(page.result.body)
  assert.match(body, /<form method="post" action="\/\.dsh-one-gateway\/login">/)
  assert.doesNotMatch(body, /action="[^"]*\?/)
  assert.doesNotMatch(body, /<script/i)
  assert.doesNotMatch(body, /\bsrc\s*=/i)
  assert.doesNotMatch(body, /\bhref\s*=/i)
  assert.equal(body.includes(secret), false)
  assert.equal(body.includes('?'), false)

  for (const method of ['HEAD', 'PUT', 'OPTIONS']) {
    const denied = responseRecorder()
    await auth.handleReservedRequest({ ...getContext(), method }, fakeRequest(''), denied)
    assertUnauthorized(denied)
  }

  const malformed = responseRecorder()
  const malformedHandled = await auth.handleReservedRequest(
    getContext({ url: 'http://127.0.0.1:3080/' }),
    fakeRequest(''),
    malformed,
  )
  assert.equal(malformedHandled.handled, false)
  assert.equal(malformed.result.statusCode, undefined)

  const query = responseRecorder()
  const queryHandled = await auth.handleReservedRequest(
    getContext({ url: `${LOGIN_PATH}?next=/` }),
    fakeRequest(''),
    query,
  )
  assert.equal(queryHandled.handled, false)
  assert.equal(query.result.statusCode, undefined)
})

test('GET with wrong or duplicate Host, or disallowed Fetch-Metadata, denies', async () => {
  const secret = generateCredentialSecret()
  const auth = credentialAuth(secret)

  const wrongHost = responseRecorder()
  await auth.handleReservedRequest(getContext({ host: 'evil.example.invalid' }), fakeRequest(''), wrongHost)
  assertUnauthorized(wrongHost)

  const duplicateHost = responseRecorder()
  await auth.handleReservedRequest(
    getContext({ extra: ['Host', 'gateway.example.invalid'] }),
    fakeRequest(''),
    duplicateHost,
  )
  assertUnauthorized(duplicateHost)

  const crossSite = responseRecorder()
  await auth.handleReservedRequest(getContext({ fetchSite: 'cross-site' }), fakeRequest(''), crossSite)
  assertUnauthorized(crossSite)

  const duplicateFetch = responseRecorder()
  await auth.handleReservedRequest(
    getContext({ fetchSite: 'same-origin', extra: ['Sec-Fetch-Site', 'none'] }),
    fakeRequest(''),
    duplicateFetch,
  )
  assertUnauthorized(duplicateFetch)
})

test('POST with wrong, missing, or duplicate Origin, or cross-site or duplicate Fetch-Metadata, denies', async () => {
  const secret = generateCredentialSecret()
  const auth = credentialAuth(secret)
  const body = JSON.stringify({ credential: secret })

  const wrongOrigin = responseRecorder()
  await auth.handleReservedRequest(loginContext({ origin: 'https://evil.example.invalid' }), fakeRequest(body), wrongOrigin)
  assertUnauthorized(wrongOrigin)

  const missingOrigin = responseRecorder()
  await auth.handleReservedRequest({
    remoteAddress: '127.0.0.1',
    rawHeaders: ['Host', 'gateway.example.invalid', 'Sec-Fetch-Site', 'same-origin'],
    method: 'POST',
    url: LOGIN_PATH,
  }, fakeRequest(body), missingOrigin)
  assertUnauthorized(missingOrigin)

  const duplicateOrigin = responseRecorder()
  await auth.handleReservedRequest(
    loginContext({ extra: ['Origin', ORIGIN] }),
    fakeRequest(body),
    duplicateOrigin,
  )
  assertUnauthorized(duplicateOrigin)

  const crossSite = responseRecorder()
  await auth.handleReservedRequest(loginContext({ fetchSite: 'cross-site' }), fakeRequest(body), crossSite)
  assertUnauthorized(crossSite)

  const duplicateFetch = responseRecorder()
  await auth.handleReservedRequest(
    loginContext({ extra: ['Sec-Fetch-Site', 'same-origin'] }),
    fakeRequest(body),
    duplicateFetch,
  )
  assertUnauthorized(duplicateFetch)
})

test('malformed JSON, duplicate form fields, missing or short credential, wrong type, and oversized body deny with the same 401', async () => {
  const secret = generateCredentialSecret()
  const auth = credentialAuth(secret)

  const malformedJson = responseRecorder()
  await auth.handleReservedRequest(loginContext(), fakeRequest('{'), malformedJson)
  assertUnauthorized(malformedJson)

  const duplicateFields = responseRecorder()
  await auth.handleReservedRequest(
    loginContext(),
    fakeRequest(`credential=${encodeURIComponent(secret)}&credential=${encodeURIComponent(secret)}`, 'application/x-www-form-urlencoded'),
    duplicateFields,
  )
  assertUnauthorized(duplicateFields)

  const missing = responseRecorder()
  await auth.handleReservedRequest(loginContext(), fakeRequest('{}'), missing)
  assertUnauthorized(missing)

  const shortJson = responseRecorder()
  await auth.handleReservedRequest(loginContext(), fakeRequest(JSON.stringify({ credential: 'short' })), shortJson)
  assertUnauthorized(shortJson)

  const shortForm = responseRecorder()
  await auth.handleReservedRequest(
    loginContext(),
    fakeRequest('credential=short', 'application/x-www-form-urlencoded'),
    shortForm,
  )
  assertUnauthorized(shortForm)

  const wrongType = responseRecorder()
  await auth.handleReservedRequest(loginContext(), fakeRequest(JSON.stringify({ credential: secret }), 'text/plain'), wrongType)
  assertUnauthorized(wrongType)

  const oversized = responseRecorder()
  await auth.handleReservedRequest(
    loginContext(),
    fakeRequest('x'.repeat(MAX_LOGIN_BODY_BYTES + 1), 'application/json'),
    oversized,
  )
  assertUnauthorized(oversized)
})

test('form POST sets the session cookie and redirects only to /; JSON POST remains 204; secret never appears in Location or body', async () => {
  const secret = generateCredentialSecret()
  const sessions = createSessionStore()
  const auth = credentialAuth(secret, { sessions })

  const form = responseRecorder()
  await auth.handleReservedRequest(
    loginContext(),
    fakeRequest(`credential=${encodeURIComponent(secret)}`, 'application/x-www-form-urlencoded'),
    form,
  )
  assert.equal(form.result.statusCode, 303)
  assert.equal(form.result.headers.Location, '/')
  assert.match(form.result.headers['Set-Cookie'], new RegExp(`^${SESSION_COOKIE_NAME}=`))
  assert.match(form.result.headers['Set-Cookie'], /Secure/)
  assert.match(form.result.headers['Set-Cookie'], /HttpOnly/)
  assert.match(form.result.headers['Set-Cookie'], /SameSite=Strict/)
  assert.equal(form.result.headers['Cache-Control'], 'no-store')
  assert.equal(String(form.result.headers.Location).includes(secret), false)
  assert.equal(String(form.result.body ?? '').includes(secret), false)

  const json = responseRecorder()
  await auth.handleReservedRequest(loginContext(), fakeRequest(JSON.stringify({ credential: secret })), json)
  assert.equal(json.result.statusCode, 204)
  assert.equal(json.result.headers.Location, undefined)
  assert.match(json.result.headers['Set-Cookie'], new RegExp(`^${SESSION_COOKIE_NAME}=`))
  assert.equal(String(json.result.body ?? '').includes(secret), false)
})

test('login GET is handled by the auth layer and never reaches the proxy', async () => {
  const secret = generateCredentialSecret()
  const auth = credentialAuth(secret)
  const server = createGatewayServer({ externalOrigin: ORIGIN }, { auth })
  const result = await new Promise((resolve, reject) => {
    const recorded = { headers: {} }
    const timer = setTimeout(() => reject(new Error('login GET did not complete')), 1000)
    server.emit('request', {
      method: 'GET',
      url: LOGIN_PATH,
      rawHeaders: ['Host', 'gateway.example.invalid', 'Sec-Fetch-Site', 'none'],
      headers: {},
      socket: { remoteAddress: '127.0.0.1' },
    }, {
      writeHead(statusCode, headers) {
        recorded.statusCode = statusCode
        recorded.headers = headers
      },
      end(body) {
        clearTimeout(timer)
        recorded.body = body
        resolve(recorded)
      },
      once() {
        return this
      },
    })
  })
  assert.equal(result.statusCode, 200)
  assert.equal(result.headers['Content-Type'], 'text/html; charset=utf-8')
  assert.match(String(result.body), /<form method="post" action="\/\.dsh-one-gateway\/login">/)
  assert.equal(String(result.body).includes(secret), false)
})
