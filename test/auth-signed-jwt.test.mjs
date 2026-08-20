import assert from 'node:assert/strict'
import test from 'node:test'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import { createSignedJwtAuth } from '../src/auth/signed-jwt.mjs'
import { APPLICATION_AUDIENCE, CLOUDFLARE_ORIGIN, TEAM_ORIGIN } from './helpers.mjs'

async function makeKeys() {
  const current = await generateKeyPair('RS256', { extractable: true })
  const previous = await generateKeyPair('RS256', { extractable: true })
  const currentJwk = { ...await exportJWK(current.publicKey), kid: 'current', alg: 'RS256', use: 'sig' }
  const previousJwk = { ...await exportJWK(previous.publicKey), kid: 'previous', alg: 'RS256', use: 'sig' }
  return { current, previous, currentJwk, previousJwk }
}

function jwksFetch(keys) {
  return async () => new Response(JSON.stringify({ keys }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}

async function token(privateKey, { kid = 'current', claims = {}, header = {} } = {}) {
  const jwt = new SignJWT({
    email: 'operator@example.invalid',
    sub: 'account-1',
    type: 'app',
    ...claims,
  })
    .setProtectedHeader({ alg: 'RS256', kid, ...header })
    .setIssuer(TEAM_ORIGIN)
    .setAudience(APPLICATION_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime('10m')
  if (claims.nbf !== undefined) jwt.setNotBefore(claims.nbf)
  return jwt.sign(privateKey)
}

function context(assertion, extra = []) {
  const headers = ['Host', 'dsh.example.invalid']
  if (assertion !== undefined) headers.push('Cf-Access-Jwt-Assertion', assertion)
  return {
    remoteAddress: '127.0.0.1',
    rawHeaders: [...headers, ...extra],
    method: 'GET',
    url: '/',
  }
}

test('signed-jwt accepts a valid Access identity token and strips assertion headers', async () => {
  const keys = await makeKeys()
  const auth = createSignedJwtAuth({
    trustedPrincipals: ['email:operator@example.invalid'],
    teamOrigin: TEAM_ORIGIN,
    applicationAudience: APPLICATION_AUDIENCE,
    fetchImpl: jwksFetch([keys.currentJwk, keys.previousJwk]),
  })
  const assertion = await token(keys.current.privateKey)
  const result = await auth.authenticate(context(assertion))
  assert.equal(result.ok, true)
  assert.equal(result.principal.id, 'email:operator@example.invalid')
  assert.ok(result.consumedHeaders.includes('cf-access-jwt-assertion'))
})

test('signed-jwt denies missing, duplicate, malformed, unsigned, and wrong-key assertions', async () => {
  const keys = await makeKeys()
  const auth = createSignedJwtAuth({
    trustedPrincipals: ['email:operator@example.invalid'],
    teamOrigin: TEAM_ORIGIN,
    applicationAudience: APPLICATION_AUDIENCE,
    fetchImpl: jwksFetch([keys.currentJwk]),
  })
  assert.equal((await auth.authenticate(context(undefined))).reasonCode, 'assertion_missing_or_duplicate')
  assert.equal((await auth.authenticate(context('a.b.c', ['Cf-Access-Jwt-Assertion', 'd.e.f']))).reasonCode, 'assertion_missing_or_duplicate')
  assert.equal((await auth.authenticate(context('not-a-jwt'))).reasonCode, 'assertion_malformed')
  const other = await generateKeyPair('RS256', { extractable: true })
  const badSig = await token(other.privateKey)
  assert.equal((await auth.authenticate(context(badSig))).ok, false)
})

test('signed-jwt denies wrong issuer, audience, expiry, type, service tokens, and convenience-header-only requests', async () => {
  const keys = await makeKeys()
  const auth = createSignedJwtAuth({
    trustedPrincipals: ['email:operator@example.invalid'],
    teamOrigin: TEAM_ORIGIN,
    applicationAudience: APPLICATION_AUDIENCE,
    fetchImpl: jwksFetch([keys.currentJwk]),
  })
  const wrongIss = await new SignJWT({ email: 'operator@example.invalid', sub: 'account-1', type: 'app' })
    .setProtectedHeader({ alg: 'RS256', kid: 'current' })
    .setIssuer('https://other.example.invalid')
    .setAudience(APPLICATION_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime('10m')
    .sign(keys.current.privateKey)
  assert.equal((await auth.authenticate(context(wrongIss))).ok, false)

  const wrongAud = await new SignJWT({ email: 'operator@example.invalid', sub: 'account-1', type: 'app' })
    .setProtectedHeader({ alg: 'RS256', kid: 'current' })
    .setIssuer(TEAM_ORIGIN)
    .setAudience('some-other-aud')
    .setIssuedAt()
    .setExpirationTime('10m')
    .sign(keys.current.privateKey)
  assert.equal((await auth.authenticate(context(wrongAud))).ok, false)

  const expired = await new SignJWT({ email: 'operator@example.invalid', sub: 'account-1', type: 'app' })
    .setProtectedHeader({ alg: 'RS256', kid: 'current' })
    .setIssuer(TEAM_ORIGIN)
    .setAudience(APPLICATION_AUDIENCE)
    .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
    .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
    .sign(keys.current.privateKey)
  assert.equal((await auth.authenticate(context(expired))).ok, false)

  const service = await new SignJWT({ sub: '', type: 'service' })
    .setProtectedHeader({ alg: 'RS256', kid: 'current' })
    .setIssuer(TEAM_ORIGIN)
    .setAudience(APPLICATION_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime('10m')
    .sign(keys.current.privateKey)
  assert.equal((await auth.authenticate(context(service))).ok, false)

  const convenienceOnly = context(undefined, ['Cf-Access-Authenticated-User-Email', 'operator@example.invalid'])
  assert.equal((await auth.authenticate(convenienceOnly)).ok, false)

  const valid = await token(keys.current.privateKey)
  const mismatch = await auth.authenticate(context(valid, ['Cf-Access-Authenticated-User-Email', 'other@example.invalid']))
  assert.equal(mismatch.reasonCode, 'convenience_header_mismatch')
  void CLOUDFLARE_ORIGIN
})

test('current and previous JWKS keys validate; unknown kid and failed JWKS fetch deny', async () => {
  const keys = await makeKeys()
  const auth = createSignedJwtAuth({
    trustedPrincipals: ['email:operator@example.invalid'],
    teamOrigin: TEAM_ORIGIN,
    applicationAudience: APPLICATION_AUDIENCE,
    fetchImpl: jwksFetch([keys.currentJwk, keys.previousJwk]),
  })
  const previousToken = await token(keys.previous.privateKey, { kid: 'previous' })
  assert.equal((await auth.authenticate(context(previousToken))).ok, true)

  const unknownKid = await token(keys.current.privateKey, { kid: 'removed' })
  assert.equal((await auth.authenticate(context(unknownKid))).ok, false)

  const failing = createSignedJwtAuth({
    trustedPrincipals: ['email:operator@example.invalid'],
    teamOrigin: TEAM_ORIGIN,
    applicationAudience: APPLICATION_AUDIENCE,
    fetchImpl: async () => { throw new Error('network') },
  })
  const ready = await failing.readiness()
  assert.equal(ready.ready, false)
})

test('JWKS redirects, oversized bodies, and duplicate kids fail closed', async () => {
  const keys = await makeKeys()
  const redirecting = createSignedJwtAuth({
    trustedPrincipals: ['email:operator@example.invalid'],
    teamOrigin: TEAM_ORIGIN,
    applicationAudience: APPLICATION_AUDIENCE,
    fetchImpl: async () => { throw Object.assign(new Error('redirect'), { name: 'TypeError' }) },
  })
  assert.equal((await redirecting.readiness()).ready, false)

  const oversized = createSignedJwtAuth({
    trustedPrincipals: ['email:operator@example.invalid'],
    teamOrigin: TEAM_ORIGIN,
    applicationAudience: APPLICATION_AUDIENCE,
    fetchImpl: async () => new Response('x'.repeat(70 * 1024), { status: 200, headers: { 'content-type': 'application/json' } }),
  })
  assert.equal((await oversized.readiness()).ready, false)

  const duplicate = createSignedJwtAuth({
    trustedPrincipals: ['email:operator@example.invalid'],
    teamOrigin: TEAM_ORIGIN,
    applicationAudience: APPLICATION_AUDIENCE,
    fetchImpl: jwksFetch([keys.currentJwk, { ...keys.previousJwk, kid: 'current' }]),
  })
  assert.equal((await duplicate.readiness()).ready, false)
})
