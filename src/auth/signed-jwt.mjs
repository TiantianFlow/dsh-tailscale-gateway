import { jwtVerify, errors as joseErrors } from 'jose'
import {
  AUTH_SIGNED_JWT,
  CLOCK_SKEW_SECONDS,
  JWT_MAX_BYTES,
} from '../core/constants.mjs'
import { exactlyOneRawHeader, rawHeaderValues } from '../core/headers.mjs'
import { denyAuth, notReady, okPrincipal, readyOk, unhandled } from './contract.mjs'
import { createJwksCache } from './jwks.mjs'
import { allowlistContains } from './timing.mjs'

export const CLOUDFLARE_JWT_PROFILE = Object.freeze({
  profileId: 'cloudflare-access-v1',
  headerName: 'cf-access-jwt-assertion',
  convenienceHeaderName: 'cf-access-authenticated-user-email',
  cookieName: 'CF_Authorization',
  principalNamespace: 'email',
  algorithms: Object.freeze(['RS256']),
  requiredType: 'app',
})

function scalarString(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 254 && value.trim() === value
}

export function createSignedJwtAuth({
  profile = CLOUDFLARE_JWT_PROFILE,
  trustedPrincipals,
  teamOrigin,
  applicationAudience,
  fetchImpl,
  now = Date.now,
  jwksCache,
}) {
  if (profile.profileId !== CLOUDFLARE_JWT_PROFILE.profileId) {
    throw new Error('dsh-one-gateway: unknown signed-jwt profile')
  }
  const cache = jwksCache ?? createJwksCache({ teamOrigin, fetchImpl, now })
  const consumedHeaders = Object.freeze([
    profile.headerName,
    profile.convenienceHeaderName,
  ])
  const consumedCookies = Object.freeze([profile.cookieName])

  return {
    mode: AUTH_SIGNED_JWT,
    profileId: profile.profileId,
    async authenticate(requestContext) {
      try {
        const assertions = rawHeaderValues(requestContext.rawHeaders, profile.headerName)
        if (assertions.length !== 1) return denyAuth('assertion_missing_or_duplicate')
        const token = exactlyOneRawHeader(requestContext.rawHeaders, profile.headerName)
        if (typeof token !== 'string' || token.length === 0 || token.length > JWT_MAX_BYTES) {
          return denyAuth('assertion_malformed')
        }
        const parts = token.split('.')
        if (parts.length !== 3) return denyAuth('assertion_malformed')

        const keys = await cache.get()
        const verified = await jwtVerify(token, keys.keySet, {
          algorithms: [...profile.algorithms],
          issuer: teamOrigin,
          audience: applicationAudience,
          clockTolerance: CLOCK_SKEW_SECONDS,
          currentDate: new Date(now()),
          requiredClaims: ['exp', 'iat', 'sub', 'email'],
        })
        const claims = verified.payload
        if (Array.isArray(claims.aud) && claims.aud.length !== 1) return denyAuth('audience_invalid')
        if (claims.type !== profile.requiredType) return denyAuth('token_type_denied')
        if (!scalarString(claims.email) || Array.isArray(claims.email) || typeof claims.email === 'object') {
          return denyAuth('principal_claim_invalid')
        }
        if (!scalarString(claims.sub)) return denyAuth('sub_missing')
        const principalId = `${profile.principalNamespace}:${claims.email}`
        if (!allowlistContains(trustedPrincipals, principalId)) return denyAuth('identity_not_allowlisted')

        const convenience = rawHeaderValues(requestContext.rawHeaders, profile.convenienceHeaderName)
        if (convenience.length > 1) return denyAuth('convenience_header_duplicate')
        if (convenience.length === 1 && convenience[0] !== claims.email) return denyAuth('convenience_header_mismatch')

        return okPrincipal(
          { id: principalId, kind: 'signed-jwt', display: claims.email },
          { consumedHeaders, consumedCookies },
        )
      } catch (error) {
        if (error instanceof joseErrors.JOSEError) return denyAuth('assertion_invalid')
        if (typeof error?.message === 'string' && error.message.startsWith('jwks_')) return denyAuth(error.message)
        return denyAuth('assertion_invalid')
      }
    },
    async handleReservedRequest() {
      return unhandled()
    },
    async readiness() {
      if (trustedPrincipals.length === 0) return notReady('empty_allowlist')
      const keys = await cache.readiness()
      return keys.ready ? readyOk() : notReady(keys.reasonCode)
    },
    async close() {},
  }
}
