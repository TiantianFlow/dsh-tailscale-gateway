import { IDENTITY_HEADER_MAX_BYTES } from '../core/constants.mjs'
import { exactlyOneRawHeader, rawHeaderValues } from '../core/headers.mjs'
import { denyAuth, notReady, okPrincipal, readyOk, unhandled } from './contract.mjs'
import { allowlistContains } from './timing.mjs'

export const TAILSCALE_HEADER_PROFILE = Object.freeze({
  profileId: 'tailscale-user-login-v1',
  headerName: 'tailscale-user-login',
  principalNamespace: 'login',
  minLength: 3,
  maxLength: 254,
})

function isValidIdentityValue(value, profile) {
  return (
    typeof value === 'string' &&
    value.length >= profile.minLength &&
    value.length <= profile.maxLength &&
    value.length <= IDENTITY_HEADER_MAX_BYTES &&
    value.trim() === value &&
    /^[\x21-\x7e]+$/.test(value)
  )
}

export function createTrustedHeaderAuth({ profile, trustedPrincipals }) {
  if (!profile?.profileId || !profile.headerName || !profile.principalNamespace) {
    throw new Error('dsh-gateway: trusted-header requires a compiled provider identity profile')
  }
  if (profile.profileId !== TAILSCALE_HEADER_PROFILE.profileId) {
    throw new Error('dsh-gateway: unknown trusted-header profile')
  }
  const consumedHeaders = Object.freeze([profile.headerName])

  return {
    mode: 'trusted-header',
    profileId: profile.profileId,
    async authenticate(requestContext) {
      const values = rawHeaderValues(requestContext.rawHeaders, profile.headerName)
      if (values.length !== 1) return denyAuth('identity_missing_or_duplicate')
      const value = exactlyOneRawHeader(requestContext.rawHeaders, profile.headerName)
      if (!isValidIdentityValue(value, profile)) return denyAuth('identity_malformed')
      const principalId = `${profile.principalNamespace}:${value}`
      if (!allowlistContains(trustedPrincipals, principalId)) return denyAuth('identity_not_allowlisted')
      return okPrincipal({ id: principalId, kind: 'trusted-header' }, { consumedHeaders })
    },
    async handleReservedRequest() {
      return unhandled()
    },
    async readiness() {
      return trustedPrincipals.length > 0 ? readyOk() : notReady('empty_allowlist')
    },
    async close() {},
  }
}
