import {
  AUTH_GATEWAY_CREDENTIAL,
  AUTH_SIGNED_JWT,
  AUTH_TRUSTED_HEADER,
  PROVIDER_CLOUDFLARE,
  PROVIDER_TAILSCALE,
} from '../core/constants.mjs'
import { createGatewayCredentialAuth } from './gateway-credential.mjs'
import { CLOUDFLARE_JWT_PROFILE, createSignedJwtAuth } from './signed-jwt.mjs'
import { createTrustedHeaderAuth, TAILSCALE_HEADER_PROFILE } from './trusted-header.mjs'

export async function createAuth(config, extras = {}) {
  if (!config?.enabled) throw new Error('dsh-gateway: cannot construct auth for a disabled config')
  const capability = config.identity
  if (config.auth.mode === AUTH_TRUSTED_HEADER) {
    if (capability.identityKind !== 'overwritten-header' || config.provider.type !== PROVIDER_TAILSCALE) {
      throw new Error('dsh-gateway: trusted-header requires a provider overwrite profile')
    }
    return createTrustedHeaderAuth({
      profile: TAILSCALE_HEADER_PROFILE,
      trustedPrincipals: config.auth.trustedPrincipals,
    })
  }
  if (config.auth.mode === AUTH_SIGNED_JWT) {
    if (capability.identityKind !== 'signed-jwt' || config.provider.type !== PROVIDER_CLOUDFLARE) {
      throw new Error('dsh-gateway: signed-jwt requires a provider JWT profile')
    }
    return createSignedJwtAuth({
      profile: CLOUDFLARE_JWT_PROFILE,
      trustedPrincipals: config.auth.trustedPrincipals,
      teamOrigin: config.provider.teamOrigin,
      applicationAudience: config.provider.applicationAudience,
      fetchImpl: extras.fetchImpl,
    })
  }
  if (config.auth.mode === AUTH_GATEWAY_CREDENTIAL) {
    if (capability.identityKind !== 'none') {
      throw new Error('dsh-gateway: gateway-credential requires identityCapability none')
    }
    return createGatewayCredentialAuth({
      trustedPrincipals: config.auth.trustedPrincipals,
      storePath: config.auth.credentialStorePath,
      externalOrigin: config.externalOrigin,
      loadStore: extras.loadStore,
      sessions: extras.sessions,
      limiter: extras.limiter,
    })
  }
  throw new Error('dsh-gateway: unsupported auth.mode')
}
