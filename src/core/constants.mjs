export const PACKAGE_NAME = 'dsh-one-gateway'
export const USER_INSTANCE_ID = 'dsh-one-gateway-user-instance'
export const BASELINE_INSTANCE_ID = 'dsh-one-gateway'
export const PREVIOUS_PACKAGE_NAME = 'dsh-gateway'
export const PREVIOUS_USER_INSTANCE_ID = 'dsh-gateway-user-instance'
export const LEGACY_PACKAGE_NAME = 'dsh-tailscale-gateway'
export const LEGACY_USER_INSTANCE_ID = 'dsh-tailscale-gateway-user-instance'

export const GATEWAY_HOST = '127.0.0.1'
export const GATEWAY_PORT = 3088
export const UPSTREAM_HOST = '127.0.0.1'
export const UPSTREAM_PORT = 3080
export const UPSTREAM_ORIGIN = `http://${UPSTREAM_HOST}:${UPSTREAM_PORT}`
export const UPSTREAM_AUTHORITY = `${UPSTREAM_HOST}:${UPSTREAM_PORT}`

export const ACTIVATION_TOKEN_BYTES = 32
export const READINESS_PATH = '/.dsh-one-gateway/ready'
export const LOGIN_PATH = '/.dsh-one-gateway/login'
export const SESSION_COOKIE_NAME = '__Host-dsh-one-gateway-session'

export const MAX_DECLARED_REQUEST_BYTES = 160 * 1024 * 1024
export const MAX_LOGIN_BODY_BYTES = 4096
export const MAX_IN_FLIGHT = 128
export const MAX_TRUSTED_PRINCIPALS = 64
export const MAX_PRINCIPAL_LENGTH = 254
export const IDENTITY_HEADER_MAX_BYTES = 1024
export const JWT_MAX_BYTES = 16 * 1024
export const JWKS_MAX_BYTES = 64 * 1024
export const JWKS_TIMEOUT_MS = 5_000
export const JWKS_FRESH_MS = 6 * 60 * 60 * 1000
export const JWKS_STALE_MS = 60 * 60 * 1000
export const CLOCK_SKEW_SECONDS = 60
export const UPSTREAM_TIMEOUT_MS = 30_000
export const COMMAND_TIMEOUT_MS = 15_000
export const MAX_COMMAND_OUTPUT_BYTES = 256 * 1024

export const PROVIDER_TAILSCALE = 'tailscale-serve'
export const PROVIDER_CLOUDFLARE = 'cloudflare-access'
export const PROVIDER_HEADSCALE_TCP_SERVE = 'headscale-tcp-serve'
export const PROVIDER_EASYTIER = 'easytier'

export const AUTH_TRUSTED_HEADER = 'trusted-header'
export const AUTH_SIGNED_JWT = 'signed-jwt'
export const AUTH_GATEWAY_CREDENTIAL = 'gateway-credential'

export const ROUTE_ENSURE = 'ensure'
export const ROUTE_VERIFY_ONLY = 'verify-only'

export const TAILSCALE_PROFILE_ID = 'tailscale-user-login-v1'
export const CLOUDFLARE_PROFILE_ID = 'cloudflare-access-v1'

export const COMPATIBILITY = Object.freeze({
  [PROVIDER_TAILSCALE]: Object.freeze({
    authMode: AUTH_TRUSTED_HEADER,
    identityKind: 'overwritten-header',
    profileId: TAILSCALE_PROFILE_ID,
    principalNamespace: 'login',
  }),
  [PROVIDER_CLOUDFLARE]: Object.freeze({
    authMode: AUTH_SIGNED_JWT,
    identityKind: 'signed-jwt',
    profileId: CLOUDFLARE_PROFILE_ID,
    principalNamespace: 'email',
  }),
  [PROVIDER_HEADSCALE_TCP_SERVE]: Object.freeze({
    authMode: AUTH_GATEWAY_CREDENTIAL,
    identityKind: 'none',
    principalNamespace: 'credential',
  }),
})
