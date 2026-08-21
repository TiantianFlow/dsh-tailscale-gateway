import { GATEWAY_HOST } from '../src/core/constants.mjs'

export const TAILSCALE_ORIGIN = 'https://gateway.example-tailnet.ts.net:8443'
export const CLOUDFLARE_ORIGIN = 'https://dsh.example.invalid'
export const TEAM_ORIGIN = 'https://team.example.invalid'
export const APPLICATION_AUDIENCE = 'replace-with-access-application-audience'
export const OPERATOR_LOGIN = 'login:operator@example.invalid'
export const OPERATOR_EMAIL = 'email:operator@example.invalid'
export const HEADSCALE_ORIGIN = 'https://gateway.example.invalid:8443'
export const OPERATOR_CREDENTIAL = 'credential:operator-1'
export const CREDENTIAL_STORE_PATH = '/path/to/dsh-one-gateway/credentials.json'
export const TLS_CERT_PATH = '/path/to/dsh-one-gateway/cert.pem'
export const TLS_KEY_PATH = '/path/to/dsh-one-gateway/key.pem'

export function tailscaleConfig(overrides = {}) {
  return {
    enabled: true,
    externalOrigin: TAILSCALE_ORIGIN,
    provider: { type: 'tailscale-serve', routeManagement: 'ensure' },
    auth: { mode: 'trusted-header', trustedPrincipals: [OPERATOR_LOGIN] },
    ...overrides,
  }
}

export function headscaleTcpConfig(overrides = {}) {
  return {
    enabled: true,
    externalOrigin: HEADSCALE_ORIGIN,
    provider: { type: 'headscale-tcp-serve', routeManagement: 'ensure' },
    auth: {
      mode: 'gateway-credential',
      trustedPrincipals: [OPERATOR_CREDENTIAL],
      credentialStorePath: CREDENTIAL_STORE_PATH,
    },
    tls: { certPath: TLS_CERT_PATH, keyPath: TLS_KEY_PATH },
    ...overrides,
  }
}

export function cloudflareConfig(overrides = {}) {
  return {
    enabled: true,
    externalOrigin: CLOUDFLARE_ORIGIN,
    provider: {
      type: 'cloudflare-access',
      routeManagement: 'verify-only',
      teamOrigin: TEAM_ORIGIN,
      applicationAudience: APPLICATION_AUDIENCE,
    },
    auth: { mode: 'signed-jwt', trustedPrincipals: [OPERATOR_EMAIL] },
    ...overrides,
  }
}

export function rawHeaders({
  host = 'gateway.example-tailnet.ts.net:8443',
  login = 'operator@example.invalid',
  origin,
  fetchSite,
  extra = [],
} = {}) {
  const headers = ['Host', host]
  if (login !== undefined && login !== null) headers.push('Tailscale-User-Login', login)
  if (origin !== undefined) headers.push('Origin', origin)
  if (fetchSite !== undefined) headers.push('Sec-Fetch-Site', fetchSite)
  return [...headers, ...extra]
}

export function request(overrides = {}) {
  return {
    remoteAddress: GATEWAY_HOST,
    rawHeaders: rawHeaders(),
    method: 'GET',
    url: '/',
    ...overrides,
  }
}

export function stubAuth(overrides = {}) {
  return {
    authenticate: async () => ({ ok: true, principal: { id: OPERATOR_LOGIN, kind: 'trusted-header' }, consumedHeaders: ['tailscale-user-login'], consumedCookies: [] }),
    handleReservedRequest: async () => ({ handled: false }),
    readiness: async () => ({ ready: true }),
    close: async () => {},
    ...overrides,
  }
}
