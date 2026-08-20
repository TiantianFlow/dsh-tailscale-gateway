import {
  AUTH_SIGNED_JWT,
  AUTH_TRUSTED_HEADER,
  PROVIDER_CLOUDFLARE,
  PROVIDER_TAILSCALE,
  ROUTE_ENSURE,
  ROUTE_VERIFY_ONLY,
} from '../core/constants.mjs'
import { assertSafeConfig, normalizeExternalOrigin, parseTrustedPrincipals } from '../core/config.mjs'
import { classifyServeStatus } from '../providers/tailscale-serve.mjs'
import { createActivationToken } from './secrets.mjs'

export const DEFAULT_HTTPS_PORTS = Object.freeze([443, ...Array.from({ length: 57 }, (_, index) => 8443 + index)])

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function originFor(hostname, port) {
  return port === 443 ? `https://${hostname}` : `https://${hostname}:${port}`
}

/**
 * Derive the single Tailscale identity that owns this node. `Self.UserLogin`
 * is not consistently populated, so follow Self.UserID into the User map.
 */
export function inferNodeIdentity(status) {
  if (!record(status) || !record(status.Self)) {
    throw new Error('Tailscale status has no Self node record')
  }
  const self = status.Self
  if (Array.isArray(self.Tags) && self.Tags.length > 0) {
    throw new Error('this is a tagged Tailscale node; Tailscale Serve will not provide a user-login identity')
  }
  if (typeof self.DNSName !== 'string') {
    throw new Error('Tailscale status has no MagicDNS name; enable HTTPS and MagicDNS first')
  }
  const hostname = self.DNSName.replace(/\.+$/, '')
  if (!hostname.endsWith('.ts.net') || hostname === '.ts.net') {
    throw new Error('Tailscale status did not provide a usable *.ts.net MagicDNS name')
  }
  if (self.UserID === undefined || self.UserID === null || !record(status.User)) {
    throw new Error('Tailscale status has no node-owner identity')
  }
  const user = status.User[String(self.UserID)]
  if (!record(user) || typeof user.LoginName !== 'string') {
    throw new Error('Tailscale status could not resolve the node owner login')
  }
  const [login] = parseTrustedPrincipals([`login:${user.LoginName}`], 'login')
  return Object.freeze({ hostname, login, loginValue: user.LoginName })
}

export function selectInitialOrigin(hostname, serveStatus, ports = DEFAULT_HTTPS_PORTS) {
  if (!Array.isArray(ports) || ports.length === 0) throw new Error('no candidate HTTPS ports were supplied')
  let absent
  for (const port of ports) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue
    const origin = normalizeExternalOrigin(originFor(hostname, port), { requireTailscaleDns: true })
    const verdict = classifyServeStatus(serveStatus, origin)
    if (verdict.kind === 'exact') return Object.freeze({ externalOrigin: origin, routeState: 'exact' })
    if (verdict.kind === 'absent' && absent === undefined) absent = origin
  }
  if (absent !== undefined) return Object.freeze({ externalOrigin: absent, routeState: 'absent' })
  throw new Error('no safe HTTPS port was found; choose one manually and resolve any Tailscale Serve conflicts')
}

export function createTailscalePlan(tailscaleStatus, serveStatus, {
  ports = DEFAULT_HTTPS_PORTS,
  trustedLogin,
  activationToken = createActivationToken(),
} = {}) {
  const identity = inferNodeIdentity(tailscaleStatus)
  const selected = selectInitialOrigin(identity.hostname, serveStatus, ports)
  const loginValue = trustedLogin ?? identity.loginValue
  const [principal] = parseTrustedPrincipals([loginValue.startsWith('login:') ? loginValue : `login:${loginValue}`], 'login')
  const config = {
    enabled: true,
    externalOrigin: selected.externalOrigin,
    provider: { type: PROVIDER_TAILSCALE, routeManagement: ROUTE_ENSURE },
    auth: { mode: AUTH_TRUSTED_HEADER, trustedPrincipals: [principal] },
    activationToken,
  }
  return Object.freeze({
    provider: PROVIDER_TAILSCALE,
    externalOrigin: selected.externalOrigin,
    routeState: selected.routeState,
    trustedPrincipal: principal,
    inferredLogin: identity.loginValue,
    config: assertSafeConfig(config),
    notes: Object.freeze([
      'Auth mode: trusted-header. This proves the exact Tailscale-User-Login Serve injects, not mesh membership.',
      selected.routeState === 'exact'
        ? 'An exact private Serve route already exists; ensure will leave it unchanged.'
        : 'ensure may create exactly one absent private Serve root route. Conflicts and Funnel are refused.',
      'Persistent Serve routes are not removed on disable or uninstall.',
    ]),
  })
}

export function createCloudflarePlan({
  externalOrigin,
  teamOrigin,
  applicationAudience,
  trustedEmail,
  activationToken = createActivationToken(),
}) {
  if (!externalOrigin || !teamOrigin || !applicationAudience || !trustedEmail) {
    throw new Error('cloudflare-access setup requires --external-origin, --team-origin, --application-audience, and --trusted-principal')
  }
  const emailValue = trustedEmail.startsWith('email:') ? trustedEmail : `email:${trustedEmail}`
  const [principal] = parseTrustedPrincipals([emailValue], 'email')
  const config = {
    enabled: true,
    externalOrigin,
    provider: {
      type: PROVIDER_CLOUDFLARE,
      routeManagement: ROUTE_VERIFY_ONLY,
      teamOrigin,
      applicationAudience,
    },
    auth: { mode: AUTH_SIGNED_JWT, trustedPrincipals: [principal] },
    activationToken,
  }
  return Object.freeze({
    provider: PROVIDER_CLOUDFLARE,
    externalOrigin: normalizeExternalOrigin(externalOrigin, { rejectQuickTunnel: true }),
    routeState: 'verify-only',
    trustedPrincipal: principal,
    config: assertSafeConfig(config),
    notes: Object.freeze([
      'Auth mode: signed-jwt. This proves a locally validated Cloudflare Access identity token (RS256, iss, aud, email, sub), not a convenience email header.',
      'routeManagement is verify-only. Setup does not create tunnels, Access applications, or DNS records.',
      'A reliable machine-readable Access-attachment check is not available without broad account credentials. Confirm the hostname is an Access application that forwards only to 127.0.0.1:3088.',
      'Do not use a quick tunnel or a tunnel without Access. The gateway will still reject requests without a valid Access JWT, but that is not a substitute for attaching Access.',
      'Cloudflare\'s edge may be internet-routable. Authorization is the Access JWT plus the gateway allowlist, not network reachability.',
    ]),
  })
}

export function describePlan(plan) {
  return [
    `Provider: ${plan.provider}`,
    `External origin: ${plan.externalOrigin}`,
    `Auth principal: ${plan.trustedPrincipal}`,
    `Route state: ${plan.routeState}`,
    ...plan.notes.map(note => `- ${note}`),
  ].join('\n')
}
