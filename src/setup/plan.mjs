import {
  AUTH_GATEWAY_CREDENTIAL,
  AUTH_SIGNED_JWT,
  AUTH_TRUSTED_HEADER,
  PROVIDER_CLOUDFLARE,
  PROVIDER_HEADSCALE_TCP_SERVE,
  PROVIDER_TAILSCALE,
  ROUTE_ENSURE,
  ROUTE_VERIFY_ONLY,
} from '../core/constants.mjs'
import { assertSafeConfig, normalizeExternalOrigin, parseTrustedPrincipals } from '../core/config.mjs'
import { classifyTcpServeStatus, tcpServeArgv, tcpServeRoute } from '../providers/headscale-tcp-serve.mjs'
import { classifyServeStatus } from '../providers/tailscale-serve.mjs'
import { classifyControlPlane } from './detect.mjs'
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

export function inferHeadscaleNode(status, { allowOfficial = false } = {}) {
  const plane = classifyControlPlane(status)
  if (plane.kind === 'disconnected') {
    throw new Error(`Tailscale backend is not running (${plane.reason})`)
  }
  if (plane.kind === 'unknown' || plane.kind === 'ambiguous') {
    throw new Error(plane.reason ?? 'Tailscale control plane could not be classified')
  }
  if (plane.kind === 'official' && !allowOfficial) {
    throw new Error('this node is on Tailscale.com; use tailscale-serve for identity-aware HTTPS Serve instead of the weaker headscale-tcp-serve path')
  }
  if (!record(status.Self)) throw new Error('Tailscale status has no Self node record')
  if (Array.isArray(status.Self.Tags) && status.Self.Tags.length > 0) {
    throw new Error('this is a tagged Tailscale node; refusing Headscale TCP Serve setup')
  }
  if (!plane.hostname) {
    throw new Error('Tailscale status did not provide a usable MagicDNS name')
  }
  return Object.freeze({ hostname: plane.hostname, controlPlane: plane.kind })
}

export function selectTcpOrigin(hostname, serveStatus, ports = DEFAULT_HTTPS_PORTS) {
  if (!Array.isArray(ports) || ports.length === 0) throw new Error('no candidate HTTPS ports were supplied')
  let absent
  for (const port of ports) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue
    const origin = normalizeExternalOrigin(originFor(hostname, port))
    const verdict = classifyTcpServeStatus(serveStatus, origin)
    if (verdict.kind === 'exact') return Object.freeze({ externalOrigin: origin, routeState: 'exact' })
    if (verdict.kind === 'absent' && absent === undefined) absent = origin
  }
  if (absent !== undefined) return Object.freeze({ externalOrigin: absent, routeState: 'absent' })
  throw new Error('no safe TCP Serve port was found; choose one manually and resolve any Serve conflicts')
}

export function createHeadscaleTcpPlan(tailscaleStatus, serveStatus, {
  ports = DEFAULT_HTTPS_PORTS,
  trustedPrincipal,
  tlsCertPath,
  tlsKeyPath,
  credentialStorePath,
  externalOrigin,
  allowOfficial = false,
  activationToken = createActivationToken(),
} = {}) {
  if (!tlsCertPath || !tlsKeyPath || !credentialStorePath) {
    throw new Error('headscale-tcp-serve setup requires --tls-cert, --tls-key, and --credential-store')
  }
  const node = inferHeadscaleNode(tailscaleStatus, { allowOfficial })
  let selected
  if (externalOrigin) {
    const origin = normalizeExternalOrigin(externalOrigin)
    const hostname = new URL(origin).hostname
    if (hostname !== node.hostname) {
      throw new Error(`externalOrigin hostname ${hostname} does not match the live MagicDNS name ${node.hostname}`)
    }
    const verdict = classifyTcpServeStatus(serveStatus, origin)
    if (verdict.kind === 'conflict') {
      throw new Error(`TCP Serve port is in conflict: ${verdict.reason}`)
    }
    selected = Object.freeze({ externalOrigin: origin, routeState: verdict.kind })
  } else {
    selected = selectTcpOrigin(node.hostname, serveStatus, ports)
  }
  const rawName = trustedPrincipal ?? 'operator-1'
  const principalValue = rawName.startsWith('credential:') ? rawName : `credential:${rawName}`
  const [principal] = parseTrustedPrincipals([principalValue], 'credential')
  const config = {
    enabled: true,
    externalOrigin: selected.externalOrigin,
    provider: { type: PROVIDER_HEADSCALE_TCP_SERVE, routeManagement: ROUTE_ENSURE },
    auth: {
      mode: AUTH_GATEWAY_CREDENTIAL,
      trustedPrincipals: [principal],
      credentialStorePath,
    },
    tls: { certPath: tlsCertPath, keyPath: tlsKeyPath },
    activationToken,
  }
  const route = tcpServeRoute(selected.externalOrigin)
  return Object.freeze({
    provider: PROVIDER_HEADSCALE_TCP_SERVE,
    externalOrigin: selected.externalOrigin,
    routeState: selected.routeState,
    trustedPrincipal: principal,
    credentialName: principal.slice('credential:'.length),
    tlsCertPath,
    tlsKeyPath,
    credentialStorePath,
    controlPlane: node.controlPlane,
    config: assertSafeConfig(config),
    notes: Object.freeze([
      'Auth mode: gateway-credential. TCP Serve supplies private reachability only; it has no user identity to offer.',
      'The gateway terminates TLS on 127.0.0.1:3088 using the operator-supplied certificate. Clients must trust that certificate; this pass does not generate a CA.',
      selected.routeState === 'exact'
        ? 'An exact private TCP Serve route already exists; ensure will leave it unchanged.'
        : 'ensure may create exactly one absent TCP Serve forward to 127.0.0.1:3088. Conflicts and Funnel are refused.',
      `Planned operation: tailscale ${tcpServeArgv(route.tcpPort).join(' ')}`,
      'Setup issues one named gateway credential after confirmation. --print issues nothing. The raw secret is shown once and is never written to the profile.',
    ]),
  })
}

export function describePlan(plan) {
  const extra = []
  if (plan.tlsCertPath) extra.push(`TLS cert: ${plan.tlsCertPath}`)
  if (plan.tlsKeyPath) extra.push(`TLS key: ${plan.tlsKeyPath}`)
  if (plan.credentialStorePath) extra.push(`Credential store: ${plan.credentialStorePath}`)
  return [
    `Provider: ${plan.provider}`,
    `External origin: ${plan.externalOrigin}`,
    `Auth principal: ${plan.trustedPrincipal}`,
    `Route state: ${plan.routeState}`,
    ...extra,
    ...plan.notes.map(note => `- ${note}`),
  ].join('\n')
}
