import {
  GATEWAY_HOST,
  GATEWAY_PORT,
  PROVIDER_HEADSCALE_TCP_SERVE,
  ROUTE_ENSURE,
  ROUTE_VERIFY_ONLY,
} from '../core/constants.mjs'
import { httpsPortFromOrigin } from '../core/origin.mjs'
import { runArgvCommand } from './command.mjs'
import {
  funnelEnabledForRoute,
  invokeTailscale,
  isRecord,
  parseServeStatusJson,
  statusAuthorityPort,
} from './tailscale-status.mjs'

export const TCP_SERVE_TARGET = `${GATEWAY_HOST}:${GATEWAY_PORT}`
export const TCP_SERVE_PROXY = `tcp://${TCP_SERVE_TARGET}`

export function tcpServeRoute(externalOrigin) {
  const httpsPort = httpsPortFromOrigin(externalOrigin)
  return Object.freeze({
    tcpPort: httpsPort,
    target: TCP_SERVE_TARGET,
    proxy: TCP_SERVE_PROXY,
  })
}

/** Exact supported create argv. `--bg` is required so apply does not block. */
export function tcpServeArgv(port) {
  return Object.freeze(['serve', '--tcp', String(port), '--bg', TCP_SERVE_PROXY])
}

function webClaimsPort(web, port) {
  return Object.entries(web ?? {}).some(([authority]) => statusAuthorityPort(authority) === port)
}

/**
 * Classify only the TCP Serve route this gateway would own. Exact means one
 * TCP-forward entry to 127.0.0.1:3088 with no HTTPS/Web handler, extra option,
 * or Funnel/public state on that port. Unknown JSON shapes throw (inspection
 * error) and are never treated as absent.
 */
export function classifyTcpServeStatus(status, externalOrigin) {
  if (!isRecord(status)) throw new Error('Tailscale Serve status is not a JSON object')
  const route = tcpServeRoute(externalOrigin)
  const web = status.Web
  const tcp = status.TCP
  if (web !== undefined && !isRecord(web)) throw new Error('Tailscale Serve status has an invalid Web section')
  if (tcp !== undefined && !isRecord(tcp)) throw new Error('Tailscale Serve status has an invalid TCP section')
  if (funnelEnabledForRoute(status, String(route.tcpPort), route.tcpPort)) {
    return { kind: 'conflict', route, reason: 'Funnel is enabled for the requested TCP Serve route' }
  }

  const tcpHandler = tcp?.[String(route.tcpPort)]
  if (webClaimsPort(web, route.tcpPort)) {
    return { kind: 'conflict', route, reason: `TCP port ${route.tcpPort} is already claimed by an HTTPS/Web Serve handler` }
  }
  if (tcpHandler === undefined) {
    return { kind: 'absent', route }
  }
  if (!isRecord(tcpHandler)) {
    return { kind: 'conflict', route, reason: `TCP port ${route.tcpPort} has a malformed Serve handler` }
  }
  if (tcpHandler.HTTPS === true || tcpHandler.HTTP === true) {
    return { kind: 'conflict', route, reason: `TCP port ${route.tcpPort} is claimed by an HTTPS/HTTP Serve listener` }
  }
  if (tcpHandler.TerminateTLS !== undefined) {
    return { kind: 'conflict', route, reason: `TCP port ${route.tcpPort} has unexpected TLS-termination settings` }
  }
  const keys = Object.keys(tcpHandler)
  if (tcpHandler.TCPForward === route.target && keys.length === 1) {
    return { kind: 'exact', route }
  }
  if (typeof tcpHandler.TCPForward === 'string' && tcpHandler.TCPForward !== route.target) {
    return { kind: 'conflict', route, reason: `TCP port ${route.tcpPort} forwards to ${tcpHandler.TCPForward}, not ${route.target}` }
  }
  return { kind: 'conflict', route, reason: `TCP port ${route.tcpPort} has unexpected Serve listener settings` }
}

export function describeTcpServeStatus(status) {
  if (!isRecord(status)) return 'TCP Serve status is not a JSON object'
  if (status.TCP !== undefined && !isRecord(status.TCP)) return 'TCP Serve status has an invalid TCP section'
  const lines = []
  for (const [port, handler] of Object.entries(status.TCP ?? {})) {
    if (!isRecord(handler)) {
      lines.push(`${port} (malformed)`)
      continue
    }
    if (typeof handler.TCPForward === 'string') lines.push(`${port} TCPForward=${handler.TCPForward}`)
    else if (handler.HTTPS === true) lines.push(`${port} HTTPS=true`)
    else lines.push(`${port} ${JSON.stringify(handler)}`)
  }
  const funnel = funnelEnabledForRoute(status, '', 0) || ['AllowFunnel', '#AllowFunnel', 'Funnel'].some(field => {
    const configured = status[field]
    if (configured === true) return true
    if (Array.isArray(configured) && configured.length > 0) return true
    return isRecord(configured) && Object.values(configured).some(Boolean)
  })
  return Object.freeze({
    handlers: lines.length === 0 ? Object.freeze(['(none)']) : Object.freeze(lines),
    funnel,
  })
}

export const headscaleTcpServeProvider = {
  id: PROVIDER_HEADSCALE_TCP_SERVE,
  identityCapability() {
    return { kind: 'none' }
  },
  requiredExecutables() {
    return ['tailscale']
  },
  async inspect(config, runtime = {}) {
    const result = await invokeTailscale(
      runtime.run ?? runArgvCommand,
      runtime.tailscaleBinary,
      ['serve', 'status', '--json'],
      'Serve status inspection',
    )
    return classifyTcpServeStatus(parseServeStatusJson(result.stdout), config.externalOrigin)
  },
  plan(config, observed) {
    if (observed.kind === 'exact') {
      return { kind: 'unchanged', operations: [], receipt: observed }
    }
    if (observed.kind === 'conflict') {
      return { kind: 'conflict', operations: [], receipt: observed, reason: observed.reason }
    }
    if (config.provider.routeManagement === ROUTE_VERIFY_ONLY) {
      return {
        kind: 'conflict',
        operations: [],
        receipt: observed,
        reason: 'TCP Serve route is absent and routeManagement is verify-only',
      }
    }
    const route = observed.route
    return {
      kind: 'create',
      operations: Object.freeze([
        { argv: tcpServeArgv(route.tcpPort) },
      ]),
      receipt: observed,
    }
  },
  async apply(config, plan, runtime = {}) {
    if (plan.kind === 'unchanged') return { action: 'unchanged', route: plan.receipt.route }
    if (plan.kind === 'conflict') throw new Error(`Headscale TCP Serve conflict: ${plan.reason}. Refusing to overwrite it.`)
    const operation = plan.operations[0]
    await invokeTailscale(
      runtime.run ?? runArgvCommand,
      runtime.tailscaleBinary,
      operation.argv,
      `TCP Serve configuration for port ${plan.receipt.route.tcpPort}`,
    )
    return { action: 'configured', route: plan.receipt.route }
  },
  async verify(config, runtime = {}) {
    const observed = await this.inspect(config, runtime)
    if (observed.kind !== 'exact') {
      const detail = observed.kind === 'conflict' ? observed.reason : 'the requested TCP Serve route is still absent'
      return { ok: false, reasonCode: `headscale_tcp_serve_verify_failed: ${detail}` }
    }
    return { ok: true, receipt: observed }
  },
}

export async function ensureHeadscaleTcpServe({ binary, externalOrigin, run = runArgvCommand }) {
  const config = { externalOrigin, provider: { type: PROVIDER_HEADSCALE_TCP_SERVE, routeManagement: ROUTE_ENSURE } }
  const runtime = { tailscaleBinary: binary, run }
  const observed = await headscaleTcpServeProvider.inspect(config, runtime)
  const planned = headscaleTcpServeProvider.plan(config, observed)
  const applied = await headscaleTcpServeProvider.apply(config, planned, runtime)
  if (applied.action === 'unchanged' && observed.kind === 'exact') return applied
  const verified = await headscaleTcpServeProvider.verify(config, runtime)
  if (!verified.ok) throw new Error(`Headscale TCP Serve verification failed: ${verified.reasonCode}`)
  return applied
}
