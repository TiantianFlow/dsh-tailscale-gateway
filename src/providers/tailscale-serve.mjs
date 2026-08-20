import { isAbsolute } from 'node:path'
import {
  GATEWAY_HOST,
  GATEWAY_PORT,
  PROVIDER_TAILSCALE,
  ROUTE_ENSURE,
  ROUTE_VERIFY_ONLY,
  TAILSCALE_PROFILE_ID,
} from '../core/constants.mjs'
import { httpsPortFromOrigin } from '../core/origin.mjs'
import { resultOrThrow, runArgvCommand } from './command.mjs'

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function readableError(error) {
  return error instanceof Error ? error.message : String(error)
}

function statusAuthorityPort(authority) {
  if (typeof authority !== 'string' || authority.length === 0) return undefined
  try {
    const url = new URL(`https://${authority}`)
    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) return undefined
    return url.port === '' ? 443 : Number(url.port)
  } catch {
    return undefined
  }
}

function funnelEnabledForRoute(status, authority, port) {
  for (const field of ['AllowFunnel', '#AllowFunnel', 'Funnel']) {
    const configured = status[field]
    if (configured === true) return true
    if (Array.isArray(configured) && configured.some(value => value === authority || value === String(port))) return true
    if (!isRecord(configured)) continue
    for (const [key, value] of Object.entries(configured)) {
      if ((key === authority || key === String(port) || statusAuthorityPort(key) === port) && value) return true
    }
  }
  return false
}

export function tailscaleServeRoute(externalOrigin) {
  const url = new URL(externalOrigin)
  const httpsPort = httpsPortFromOrigin(externalOrigin)
  return Object.freeze({
    httpsPort,
    authority: `${url.hostname}:${httpsPort}`,
    proxy: `http://${GATEWAY_HOST}:${GATEWAY_PORT}`,
  })
}

/**
 * Classify only the route this gateway would own. A route is exact solely when
 * it is the one root handler on the canonical authority and its TCP listener
 * has the standard private-HTTPS shape. Any ambiguity is a conflict.
 */
export function classifyServeStatus(status, externalOrigin) {
  if (!isRecord(status)) throw new Error('Tailscale Serve status is not a JSON object')
  const route = tailscaleServeRoute(externalOrigin)
  const web = status.Web
  const tcp = status.TCP
  if (web !== undefined && !isRecord(web)) throw new Error('Tailscale Serve status has an invalid Web section')
  if (tcp !== undefined && !isRecord(tcp)) throw new Error('Tailscale Serve status has an invalid TCP section')
  if (funnelEnabledForRoute(status, route.authority, route.httpsPort)) {
    return { kind: 'conflict', route, reason: 'Funnel is enabled for the requested HTTPS route' }
  }

  const webEntriesOnPort = Object.entries(web ?? {}).filter(([authority]) => statusAuthorityPort(authority) === route.httpsPort)
  const exactAuthority = web?.[route.authority]
  if (webEntriesOnPort.some(([authority]) => authority !== route.authority)) {
    return { kind: 'conflict', route, reason: `HTTPS port ${route.httpsPort} already has a Serve web handler for another authority` }
  }

  const tcpHandler = tcp?.[String(route.httpsPort)]
  if (exactAuthority === undefined) {
    if (tcpHandler !== undefined) {
      return { kind: 'conflict', route, reason: `HTTPS port ${route.httpsPort} is already claimed by another Tailscale Serve configuration` }
    }
    return { kind: 'absent', route }
  }
  if (!isRecord(exactAuthority) || !isRecord(exactAuthority.Handlers)) {
    return { kind: 'conflict', route, reason: `canonical authority ${route.authority} has an invalid or non-proxy Serve handler` }
  }
  const handlers = exactAuthority.Handlers
  const handlerPaths = Object.keys(handlers)
  if (handlerPaths.length !== 1 || handlerPaths[0] !== '/') {
    return { kind: 'conflict', route, reason: `canonical authority ${route.authority} has additional or non-root Serve handlers` }
  }
  const rootHandler = handlers['/']
  if (!isRecord(rootHandler) || rootHandler.Proxy !== route.proxy || Object.keys(rootHandler).length !== 1) {
    return { kind: 'conflict', route, reason: `canonical root handler does not proxy exactly to ${route.proxy}` }
  }
  if (!isRecord(tcpHandler) || tcpHandler.HTTPS !== true || Object.keys(tcpHandler).length !== 1) {
    return { kind: 'conflict', route, reason: `HTTPS port ${route.httpsPort} has unexpected TCP listener settings` }
  }
  return { kind: 'exact', route }
}

async function invoke(run, binary, argv, action) {
  let result
  try {
    result = await run(binary, argv)
  } catch (error) {
    throw new Error(`Tailscale ${action} could not run: ${readableError(error)}`)
  }
  return resultOrThrow(result, `Tailscale ${action}`)
}

function parseStatus(text) {
  try {
    return JSON.parse(text)
  } catch {
    throw new Error('Tailscale Serve status is not valid JSON')
  }
}

export const tailscaleServeProvider = {
  id: PROVIDER_TAILSCALE,
  identityCapability() {
    return { kind: 'overwritten-header', profileId: TAILSCALE_PROFILE_ID }
  },
  requiredExecutables() {
    return ['tailscale']
  },
  async inspect(config, runtime = {}) {
    const binary = runtime.tailscaleBinary
    const run = runtime.run ?? runArgvCommand
    if (typeof binary !== 'string' || !isAbsolute(binary)) {
      throw new Error('Tailscale CLI path was not supplied as an absolute executable')
    }
    const result = await invoke(run, binary, ['serve', 'status', '--json'], 'Serve status inspection')
    return classifyServeStatus(parseStatus(result.stdout), config.externalOrigin)
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
        reason: 'Tailscale Serve route is absent and routeManagement is verify-only',
      }
    }
    const route = observed.route
    return {
      kind: 'create',
      operations: Object.freeze([
        { argv: ['serve', `--https=${route.httpsPort}`, '--bg', route.proxy] },
      ]),
      receipt: observed,
    }
  },
  async apply(config, plan, runtime = {}) {
    if (plan.kind === 'unchanged') return { action: 'unchanged', route: plan.receipt.route }
    if (plan.kind === 'conflict') throw new Error(`Tailscale Serve conflict: ${plan.reason}. Refusing to overwrite it.`)
    const binary = runtime.tailscaleBinary
    const run = runtime.run ?? runArgvCommand
    if (typeof binary !== 'string' || !isAbsolute(binary)) {
      throw new Error('Tailscale CLI path was not supplied as an absolute executable')
    }
    const operation = plan.operations[0]
    await invoke(run, binary, operation.argv, `Serve configuration for ${plan.receipt.route.authority}`)
    return { action: 'configured', route: plan.receipt.route }
  },
  async verify(config, runtime = {}) {
    const observed = await this.inspect(config, runtime)
    if (observed.kind !== 'exact') {
      const detail = observed.kind === 'conflict' ? observed.reason : 'the requested route is still absent'
      return { ok: false, reasonCode: `tailscale_verify_failed: ${detail}` }
    }
    return { ok: true, receipt: observed }
  },
}

export async function ensureTailscaleServe({ binary, publicOrigin, externalOrigin, run = runArgvCommand }) {
  const origin = externalOrigin ?? publicOrigin
  const config = { externalOrigin: origin, provider: { type: PROVIDER_TAILSCALE, routeManagement: ROUTE_ENSURE } }
  const runtime = { tailscaleBinary: binary, run }
  const observed = await tailscaleServeProvider.inspect(config, runtime)
  const planned = tailscaleServeProvider.plan(config, observed)
  const applied = await tailscaleServeProvider.apply(config, planned, runtime)
  if (applied.action === 'unchanged' && observed.kind === 'exact') return applied
  const verified = await tailscaleServeProvider.verify(config, runtime)
  if (!verified.ok) throw new Error(`Tailscale Serve verification failed: ${verified.reasonCode}`)
  return applied
}
