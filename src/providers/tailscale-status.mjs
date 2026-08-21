import { isAbsolute } from 'node:path'
import { resultOrThrow, runArgvCommand } from './command.mjs'

export function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

export function readableError(error) {
  return error instanceof Error ? error.message : String(error)
}

export function statusAuthorityPort(authority) {
  if (typeof authority !== 'string' || authority.length === 0) return undefined
  try {
    const url = new URL(`https://${authority}`)
    if (url.username || url.password || url.pathname !== '/' || url.search || url.hash) return undefined
    return url.port === '' ? 443 : Number(url.port)
  } catch {
    return undefined
  }
}

export function funnelEnabledForRoute(status, authority, port) {
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

export async function invokeTailscale(run, binary, argv, action) {
  if (typeof binary !== 'string' || !isAbsolute(binary)) {
    throw new Error('Tailscale CLI path was not supplied as an absolute executable')
  }
  let result
  try {
    result = await run(binary, argv)
  } catch (error) {
    throw new Error(`Tailscale ${action} could not run: ${readableError(error)}`)
  }
  return resultOrThrow(result, `Tailscale ${action}`)
}

export function parseServeStatusJson(text) {
  try {
    return JSON.parse(text)
  } catch {
    throw new Error('Tailscale Serve status is not valid JSON')
  }
}

export async function readServeStatus(binary, run = runArgvCommand) {
  const result = await invokeTailscale(run, binary, ['serve', 'status', '--json'], 'Serve status inspection')
  return parseServeStatusJson(result.stdout)
}
