import { LOGIN_PATH, READINESS_PATH } from './constants.mjs'
import {
  isAllowedFetchSite,
  isApiPath,
  isExpectedHost,
  isExpectedOrigin,
  isLiteralLoopbackPeer,
  isUnsafeMethod,
  normalizedProxyPath,
} from './origin.mjs'

function deny(reasonCode) {
  return { ok: false, reasonCode }
}

/**
 * Gate every proxy operation. Static navigation/assets may omit Origin, but
 * unsafe operations, all /api paths, and WebSocket handshakes must provide the
 * exact external origin. Auth evidence is evaluated only after protocol checks.
 */
export async function authorizeRequest(context, config, auth, { websocket = false } = {}) {
  try {
    if (!isLiteralLoopbackPeer(context.remoteAddress)) return deny('peer_not_loopback')
    if (!isExpectedHost(context.rawHeaders, config.externalOrigin)) return deny('host_mismatch')
    if (!isAllowedFetchSite(context.rawHeaders)) return deny('fetch_site_denied')
    const path = normalizedProxyPath(context.method, context.url, config.externalOrigin)
    if (!path) return deny('invalid_target')
    if (
      path === READINESS_PATH || path.startsWith(`${READINESS_PATH}?`) ||
      path === LOGIN_PATH || path.startsWith(`${LOGIN_PATH}?`)
    ) {
      return deny('reserved_path')
    }
    const requireOrigin = websocket || isUnsafeMethod(context.method) || isApiPath(path)
    if (!isExpectedOrigin(context.rawHeaders, config.externalOrigin, requireOrigin)) return deny('origin_mismatch')
    const result = await auth.authenticate(context)
    if (!result || result.ok !== true || !result.principal?.id) return deny(result?.reasonCode ?? 'auth_denied')
    return {
      ok: true,
      path,
      principal: result.principal,
      consumedHeaders: result.consumedHeaders ?? [],
      consumedCookies: result.consumedCookies ?? [],
    }
  } catch {
    return deny('auth_exception')
  }
}
