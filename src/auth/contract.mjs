export function okPrincipal(principal, { consumedHeaders = [], consumedCookies = [] } = {}) {
  return {
    ok: true,
    principal: Object.freeze({ ...principal }),
    consumedHeaders: Object.freeze([...consumedHeaders]),
    consumedCookies: Object.freeze([...consumedCookies]),
  }
}

export function denyAuth(reasonCode) {
  return { ok: false, reasonCode }
}

export function unhandled() {
  return { handled: false }
}

export function handledResponse(response) {
  return { handled: true, response }
}

export function readyOk() {
  return { ready: true }
}

export function notReady(reasonCode) {
  return { ready: false, reasonCode }
}
