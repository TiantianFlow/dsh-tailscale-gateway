import { createServer } from 'node:http'
import {
  GATEWAY_HOST,
  GATEWAY_PORT,
  MAX_IN_FLIGHT,
  PACKAGE_NAME,
} from './constants.mjs'
import { authorizeRequest } from './authorize.mjs'
import { proxyHttp } from './proxy-http.mjs'
import { proxyWebSocket, writeUpgradeDenied } from './proxy-websocket.mjs'
import { isLocalReadinessRequest, isReadinessPath, writeReadiness } from './readiness.mjs'
import { requestContext } from './request-context.mjs'
import { createAuth } from '../auth/create.mjs'
import { applyProvider, inspectProvider, verifyProvider } from '../providers/registry.mjs'

function writeDenied(response, statusCode, reason) {
  response.writeHead(statusCode, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "frame-ancestors 'none'; base-uri 'none'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
  })
  response.end(`${statusCode} ${reason}\n`)
}

function createInFlightGuard() {
  let inFlight = 0
  return {
    acquire() {
      if (inFlight >= MAX_IN_FLIGHT) return false
      inFlight += 1
      return true
    },
    release() {
      if (inFlight > 0) inFlight -= 1
    },
  }
}

export function createGatewayServer(config, { isReady = () => false, auth } = {}) {
  if (!auth) throw new Error('dsh-gateway: createGatewayServer requires an auth module')
  const inFlight = createInFlightGuard()
  const server = createServer((request, response) => {
    if (isReadinessPath(request)) {
      if (!isLocalReadinessRequest(request, config)) return writeDenied(response, 404, 'Not Found')
      return writeReadiness(response, isReady(), config.activationToken)
    }
    if (!inFlight.acquire()) return writeDenied(response, 429, 'Too Many Requests')
    const finish = () => inFlight.release()
    response.once('close', finish)
    const context = requestContext(request)
    Promise.resolve(auth.handleReservedRequest(context, request, response)).then(handled => {
      if (handled?.handled === true) return
      return authorizeRequest(context, config, auth).then(verdict => {
        if (!verdict.ok) return writeDenied(response, 403, 'Forbidden')
        return proxyHttp(request, response, {
          path: verdict.path,
          extraStripNames: verdict.consumedHeaders,
          externalOrigin: config.externalOrigin,
          writeDenied,
        })
      })
    }).catch(() => {
      if (!response.headersSent) writeDenied(response, 403, 'Forbidden')
    })
  })
  server.on('upgrade', (request, socket, head) => {
    if (!inFlight.acquire()) {
      writeUpgradeDenied(socket, 429, 'Too Many Requests')
      return
    }
    socket.once('close', () => inFlight.release())
    const context = requestContext(request)
    authorizeRequest(context, config, auth, { websocket: true }).then(verdict => {
      if (!verdict.ok || request.method !== 'GET' || String(request.headers.upgrade).toLowerCase() !== 'websocket') {
        writeUpgradeDenied(socket, 403, 'Forbidden')
        return
      }
      proxyWebSocket(request, socket, head, { path: verdict.path, externalOrigin: config.externalOrigin })
    }).catch(() => writeUpgradeDenied(socket, 403, 'Forbidden'))
  })
  server.on('connect', (_request, socket) => writeUpgradeDenied(socket, 405, 'Method Not Allowed'))
  server.on('clientError', (_error, socket) => writeUpgradeDenied(socket, 400, 'Bad Request'))
  return server
}

async function closeServer(server) {
  await new Promise(resolve => server.close(resolve))
}

export async function start(config, {
  auth,
  runtime = {},
  createGateway = createGatewayServer,
  logger = console,
} = {}) {
  if (!config?.enabled) throw new Error('sidecar cannot run while disabled')
  const resolvedAuth = auth ?? await createAuth(config)
  const authReady = await resolvedAuth.readiness()
  if (!authReady.ready) {
    await resolvedAuth.close?.()
    throw new Error(`auth is not ready: ${authReady.reasonCode ?? 'unknown'}`)
  }

  let ready = false
  const server = createGateway(config, { isReady: () => ready, auth: resolvedAuth })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(GATEWAY_PORT, GATEWAY_HOST, resolve)
  })
  logger.log(`[${PACKAGE_NAME}] bound only on http://${GATEWAY_HOST}:${GATEWAY_PORT}`)

  try {
    const observed = await inspectProvider(config, runtime)
    const applied = await applyProvider(config, observed, runtime)
    if (applied?.detail) logger.log(`[${PACKAGE_NAME}] provider ${config.provider.type} ${applied.detail}`)
    const verified = await verifyProvider(config, runtime)
    if (!verified.ok) throw new Error(verified.reasonCode ?? 'provider_verify_failed')
  } catch (error) {
    await closeServer(server)
    await resolvedAuth.close?.()
    throw new Error(`provider setup failed after the loopback sidecar bound: ${error instanceof Error ? error.message : String(error)}`)
  }

  ready = true
  return server
}
