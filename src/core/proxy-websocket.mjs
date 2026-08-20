import { request as upstreamRequest } from 'node:http'
import { rewriteDownstreamHeaders, rewriteWebSocketHeaders } from './headers.mjs'
import { upstreamOptions } from './proxy-http.mjs'

function responseStatusLine(response) {
  const code = response.statusCode ?? 502
  const message = (response.statusMessage || (code === 101 ? 'Switching Protocols' : 'Bad Gateway')).replace(/[\r\n]/g, '')
  return `HTTP/1.1 ${code} ${message}\r\n`
}

function writeUpgradeResponse(socket, upstreamResponse, externalOrigin) {
  const headers = rewriteDownstreamHeaders(upstreamResponse.headers, externalOrigin)
  delete headers.connection
  delete headers.upgrade
  socket.write(responseStatusLine(upstreamResponse))
  socket.write('Connection: Upgrade\r\nUpgrade: websocket\r\n')
  for (const [name, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      for (const item of value) socket.write(`${name}: ${item}\r\n`)
    } else socket.write(`${name}: ${value}\r\n`)
  }
  socket.write('\r\n')
}

export function writeUpgradeDenied(socket, statusCode, reason) {
  socket.end(
    `HTTP/1.1 ${statusCode} ${reason}\r\n` +
    'Connection: close\r\n' +
    'Cache-Control: no-store\r\n' +
    'X-Content-Type-Options: nosniff\r\n' +
    '\r\n',
  )
}

export function proxyWebSocket(request, socket, head, { path, externalOrigin }) {
  let upgraded = false
  let normalResponse = false
  const upstream = upstreamRequest(
    upstreamOptions(path, request.method, rewriteWebSocketHeaders(request.headers)),
  )
  upstream.once('timeout', () => upstream.destroy(new Error('upstream timed out')))
  upstream.once('error', () => {
    if (upgraded || normalResponse) socket.destroy()
    else writeUpgradeDenied(socket, 502, 'Bad Gateway')
  })
  upstream.once('response', upstreamResponse => {
    normalResponse = true
    const headers = rewriteDownstreamHeaders(upstreamResponse.headers, externalOrigin)
    socket.write(responseStatusLine(upstreamResponse))
    for (const [name, value] of Object.entries(headers)) socket.write(`${name}: ${value}\r\n`)
    socket.write('\r\n')
    upstreamResponse.pipe(socket)
  })
  upstream.once('upgrade', (upstreamResponse, upstreamSocket, upstreamHead) => {
    upgraded = true
    writeUpgradeResponse(socket, upstreamResponse, externalOrigin)
    if (head?.length) upstreamSocket.write(head)
    if (upstreamHead?.length) socket.write(upstreamHead)
    upstreamSocket.on('error', () => socket.destroy())
    socket.on('error', () => upstreamSocket.destroy())
    upstreamSocket.pipe(socket)
    socket.pipe(upstreamSocket)
  })
  upstream.end()
}
