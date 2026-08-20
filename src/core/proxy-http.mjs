import { request as upstreamRequest } from 'node:http'
import {
  MAX_DECLARED_REQUEST_BYTES,
  UPSTREAM_HOST,
  UPSTREAM_PORT,
  UPSTREAM_TIMEOUT_MS,
} from './constants.mjs'
import { rewriteDownstreamHeaders, rewriteUpstreamHeaders } from './headers.mjs'

export function hasOversizeContentLength(headers) {
  const raw = headers?.['content-length']
  if (typeof raw !== 'string' || raw.length === 0) return false
  if (!/^\d+$/.test(raw)) return true
  return Number(raw) > MAX_DECLARED_REQUEST_BYTES
}

export function upstreamOptions(path, method, headers) {
  return {
    host: UPSTREAM_HOST,
    port: UPSTREAM_PORT,
    path,
    method,
    headers,
    family: 4,
    timeout: UPSTREAM_TIMEOUT_MS,
  }
}

export function proxyHttp(request, response, { path, extraStripNames = [], externalOrigin, writeDenied }) {
  if (hasOversizeContentLength(request.headers)) return writeDenied(response, 413, 'Payload Too Large')

  const upstream = upstreamRequest(
    upstreamOptions(path, request.method, rewriteUpstreamHeaders(request.headers, { extraStripNames })),
    upstreamResponse => {
      const headers = rewriteDownstreamHeaders(upstreamResponse.headers, externalOrigin)
      response.writeHead(upstreamResponse.statusCode ?? 502, headers)
      upstreamResponse.pipe(response)
    },
  )
  upstream.once('timeout', () => upstream.destroy(new Error('upstream timed out')))
  upstream.once('error', () => {
    if (!response.headersSent) writeDenied(response, 502, 'Bad Gateway')
    else response.destroy()
  })
  request.once('aborted', () => upstream.destroy())
  request.pipe(upstream)
}
