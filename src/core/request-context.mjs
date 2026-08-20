export function requestContext(request) {
  return Object.freeze({
    remoteAddress: request.socket?.remoteAddress,
    rawHeaders: request.rawHeaders,
    headers: request.headers,
    method: request.method,
    url: request.url,
  })
}
