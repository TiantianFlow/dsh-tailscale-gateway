import { createPrivateKey, X509Certificate } from 'node:crypto'
import { readFile, stat } from 'node:fs/promises'
import { isIP } from 'node:net'
import { PROVIDER_HEADSCALE_TCP_SERVE } from './constants.mjs'

const ALLOWED_KEY_MODES = new Set([0o600, 0o400])

function isAbsolutePath(value) {
  return typeof value === 'string' && value.startsWith('/') && !value.includes('\\') && !value.includes('\0') && !value.includes('..')
}

export async function assertRestrictiveKeyFile(path) {
  if (!isAbsolutePath(path)) {
    throw new Error('dsh-one-gateway: tls.keyPath must be an absolute path')
  }
  let info
  try {
    info = await stat(path)
  } catch (error) {
    throw new Error(`dsh-one-gateway: tls key could not be read: ${error instanceof Error ? error.message : String(error)}`)
  }
  if (!info.isFile()) throw new Error('dsh-one-gateway: tls.keyPath is not a file')
  if (process.platform !== 'win32') {
    const mode = info.mode & 0o777
    if (!ALLOWED_KEY_MODES.has(mode)) {
      throw new Error('dsh-one-gateway: tls key permissions are too broad')
    }
    if (typeof process.getuid === 'function' && info.uid !== process.getuid()) {
      throw new Error('dsh-one-gateway: tls key is not owned by the current user')
    }
  }
}

function certificateCoversHost(cert, hostname) {
  if (typeof cert.subjectAltName !== 'string' || cert.subjectAltName.length === 0) return false
  if (isIP(hostname)) return Boolean(cert.checkIP(hostname))
  return Boolean(cert.checkHost(hostname, {
    wildcards: true,
    partialWildcards: false,
    multiLabelWildcards: false,
    singleLabelSubdomains: false,
  }))
}

/**
 * Load an operator-supplied certificate and private key. This pass never
 * generates a CA or self-signed certificate.
 */
export async function loadGatewayTls(tls, externalOrigin) {
  if (!tls || typeof tls !== 'object' || Array.isArray(tls)) {
    throw new Error('dsh-one-gateway: tls certificate and key are required')
  }
  if (!isAbsolutePath(tls.certPath)) {
    throw new Error('dsh-one-gateway: tls.certPath must be an absolute path')
  }
  await assertRestrictiveKeyFile(tls.keyPath)
  let certPem
  let keyPem
  try {
    certPem = await readFile(tls.certPath)
  } catch (error) {
    throw new Error(`dsh-one-gateway: tls certificate could not be read: ${error instanceof Error ? error.message : String(error)}`)
  }
  try {
    keyPem = await readFile(tls.keyPath)
  } catch (error) {
    throw new Error(`dsh-one-gateway: tls key could not be read: ${error instanceof Error ? error.message : String(error)}`)
  }

  let cert
  try {
    cert = new X509Certificate(certPem)
  } catch {
    throw new Error('dsh-one-gateway: tls.certPath is not a valid X.509 certificate')
  }
  let key
  try {
    key = createPrivateKey(keyPem)
  } catch {
    throw new Error('dsh-one-gateway: tls.keyPath is not a valid private key')
  }
  if (!cert.checkPrivateKey(key)) {
    throw new Error('dsh-one-gateway: tls certificate does not match the private key')
  }

  const now = Date.now()
  const from = Date.parse(cert.validFrom)
  const to = Date.parse(cert.validTo)
  if (!Number.isFinite(from) || !Number.isFinite(to) || now < from || now > to) {
    throw new Error('dsh-one-gateway: tls certificate is expired or not yet valid')
  }

  let hostname
  try {
    hostname = new URL(externalOrigin).hostname
  } catch {
    throw new Error('dsh-one-gateway: tls validation requires a valid externalOrigin')
  }
  if (!hostname || !certificateCoversHost(cert, hostname)) {
    throw new Error('dsh-one-gateway: tls certificate does not cover the externalOrigin hostname')
  }

  return Object.freeze({
    cert: certPem,
    key: keyPem,
  })
}

export function needsLoopbackTls(config) {
  return config?.provider?.type === PROVIDER_HEADSCALE_TCP_SERVE
}
