import { execFileSync } from 'node:child_process'
import { chmodSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

function openssl(args, options = {}) {
  return execFileSync('openssl', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...options })
}

/**
 * Generate a clearly-fake operator certificate for tests. Never used at runtime.
 */
export function writeFakeTls(options = {}) {
  const {
    hostname = 'gateway.example.invalid',
    ip,
    days = 2,
    notBefore,
    notAfter,
    keyMode = 0o600,
    directory = mkdtempSync(join(tmpdir(), 'dsh-one-gateway-tls-')),
    san,
  } = options
  const keyPath = join(directory, options.keyName ?? 'key.pem')
  const certPath = join(directory, options.certName ?? 'cert.pem')
  const names = san ?? [
    `DNS:${hostname}`,
    ...(ip ? [`IP:${ip}`] : []),
  ]
  const args = [
    'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-keyout', keyPath,
    '-out', certPath,
    '-subj', `/CN=${hostname}`,
    '-addext', `subjectAltName=${names.join(',')}`,
  ]
  if (notBefore) args.push('-not_before', notBefore)
  if (notAfter) args.push('-not_after', notAfter)
  else args.push('-days', String(days))
  openssl(args)
  chmodSync(keyPath, keyMode)
  chmodSync(certPath, 0o644)
  return { directory, keyPath, certPath, hostname }
}

export function writeUnrelatedKey(directory, name = 'other-key.pem', mode = 0o600) {
  const keyPath = join(directory, name)
  openssl(['genrsa', '-out', keyPath, '2048'])
  chmodSync(keyPath, mode)
  return keyPath
}

export function writeInvalidPem(directory, name, mode = 0o600) {
  const path = join(directory, name)
  writeFileSync(path, 'this is not a certificate\n', { mode })
  chmodSync(path, mode)
  return path
}
