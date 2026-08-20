import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { chmod, mkdir, open, readFile, rename, stat, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'
import { AUTH_GATEWAY_CREDENTIAL, MAX_PRINCIPAL_LENGTH } from '../core/constants.mjs'

export const CREDENTIAL_BYTES = 32
const STORE_VERSION = 1
const ALLOWED_MODE = 0o600

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

export function hashCredential(secret) {
  return createHash('sha256').update(secret).digest('hex')
}

export function generateCredentialSecret() {
  return randomBytes(CREDENTIAL_BYTES).toString('base64url')
}

export function principalIdFor(name) {
  if (typeof name !== 'string' || name.trim() !== name || !/^[A-Za-z0-9._-]{1,64}$/.test(name)) {
    throw new Error('dsh-gateway: credential principal name must be a short token such as operator-1')
  }
  return `credential:${name}`
}

function verifierMatches(storedHex, secret) {
  if (typeof storedHex !== 'string' || !/^[0-9a-f]{64}$/.test(storedHex)) return false
  const expected = Buffer.from(storedHex, 'hex')
  const actual = Buffer.from(hashCredential(secret), 'hex')
  return expected.length === actual.length && timingSafeEqual(expected, actual)
}

export function parseStoreDocument(raw) {
  let parsed
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error('dsh-gateway: credential store is not valid JSON')
  }
  if (!isRecord(parsed) || parsed.version !== STORE_VERSION || !Array.isArray(parsed.credentials)) {
    throw new Error('dsh-gateway: credential store is malformed')
  }
  const credentials = []
  const seen = new Set()
  for (const entry of parsed.credentials) {
    if (!isRecord(entry) || typeof entry.principalId !== 'string' || typeof entry.verifier !== 'string') {
      throw new Error('dsh-gateway: credential store entry is malformed')
    }
    if (!entry.principalId.startsWith('credential:') || entry.principalId.length > MAX_PRINCIPAL_LENGTH) {
      throw new Error('dsh-gateway: credential store principal is invalid')
    }
    if (seen.has(entry.principalId)) throw new Error('dsh-gateway: credential store contains duplicate principals')
    seen.add(entry.principalId)
    credentials.push(Object.freeze({
      principalId: entry.principalId,
      verifier: entry.verifier,
      createdAt: typeof entry.createdAt === 'string' ? entry.createdAt : undefined,
      revoked: entry.revoked === true,
    }))
  }
  return Object.freeze({ version: STORE_VERSION, credentials: Object.freeze(credentials) })
}

export async function assertRestrictiveStoreFile(path) {
  const info = await stat(path)
  if (!info.isFile()) throw new Error('dsh-gateway: credential store path is not a file')
  if (process.platform !== 'win32') {
    const mode = info.mode & 0o777
    if (mode !== ALLOWED_MODE && mode !== 0o400) {
      throw new Error('dsh-gateway: credential store permissions are too broad')
    }
    if (typeof process.getuid === 'function' && info.uid !== process.getuid()) {
      throw new Error('dsh-gateway: credential store is not owned by the current user')
    }
  }
}

export async function readCredentialStore(path) {
  await assertRestrictiveStoreFile(path)
  const raw = await readFile(path, 'utf8')
  return parseStoreDocument(raw)
}

export async function writeCredentialStore(path, document, { exclusive = false } = {}) {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  const payload = `${JSON.stringify({ version: STORE_VERSION, credentials: document.credentials }, null, 2)}\n`
  if (exclusive) {
    const handle = await open(path, 'wx', ALLOWED_MODE)
    try {
      await handle.writeFile(payload, { encoding: 'utf8' })
    } finally {
      await handle.close()
    }
    return
  }
  const temporary = `${path}.dsh-gateway-${process.pid}.tmp`
  await writeFile(temporary, payload, { encoding: 'utf8', mode: ALLOWED_MODE })
  await chmod(temporary, ALLOWED_MODE)
  await rename(temporary, path)
  await chmod(path, ALLOWED_MODE)
}

export async function issueCredential(path, name) {
  const principalId = principalIdFor(name)
  const secret = generateCredentialSecret()
  let document
  try {
    document = await readCredentialStore(path)
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error
    document = { version: STORE_VERSION, credentials: [] }
  }
  if (document.credentials.some(entry => entry.principalId === principalId && entry.revoked !== true)) {
    throw new Error(`dsh-gateway: credential ${principalId} already exists`)
  }
  const next = {
    version: STORE_VERSION,
    credentials: [
      ...document.credentials.filter(entry => entry.principalId !== principalId),
      {
        principalId,
        verifier: hashCredential(secret),
        createdAt: new Date().toISOString(),
        revoked: false,
      },
    ],
  }
  const exclusive = document.credentials.length === 0
  try {
    await writeCredentialStore(path, next, { exclusive })
  } catch (error) {
    if (exclusive && error?.code === 'EEXIST') {
      document = await readCredentialStore(path)
      if (document.credentials.some(entry => entry.principalId === principalId && entry.revoked !== true)) {
        throw new Error(`dsh-gateway: credential ${principalId} already exists`)
      }
      await writeCredentialStore(path, {
        version: STORE_VERSION,
        credentials: [
          ...document.credentials.filter(entry => entry.principalId !== principalId),
          next.credentials.at(-1),
        ],
      })
    } else throw error
  }
  return { principalId, secret, mode: AUTH_GATEWAY_CREDENTIAL }
}

export async function revokeCredential(path, name) {
  const principalId = name.startsWith('credential:') ? name : principalIdFor(name)
  const document = await readCredentialStore(path)
  let found = false
  const credentials = document.credentials.map(entry => {
    if (entry.principalId !== principalId) return entry
    found = true
    return { ...entry, revoked: true }
  })
  if (!found) throw new Error(`dsh-gateway: credential ${principalId} was not found`)
  await writeCredentialStore(path, { version: STORE_VERSION, credentials })
  return { principalId, revoked: true }
}

export async function listCredentials(path) {
  const document = await readCredentialStore(path)
  return document.credentials.map(entry => ({
    principalId: entry.principalId,
    createdAt: entry.createdAt,
    revoked: entry.revoked === true,
  }))
}

export function lookupCredential(document, secret) {
  if (typeof secret !== 'string' || secret.length < 32) return undefined
  let matched
  for (const entry of document.credentials) {
    if (entry.revoked === true) continue
    if (verifierMatches(entry.verifier, secret)) matched = entry
  }
  return matched
}

export function emptyStore() {
  return { version: STORE_VERSION, credentials: [] }
}
