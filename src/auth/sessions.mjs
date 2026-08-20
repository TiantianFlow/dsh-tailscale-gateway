import { randomBytes } from 'node:crypto'

const DEFAULT_IDLE_MS = 30 * 60 * 1000
const DEFAULT_ABSOLUTE_MS = 12 * 60 * 60 * 1000

export function createSessionStore({ idleMs = DEFAULT_IDLE_MS, absoluteMs = DEFAULT_ABSOLUTE_MS, now = Date.now } = {}) {
  const sessions = new Map()

  function expired(session, timestamp) {
    return timestamp - session.createdAt > absoluteMs || timestamp - session.lastSeenAt > idleMs
  }

  return {
    create(principalId) {
      const id = randomBytes(32).toString('base64url')
      const timestamp = now()
      sessions.set(id, { principalId, createdAt: timestamp, lastSeenAt: timestamp })
      return id
    },
    get(id) {
      if (typeof id !== 'string' || id.length === 0) return undefined
      const session = sessions.get(id)
      if (!session) return undefined
      const timestamp = now()
      if (expired(session, timestamp)) {
        sessions.delete(id)
        return undefined
      }
      session.lastSeenAt = timestamp
      return session
    },
    revokePrincipal(principalId) {
      for (const [id, session] of sessions) {
        if (session.principalId === principalId) sessions.delete(id)
      }
    },
    clear() {
      sessions.clear()
    },
    async close() {
      sessions.clear()
    },
  }
}
