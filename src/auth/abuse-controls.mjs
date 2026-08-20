const DEFAULTS = Object.freeze({
  perSourceWindowMs: 60_000,
  perSourceMax: 10,
  globalWindowMs: 60_000,
  globalMax: 60,
  maxDelayMs: 5_000,
})

function prune(timestamps, windowMs, now) {
  return timestamps.filter(timestamp => now - timestamp < windowMs)
}

export function createLoginLimiter(options = {}) {
  const settings = { ...DEFAULTS, ...options }
  const sources = new Map()
  let globalHits = []

  return {
    async admit(sourceKey) {
      const timestamp = Date.now()
      globalHits = prune(globalHits, settings.globalWindowMs, timestamp)
      if (globalHits.length >= settings.globalMax) return { ok: false, reasonCode: 'rate_limited' }
      const record = sources.get(sourceKey) ?? { hits: [], failures: 0 }
      record.hits = prune(record.hits, settings.perSourceWindowMs, timestamp)
      if (record.hits.length >= settings.perSourceMax) return { ok: false, reasonCode: 'rate_limited' }
      const delay = Math.min(settings.maxDelayMs, (2 ** Math.min(record.failures, 6)) * 50)
      if (delay > 50) await new Promise(resolve => setTimeout(resolve, delay))
      record.hits.push(timestamp)
      globalHits.push(timestamp)
      sources.set(sourceKey, record)
      return { ok: true }
    },
    recordFailure(sourceKey) {
      const record = sources.get(sourceKey)
      if (record) record.failures += 1
    },
    recordSuccess(sourceKey) {
      const record = sources.get(sourceKey)
      if (record) record.failures = 0
    },
  }
}
