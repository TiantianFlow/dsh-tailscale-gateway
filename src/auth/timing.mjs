import { timingSafeEqual } from 'node:crypto'

export function timingSafeEqualString(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false
  const a = Buffer.from(left)
  const b = Buffer.from(right)
  if (a.length !== b.length) {
    timingSafeEqual(a, a)
    return false
  }
  return timingSafeEqual(a, b)
}

export function allowlistContains(allowlist, candidate) {
  if (!Array.isArray(allowlist) || typeof candidate !== 'string') return false
  let matched = false
  for (const allowed of allowlist) {
    if (timingSafeEqualString(allowed, candidate)) matched = true
  }
  return matched
}
