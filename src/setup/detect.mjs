import { spawnSync } from 'node:child_process'
import { PROVIDER_CLOUDFLARE, PROVIDER_TAILSCALE } from '../core/constants.mjs'

function commandExists(name) {
  const result = spawnSync(name, ['--version'], { encoding: 'utf8', timeout: 5_000, shell: false })
  if (result.error && result.error.code === 'ENOENT') return false
  return true
}

export function detectProviders({ hasCommand = commandExists } = {}) {
  const detected = []
  if (hasCommand('tailscale')) {
    detected.push({ id: PROVIDER_TAILSCALE, reason: 'tailscale executable is present' })
  }
  if (hasCommand('cloudflared')) {
    detected.push({ id: PROVIDER_CLOUDFLARE, reason: 'cloudflared executable is present' })
  }
  return detected
}

export function selectProvider(detected, requested) {
  if (requested) {
    if (requested !== PROVIDER_TAILSCALE && requested !== PROVIDER_CLOUDFLARE) {
      throw new Error('dsh-gateway: --provider must be tailscale-serve or cloudflare-access')
    }
    return requested
  }
  if (detected.length === 1) return detected[0].id
  if (detected.length === 0) {
    throw new Error('dsh-gateway: no provider executable was detected; pass --provider tailscale-serve or --provider cloudflare-access')
  }
  throw new Error('dsh-gateway: multiple providers were detected; pass --provider tailscale-serve or --provider cloudflare-access')
}
