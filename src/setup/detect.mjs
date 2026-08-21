import { spawnSync } from 'node:child_process'
import { PROVIDER_CLOUDFLARE, PROVIDER_HEADSCALE_TCP_SERVE, PROVIDER_TAILSCALE } from '../core/constants.mjs'
import { isRecord } from '../providers/tailscale-status.mjs'

const KNOWN_PROVIDERS = new Set([PROVIDER_TAILSCALE, PROVIDER_CLOUDFLARE, PROVIDER_HEADSCALE_TCP_SERVE])

function commandExists(name) {
  const result = spawnSync(name, ['--version'], { encoding: 'utf8', timeout: 5_000, shell: false })
  if (result.error && result.error.code === 'ENOENT') return false
  return true
}

export function classifyControlPlane(status) {
  if (!isRecord(status) || !isRecord(status.Self)) {
    return { kind: 'unknown', reason: 'Tailscale status has no Self node record' }
  }
  const backend = status.BackendState
  if (typeof backend === 'string' && backend !== 'Running') {
    return { kind: 'disconnected', reason: `Tailscale backend is ${backend}` }
  }
  const dnsName = typeof status.Self.DNSName === 'string'
    ? status.Self.DNSName.replace(/\.+$/, '')
    : ''
  const suffix = isRecord(status.CurrentTailnet) && typeof status.CurrentTailnet.MagicDNSSuffix === 'string'
    ? status.CurrentTailnet.MagicDNSSuffix.replace(/\.+$/, '')
    : ''
  const officialDns = dnsName.endsWith('.ts.net') && dnsName !== '.ts.net'
  const officialSuffix = suffix.endsWith('.ts.net') || suffix === 'ts.net'
  if (officialDns && (suffix === '' || officialSuffix)) {
    return { kind: 'official', hostname: dnsName, magicDnsSuffix: suffix || undefined }
  }
  if (dnsName.length > 0 && !officialDns && !officialSuffix) {
    return { kind: 'headscale', hostname: dnsName, magicDnsSuffix: suffix || undefined }
  }
  return { kind: 'ambiguous', reason: 'Tailscale control plane could not be classified as Tailscale.com or Headscale' }
}

export function refineDetectedProviders(detected, controlPlane) {
  return (detected ?? []).map(item => {
    if (item.id === PROVIDER_TAILSCALE && controlPlane?.kind === 'headscale') {
      return { id: PROVIDER_HEADSCALE_TCP_SERVE, reason: 'tailscale executable is present on a Headscale control plane' }
    }
    if (item.id === PROVIDER_HEADSCALE_TCP_SERVE && controlPlane?.kind === 'official') {
      return { id: PROVIDER_TAILSCALE, reason: 'tailscale executable is present on Tailscale.com' }
    }
    return item
  })
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
    if (!KNOWN_PROVIDERS.has(requested)) {
      throw new Error('dsh-one-gateway: --provider must be tailscale-serve, cloudflare-access, or headscale-tcp-serve')
    }
    return requested
  }
  if (detected.length === 1) return detected[0].id
  if (detected.length === 0) {
    throw new Error('dsh-one-gateway: no provider executable was detected; non-interactive setup requires --provider tailscale-serve, --provider cloudflare-access, or --provider headscale-tcp-serve')
  }
  throw new Error('dsh-one-gateway: multiple providers were detected; non-interactive setup requires --provider tailscale-serve, --provider cloudflare-access, or --provider headscale-tcp-serve')
}
