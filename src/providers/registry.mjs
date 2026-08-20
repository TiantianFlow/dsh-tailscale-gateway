import { COMPATIBILITY, PROVIDER_CLOUDFLARE, PROVIDER_EASYTIER, PROVIDER_TAILSCALE } from '../core/constants.mjs'
import { cloudflareAccessProvider } from './cloudflare-access.mjs'
import { tailscaleServeProvider } from './tailscale-serve.mjs'

const PROVIDERS = Object.freeze({
  [PROVIDER_TAILSCALE]: tailscaleServeProvider,
  [PROVIDER_CLOUDFLARE]: cloudflareAccessProvider,
})

export function getProvider(type) {
  if (type === PROVIDER_EASYTIER) {
    throw new Error('dsh-one-gateway: provider type easytier is not supported in v1')
  }
  const provider = PROVIDERS[type]
  if (!provider) throw new Error(`dsh-one-gateway: unknown provider ${type}`)
  return provider
}

export function requiredExecutables(config) {
  return getProvider(config.provider.type).requiredExecutables(config)
}

export async function inspectProvider(config, runtime) {
  return getProvider(config.provider.type).inspect(config, runtime)
}

export async function applyProvider(config, observed, runtime) {
  const provider = getProvider(config.provider.type)
  const plan = provider.plan(config, observed)
  return provider.apply(config, plan, runtime)
}

export async function verifyProvider(config, runtime) {
  return getProvider(config.provider.type).verify(config, runtime)
}

export function providerIds() {
  return Object.freeze(Object.keys(PROVIDERS))
}

export function compatibleAuthMode(providerType) {
  return COMPATIBILITY[providerType]?.authMode
}
