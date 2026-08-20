import { start } from './core/server.mjs'
import { assertSafeConfig } from './core/config.mjs'
import { PACKAGE_NAME } from './core/constants.mjs'

function loadConfig() {
  const encoded = process.env.DSH_GATEWAY_CONFIG
  if (!encoded) throw new Error('DSH_GATEWAY_CONFIG was not supplied by the DSH plugin')
  let config
  try {
    config = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'))
  } catch {
    throw new Error('sidecar configuration is invalid')
  }
  const safe = assertSafeConfig(config)
  if (!safe.enabled) throw new Error('sidecar cannot run while disabled')
  return safe
}

export async function startSidecar() {
  const config = loadConfig()
  return start(config, {
    runtime: {
      tailscaleBinary: process.env.DSH_GATEWAY_TAILSCALE_BINARY,
    },
  })
}

startSidecar().catch(error => {
  console.error(`[${PACKAGE_NAME}] ${error instanceof Error ? error.stack ?? error.message : String(error)}`)
  process.exitCode = 1
})
