import { dirname, isAbsolute, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { assertSafeConfig } from './core/config.mjs'
import { PACKAGE_NAME } from './core/constants.mjs'
import { requiredExecutables } from './providers/registry.mjs'

export const name = PACKAGE_NAME
export const inject = ['subprocess']

const here = dirname(fileURLToPath(import.meta.url))
const sidecarFile = join(here, 'sidecar.mjs')

export function apply(ctx, suppliedConfig = {}) {
  const config = assertSafeConfig(suppliedConfig)
  if (!config.enabled) {
    console.log(`[${PACKAGE_NAME}] installed but disabled`)
    return
  }

  let handle
  let disposed = false
  const encodedConfig = Buffer.from(JSON.stringify(suppliedConfig ?? {})).toString('base64url')
  ctx.effect(async () => {
    try {
      const node = await ctx.subprocess.resolveExecutable('node')
      const env = { DSH_GATEWAY_CONFIG: encodedConfig }
      for (const command of requiredExecutables(config)) {
        const resolved = await ctx.subprocess.resolveExecutable(command)
        if (typeof resolved !== 'string' || !isAbsolute(resolved)) {
          throw new Error(`DSH resolved a non-absolute ${command} executable path`)
        }
        if (command === 'tailscale') env.DSH_GATEWAY_TAILSCALE_BINARY = resolved
      }
      if (!disposed) {
        handle = ctx.subprocess.spawn({
          argv: [node, sidecarFile],
          cwd: here,
          env,
          stdio: { stdin: 'ignore', stdout: { maxBytes: 131072 }, stderr: { maxBytes: 131072 } },
          graceMs: 5_000,
        })
        handle.done.then(
          outcome => {
            const stderr = handle?.collected?.stderr?.readFrom(0).text.trim()
            const detail = stderr ? ` stderr=${JSON.stringify(stderr)}` : ''
            console.log(`[${PACKAGE_NAME}] sidecar exited code=${outcome.exitCode} signal=${outcome.signal}${detail}`)
          },
          error => console.error(`[${PACKAGE_NAME}] sidecar failed: ${error instanceof Error ? error.message : String(error)}`),
        )
      }
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error)
      console.error(`[${PACKAGE_NAME}] could not start: ${detail}`)
    }
    return async () => {
      disposed = true
      const current = handle
      if (!current) return
      try { await current.terminate() } catch { /* DSH owns final process-tree cleanup too. */ }
      try { await current.done } catch { /* The exit was already reported above. */ }
    }
  }, 'dsh-one-gateway sidecar lifecycle')
}
