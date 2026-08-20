import { spawn as nodeSpawn } from 'node:child_process'
import { COMMAND_TIMEOUT_MS, MAX_COMMAND_OUTPUT_BYTES } from '../core/constants.mjs'

export function runArgvCommand(binary, argv, { spawn = nodeSpawn, timeoutMs = COMMAND_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    let stdout = ''
    let stderr = ''
    let outputBytes = 0
    let settled = false
    let timedOut = false
    let child
    const finish = (value, rejectWithError = false) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (rejectWithError) reject(value)
      else resolve(value)
    }
    const append = (which, chunk) => {
      outputBytes += chunk.length
      if (outputBytes > MAX_COMMAND_OUTPUT_BYTES) {
        child?.kill('SIGTERM')
        return
      }
      if (which === 'stdout') stdout += chunk.toString('utf8')
      else stderr += chunk.toString('utf8')
    }
    const timer = setTimeout(() => {
      timedOut = true
      child?.kill('SIGTERM')
    }, timeoutMs)
    try {
      child = spawn(binary, argv, { shell: false, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true })
    } catch (error) {
      finish(error, true)
      return
    }
    child.stdout.on('data', chunk => append('stdout', chunk))
    child.stderr.on('data', chunk => append('stderr', chunk))
    child.once('error', error => finish(error, true))
    child.once('close', code => {
      if (timedOut) {
        finish(new Error(`command timed out after ${timeoutMs}ms`), true)
        return
      }
      if (outputBytes > MAX_COMMAND_OUTPUT_BYTES) {
        finish(new Error(`command output exceeded ${MAX_COMMAND_OUTPUT_BYTES} bytes`), true)
        return
      }
      finish({ exitCode: code ?? 1, stdout, stderr })
    })
  })
}

export function resultOrThrow(result, action) {
  if (!result || typeof result !== 'object' || !Number.isInteger(result.exitCode) || typeof result.stdout !== 'string' || typeof result.stderr !== 'string') {
    throw new Error(`${action} returned an invalid command result`)
  }
  if (result.exitCode !== 0) {
    const detail = (result.stderr || result.stdout || `exit code ${result.exitCode}`).trim()
    throw new Error(`${action} failed: ${detail}`)
  }
  return result
}
