import { createInterface } from 'node:readline/promises'
import { PROVIDER_CLOUDFLARE, PROVIDER_TAILSCALE } from '../core/constants.mjs'

export const SETUP_EOF = 'SETUP_EOF'

const PROVIDER_MENU = Object.freeze([
  {
    key: '1',
    id: PROVIDER_TAILSCALE,
    label: 'Tailscale Serve — private Serve ingress with Tailscale user identity',
  },
  {
    key: '2',
    id: PROVIDER_CLOUDFLARE,
    label: 'Cloudflare Access — existing Access-protected application with signed identity',
  },
])

function setupEofError(message) {
  const error = new Error(message)
  error.code = SETUP_EOF
  return error
}

export async function ask(question, { stdin = process.stdin, stdout = process.stdout } = {}) {
  if (stdin.readableEnded || stdin.destroyed) {
    throw setupEofError('dsh-one-gateway: setup ended while waiting for input')
  }
  const prompt = createInterface({
    input: stdin,
    output: stdout,
    terminal: Boolean(stdout.isTTY && typeof stdout.cursorTo === 'function'),
  })
  try {
    const answer = await new Promise((resolve, reject) => {
      let settled = false
      const settle = (fn, value) => {
        if (settled) return
        settled = true
        stdin.off('end', onEnd)
        fn(value)
      }
      const onEnd = () => {
        settle(reject, setupEofError('dsh-one-gateway: setup ended while waiting for input'))
      }
      stdin.once('end', onEnd)
      prompt.question(question).then(
        value => settle(resolve, value),
        error => settle(reject, error),
      )
    })
    return answer.trim()
  } finally {
    prompt.close()
  }
}

export function isInteractive({ stdin = process.stdin, stdout = process.stdout } = {}) {
  return Boolean(stdin.isTTY && stdout.isTTY)
}

export async function confirmWrite(options, io) {
  if (options.yes) return true
  if (!isInteractive(io)) return false
  return /^y(?:es)?$/i.test(await ask('Write this profile entry and enable the gateway? [y/N] ', io))
}

export async function chooseProvider(detected, io) {
  const detectedIds = new Set((detected ?? []).map(item => item.id))
  const lines = [
    'Select the ingress provider to configure.',
    'Detection is a hint only; setup will still validate the selected provider.',
  ]
  for (const item of PROVIDER_MENU) {
    lines.push(`  ${item.key}) ${item.label}${detectedIds.has(item.id) ? ' [detected]' : ''}`)
  }
  io.stdout.write(`${lines.join('\n')}\n`)

  const only = detected?.length === 1 ? detected[0].id : null
  const defaultKey = PROVIDER_MENU.find(item => item.id === only)?.key ?? null
  const prompt = defaultKey ? `Provider [${defaultKey}]: ` : 'Provider (1-2): '

  while (true) {
    let answer
    try {
      answer = await ask(prompt, io)
    } catch (error) {
      if (error?.code === SETUP_EOF) {
        throw setupEofError('dsh-one-gateway: setup ended before a provider was selected; rerun with --provider tailscale-serve or --provider cloudflare-access')
      }
      throw error
    }
    const selectedKey = answer === '' ? defaultKey : answer
    const selected = PROVIDER_MENU.find(item => item.key === selectedKey)
    if (selected) return selected.id
    io.stdout.write('Invalid selection. Enter 1 or 2.\n')
  }
}

export async function askRequired(question, io) {
  while (true) {
    let value
    try {
      value = await ask(question, io)
    } catch (error) {
      if (error?.code === SETUP_EOF) {
        throw setupEofError('dsh-one-gateway: setup ended before required Cloudflare values were collected; rerun with --external-origin, --team-origin, --application-audience, and --trusted-principal')
      }
      throw error
    }
    if (value) return value
    io.stdout.write('A value is required; supply it here or with the corresponding flag.\n')
  }
}
