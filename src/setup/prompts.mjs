import { createInterface } from 'node:readline/promises'

export async function ask(question, { stdin = process.stdin, stdout = process.stdout } = {}) {
  const prompt = createInterface({ input: stdin, output: stdout })
  try {
    return (await prompt.question(question)).trim()
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
