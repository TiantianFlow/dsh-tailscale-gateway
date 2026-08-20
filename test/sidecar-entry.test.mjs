import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import { mkdir, mkdtemp, rm, symlink } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const sourceDirectory = dirname(fileURLToPath(new URL('../src/sidecar.mjs', import.meta.url)))

test('the dedicated sidecar entry executes through a pnpm-style directory symlink', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'dsh-one-gateway-entry-'))
  try {
    const linkedSource = join(directory, 'node_modules', 'dsh-one-gateway', 'src')
    await mkdir(dirname(linkedSource), { recursive: true })
    await symlink(sourceDirectory, linkedSource, 'dir')
    const child = spawn(process.execPath, [join(linkedSource, 'sidecar.mjs')], {
      cwd: directory,
      env: { PATH: process.env.PATH ?? '' },
      stdio: ['ignore', 'ignore', 'pipe'],
    })
    let stderr = ''
    child.stderr.on('data', chunk => { stderr += chunk.toString('utf8') })
    const [exitCode] = await once(child, 'close')
    assert.equal(exitCode, 1)
    assert.match(stderr, /DSH_GATEWAY_CONFIG was not supplied/)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})
