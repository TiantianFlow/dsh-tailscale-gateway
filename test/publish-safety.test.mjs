import assert from 'node:assert/strict'
import { readdir, readFile, stat } from 'node:fs/promises'
import { extname, join, relative } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const SKIP_DIRS = new Set(['.git', 'node_modules', '.pnpm-store', 'coverage'])
const TEXT_EXT = new Set(['.mjs', '.js', '.json', '.yml', '.yaml', '.md', '.txt', '.gitignore'])

async function walk(directory, files = []) {
  for (const entry of await readdir(directory)) {
    if (SKIP_DIRS.has(entry) || entry === 'ASSIGNMENT.md') continue
    const path = join(directory, entry)
    const info = await stat(path)
    if (info.isDirectory()) await walk(path, files)
    else if (TEXT_EXT.has(extname(entry)) || entry === 'LICENSE' || entry === '.gitignore') files.push(path)
  }
  return files
}

function withoutPlaceholders(text) {
  return text
    .replaceAll('operator@example.invalid', '')
    .replaceAll('admin@example.invalid', '')
    .replaceAll('owner@example.invalid', '')
    .replaceAll('other@example.invalid', '')
    .replaceAll('not-allowed@example.invalid', '')
    .replaceAll('example.invalid', '')
    .replaceAll('example-tailnet.ts.net', '')
    .replaceAll('127.0.0.1', '')
    .replaceAll('0.0.0.0', '')
    .replaceAll('203.0.113.1', '')
    .replaceAll('203.0.113.2', '')
    .replaceAll('/path/to/', '')
    .replaceAll('/opt/dsh/', '')
    .replaceAll('/opt/tailscale/', '')
    .replaceAll('/usr/local/bin/tailscale', '')
}

test('tracked sources use only placeholder identities, domains, and paths', async () => {
  const files = await walk(root)
  const violations = []
  for (const file of files) {
    const text = await readFile(file, 'utf8')
    const rel = relative(root, file)
    const scanned = withoutPlaceholders(text)
    if (/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(scanned)) {
      violations.push(`${rel}: non-placeholder email`)
    }
    if (/\/Users\/[A-Za-z]/.test(scanned)) {
      violations.push(`${rel}: real home path`)
    }
    if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(scanned)) {
      violations.push(`${rel}: non-placeholder IPv4`)
    }
    if (/[a-z0-9-]+\.ts\.net/.test(scanned)) {
      violations.push(`${rel}: non-placeholder ts.net hostname`)
    }
    if (/[a-z0-9-]+\.cloudflareaccess\.com/.test(scanned)) {
      violations.push(`${rel}: real Cloudflare Access team hostname`)
    }
    if (/\b(?:sk-|ghp_|github_pat_)[A-Za-z0-9_]{8,}/.test(scanned)) {
      violations.push(`${rel}: token-like secret`)
    }
  }
  assert.deepEqual(violations, [])
})
