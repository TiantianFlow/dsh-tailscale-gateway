import { spawnSync } from 'node:child_process'
import { homedir } from 'node:os'
import { join } from 'node:path'
import process from 'node:process'
import { PROVIDER_CLOUDFLARE, PROVIDER_TAILSCALE } from '../core/constants.mjs'
import { fetchJwksDocument } from '../auth/jwks.mjs'
import {
  issueCredential,
  listCredentials,
  revokeCredential,
} from '../auth/credential-store.mjs'
import { probeAccessAttachment } from '../providers/cloudflare-access.mjs'
import { detectProviders, selectProvider } from './detect.mjs'
import { createCloudflarePlan, createTailscalePlan, describePlan } from './plan.mjs'
import { renderProfileEntry, writeInitialProfileEntry } from './profile.mjs'
import { ask, confirmWrite, isInteractive } from './prompts.mjs'

export const DEFAULT_DSH_HOME = process.env.DSH_HOME || join(homedir(), '.dsh')
export const DEFAULT_PROFILE = join(DEFAULT_DSH_HOME, 'profiles', 'web', 'cordis.patch.yml')

export function usage() {
  return `Usage:
  dsh-one-gateway setup [--provider tailscale-serve|cloudflare-access] [--yes] [--print] [--profile PATH]
                    [--trusted-principal PRINCIPAL] [--external-origin URL]
                    [--team-origin URL] [--application-audience AUD]
  dsh-one-gateway doctor [--profile PATH]
  dsh-one-gateway credential issue --store PATH --name operator-1
  dsh-one-gateway credential revoke --store PATH --name operator-1
  dsh-one-gateway credential list --store PATH

Private, zero-trust dsh-one-gateway onboarding. Setup previews a plan, refuses
public/anonymous defaults, and writes a profile entry only after confirmation.
`
}

export function parseArgs(args, { defaultProfile = DEFAULT_PROFILE } = {}) {
  const options = { profile: defaultProfile, _: [] }
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index]
    if (!argument.startsWith('--')) {
      options._.push(argument)
      continue
    }
    if (argument === '--yes') options.yes = true
    else if (argument === '--print') options.print = true
    else if (argument === '--help' || argument === '-h') options.help = true
    else if ([
      '--profile', '--provider', '--trusted-principal', '--trusted-login',
      '--external-origin', '--team-origin', '--application-audience',
      '--store', '--name', '--credential-output',
    ].includes(argument)) {
      const value = args[++index]
      if (!value || value.startsWith('--')) throw new Error(`${argument} requires a value`)
      const key = argument.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())
      options[key] = value
    } else throw new Error(`unknown option: ${argument}`)
  }
  if (options.trustedLogin && !options.trustedPrincipal) options.trustedPrincipal = options.trustedLogin
  if (options.yes && options.print) throw new Error('--yes and --print cannot be used together')
  return options
}

export function tailscaleJson(argv) {
  const result = spawnSync('tailscale', argv, { encoding: 'utf8', maxBuffer: 512 * 1024, shell: false })
  if (result.error) throw new Error(`could not run Tailscale CLI: ${result.error.message}`)
  if (result.status !== 0) {
    throw new Error(`Tailscale ${argv.join(' ')} failed: ${(result.stderr || result.stdout || `exit ${result.status}`).trim()}`)
  }
  try {
    return JSON.parse(result.stdout)
  } catch {
    throw new Error(`Tailscale ${argv.join(' ')} did not return valid JSON`)
  }
}

async function buildTailscalePlan(options, io, deps) {
  const status = deps.tailscaleJson(['status', '--json'])
  const serve = deps.tailscaleJson(['serve', 'status', '--json'])
  const first = createTailscalePlan(status, serve)
  let login = options.trustedPrincipal
  if (!login && isInteractive(io)) {
    login = await ask(`Trusted Tailscale login [${first.inferredLogin}]: `, io) || first.inferredLogin
  } else if (!login) {
    if (options.yes && !isInteractive(io) && !options.trustedPrincipal) {
      throw new Error('non-interactive --yes requires --trusted-principal (or inferred login is only used interactively/--print)')
    }
    login = first.inferredLogin
  }
  return createTailscalePlan(status, serve, { trustedLogin: login })
}

async function buildCloudflarePlan(options, deps) {
  if (!options.externalOrigin || !options.teamOrigin || !options.applicationAudience || !options.trustedPrincipal) {
    throw new Error('cloudflare-access setup requires --external-origin, --team-origin, --application-audience, and --trusted-principal')
  }
  const plan = createCloudflarePlan({
    externalOrigin: options.externalOrigin,
    teamOrigin: options.teamOrigin,
    applicationAudience: options.applicationAudience,
    trustedEmail: options.trustedPrincipal,
  })
  await deps.fetchJwks(plan.config.provider.teamOrigin)
  const probe = await deps.probeAccess(plan.externalOrigin)
  return { ...plan, probe }
}

export async function setupCommand(options, io, deps = {}) {
  const resolved = {
    detect: deps.detect ?? detectProviders,
    fetchJwks: deps.fetchJwks ?? fetchJwksDocument,
    probeAccess: deps.probeAccess ?? probeAccessAttachment,
    tailscaleJson: deps.tailscaleJson ?? tailscaleJson,
    writeProfile: deps.writeProfile ?? writeInitialProfileEntry,
  }
  const detected = resolved.detect()
  const provider = selectProvider(detected, options.provider)
  const plan = provider === PROVIDER_TAILSCALE
    ? await buildTailscalePlan(options, io, resolved)
    : await buildCloudflarePlan(options, resolved)
  const entry = renderProfileEntry(plan.config)
  io.stdout.write(`\n${describePlan(plan)}\n`)
  if (plan.probe) io.stdout.write(`Access probe: ${plan.probe.kind}. ${plan.probe.reason}\n`)
  io.stdout.write(`\nProposed DSH Web-profile entry for ${options.profile}:\n\n${entry}`)
  if (options.print) return { written: false, entry, plan }
  if (!await confirmWrite(options, io)) {
    throw new Error('nothing was written; rerun interactively or pass --yes after reviewing the proposed entry')
  }
  await resolved.writeProfile(options.profile, entry)
  io.stdout.write(
    `\nSaved ${options.profile}. Restart the DSH Web process you own to activate it.\n` +
    `Then run dsh-one-gateway doctor and open ${plan.externalOrigin} as an allowlisted principal.\n` +
    'Setup never restarts supervisors or removes provider resources.\n',
  )
  return { written: true, entry, plan }
}

export async function doctorCommand(options, io, deps = {}) {
  const detect = deps.detect ?? detectProviders
  const readJson = deps.tailscaleJson ?? tailscaleJson
  io.stdout.write(`Profile: ${options.profile}\n`)
  const detected = detect()
  io.stdout.write(`Detected providers: ${detected.length === 0 ? '(none)' : detected.map(item => item.id).join(', ')}\n`)
  if (detected.some(item => item.id === PROVIDER_TAILSCALE)) {
    try {
      const status = readJson(['status', '--json'])
      const self = status?.Self?.DNSName ?? '(unknown)'
      io.stdout.write(`Tailscale MagicDNS: ${self}\n`)
    } catch (error) {
      io.stdout.write(`Tailscale status: ${error instanceof Error ? error.message : String(error)}\n`)
    }
  }
  io.stdout.write('Doctor does not mutate provider state or restart DSH.\n')
}

export async function credentialCommand(subcommand, options, io) {
  if (!options.store) throw new Error('credential commands require --store PATH')
  if (subcommand === 'list') {
    const entries = await listCredentials(options.store)
    if (entries.length === 0) io.stdout.write('(no credentials)\n')
    for (const entry of entries) {
      io.stdout.write(`${entry.principalId} revoked=${entry.revoked} createdAt=${entry.createdAt ?? ''}\n`)
    }
    return
  }
  if (!options.name) throw new Error(`${subcommand} requires --name`)
  if (subcommand === 'issue') {
    const issued = await issueCredential(options.store, options.name)
    io.stdout.write(`Issued ${issued.principalId}. The raw secret is shown once and is not stored.\n`)
    io.stdout.write(`${issued.secret}\n`)
    return issued
  }
  if (subcommand === 'revoke') {
    const revoked = await revokeCredential(options.store, options.name)
    io.stdout.write(`Revoked ${revoked.principalId}. In-memory sessions drop on sidecar restart; a running sidecar re-reads the store on the next authenticate.\n`)
    return revoked
  }
  throw new Error(`unknown credential subcommand: ${subcommand}`)
}

export async function main(argv = process.argv.slice(2), io = { stdin: process.stdin, stdout: process.stdout, stderr: process.stderr }, deps) {
  const options = parseArgs(argv)
  if (options.help || options._.length === 0) {
    io.stdout.write(usage())
    return
  }
  const [command, subcommand] = options._
  if (command === 'setup') return setupCommand(options, io, deps)
  if (command === 'doctor') return doctorCommand(options, io, deps)
  if (command === 'credential') return credentialCommand(subcommand, options, io)
  throw new Error(`unknown command: ${command}`)
}
