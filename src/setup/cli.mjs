import { spawnSync } from 'node:child_process'
import { unlink } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'
import process from 'node:process'
import { PROVIDER_CLOUDFLARE, PROVIDER_HEADSCALE_TCP_SERVE, PROVIDER_TAILSCALE } from '../core/constants.mjs'
import { fetchJwksDocument } from '../auth/jwks.mjs'
import {
  issueCredential,
  listCredentials,
  readCredentialStore,
  revokeCredential,
  writeCredentialStore,
} from '../auth/credential-store.mjs'
import { probeAccessAttachment } from '../providers/cloudflare-access.mjs'
import { describeTcpServeStatus } from '../providers/headscale-tcp-serve.mjs'
import {
  classifyControlPlane,
  detectProviders,
  refineDetectedProviders,
  selectProvider,
} from './detect.mjs'
import { createCloudflarePlan, createHeadscaleTcpPlan, createTailscalePlan, describePlan } from './plan.mjs'
import { renderProfileEntry, writeInitialProfileEntry } from './profile.mjs'
import { ask, askRequired, chooseProvider, confirmWeakerAuth, confirmWrite, isInteractive } from './prompts.mjs'

export const DEFAULT_DSH_HOME = process.env.DSH_HOME || join(homedir(), '.dsh')
export const DEFAULT_PROFILE = join(DEFAULT_DSH_HOME, 'profiles', 'web', 'cordis.patch.yml')

export function usage() {
  return `Usage:
  dsh-one-gateway setup [--provider tailscale-serve|cloudflare-access|headscale-tcp-serve] [--yes] [--print] [--profile PATH]
                    [--trusted-principal PRINCIPAL] [--external-origin URL]
                    [--team-origin URL] [--application-audience AUD]
                    [--tls-cert PATH] [--tls-key PATH] [--credential-store PATH]
  dsh-one-gateway doctor [--profile PATH]
  dsh-one-gateway credential issue --store PATH --name operator-1
  dsh-one-gateway credential revoke --store PATH --name operator-1
  dsh-one-gateway credential list --store PATH

Private, zero-trust dsh-one-gateway onboarding. Setup previews a plan, refuses
public/anonymous defaults, and writes a profile entry only after confirmation.
Omitting --provider in a TTY opens a menu. Operators on Tailscale.com are
steered to identity-aware Tailscale Serve; Headscale TCP Serve (credential-only)
is offered when the live node is on Headscale, or when --provider
headscale-tcp-serve is passed explicitly after the tradeoff. Non-interactive
setup still requires --provider when zero or multiple providers are detected.
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
      '--tls-cert', '--tls-key', '--credential-store',
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

export async function resolveSetupProvider(options, detected, io, { controlPlane } = {}) {
  if (options.provider) {
    return { ...options, provider: selectProvider(detected, options.provider) }
  }
  if (isInteractive(io)) {
    return { ...options, provider: await chooseProvider(detected, io, { controlPlane }) }
  }
  return { ...options, provider: selectProvider(detected) }
}

async function buildHeadscaleTcpPlan(options, io, deps, { allowOfficial = false } = {}) {
  const collected = { ...options }
  if (isInteractive(io)) {
    io.stdout.write(
      'Headscale TCP Serve is private reachability only. It does not prove who you are.\n' +
      'The gateway will terminate TLS on 127.0.0.1:3088 with an operator-supplied certificate\n' +
      'and authenticate with a generated gateway credential (not a user-chosen password).\n',
    )
    const eofMessage = 'dsh-one-gateway: setup ended before required Headscale TCP Serve values were collected; rerun with --tls-cert, --tls-key, and --credential-store'
    if (!collected.tlsCert) collected.tlsCert = await askRequired('TLS certificate path (absolute): ', io, { eofMessage })
    if (!collected.tlsKey) collected.tlsKey = await askRequired('TLS private key path (absolute): ', io, { eofMessage })
    if (!collected.credentialStore) collected.credentialStore = await askRequired('Credential store path (absolute): ', io, { eofMessage })
    if (!collected.trustedPrincipal) {
      collected.trustedPrincipal = await ask('Trusted credential name [operator-1]: ', io) || 'operator-1'
    }
  }
  if (!collected.tlsCert || !collected.tlsKey || !collected.credentialStore) {
    throw new Error('headscale-tcp-serve setup requires --tls-cert, --tls-key, and --credential-store')
  }
  const status = deps.tailscaleJson(['status', '--json'])
  const serve = deps.tailscaleJson(['serve', 'status', '--json'])
  return createHeadscaleTcpPlan(status, serve, {
    trustedPrincipal: collected.trustedPrincipal,
    tlsCertPath: collected.tlsCert,
    tlsKeyPath: collected.tlsKey,
    credentialStorePath: collected.credentialStore,
    externalOrigin: collected.externalOrigin,
    allowOfficial,
  })
}

async function buildCloudflarePlan(options, io, deps) {
  const collected = { ...options }
  if (isInteractive(io)) {
    io.stdout.write(
      'Cloudflare setup is verify-only. It will not create a tunnel, DNS record, or Access application.\n' +
      'Use an existing Access-protected HTTPS application.\n',
    )
    if (!collected.externalOrigin) {
      collected.externalOrigin = await askRequired('Existing Access application origin (HTTPS): ', io)
    }
    if (!collected.teamOrigin) {
      collected.teamOrigin = await askRequired('Cloudflare Access team origin (HTTPS): ', io)
    }
    if (!collected.applicationAudience) {
      collected.applicationAudience = await askRequired('Cloudflare Access application audience (aud): ', io)
    }
    if (!collected.trustedPrincipal) {
      collected.trustedPrincipal = await askRequired('Trusted Cloudflare Access email: ', io)
    }
  }
  if (!collected.externalOrigin || !collected.teamOrigin || !collected.applicationAudience || !collected.trustedPrincipal) {
    throw new Error('cloudflare-access setup requires --external-origin, --team-origin, --application-audience, and --trusted-principal')
  }
  const plan = createCloudflarePlan({
    externalOrigin: collected.externalOrigin,
    teamOrigin: collected.teamOrigin,
    applicationAudience: collected.applicationAudience,
    trustedEmail: collected.trustedPrincipal,
  })
  await deps.fetchJwks(plan.config.provider.teamOrigin)
  const probe = await deps.probeAccess(plan.externalOrigin)
  return { ...plan, probe }
}

function inspectControlPlane(detected, tailscaleJsonFn) {
  const related = detected.some(item => item.id === PROVIDER_TAILSCALE || item.id === PROVIDER_HEADSCALE_TCP_SERVE)
  if (!related) return { detected, controlPlane: undefined }
  try {
    const status = tailscaleJsonFn(['status', '--json'])
    const controlPlane = classifyControlPlane(status)
    return { detected: refineDetectedProviders(detected, controlPlane), controlPlane }
  } catch {
    return { detected, controlPlane: { kind: 'unknown' } }
  }
}

async function maybeConfirmWeakerAuth(options, io, controlPlane) {
  if (options.provider !== PROVIDER_HEADSCALE_TCP_SERVE) return
  if (controlPlane?.kind !== 'official') return
  io.stdout.write(
    'This node appears to be on Tailscale.com, where tailscale-serve (trusted-header) is the stronger path.\n' +
    'headscale-tcp-serve uses a generated gateway credential instead of Tailscale user identity.\n',
  )
  if (options.print || options.yes || !isInteractive(io)) return
  if (!await confirmWeakerAuth(io)) {
    throw new Error('refusing the weaker credential-only path; rerun with --provider tailscale-serve')
  }
}

async function commitHeadscaleSetup(options, io, plan, entry, deps) {
  if (options.print) return { written: false, issued: null }
  if (!await confirmWrite(options, io)) {
    throw new Error('nothing was written; rerun interactively or pass --yes after reviewing the proposed entry')
  }
  let previous
  let storeExisted = true
  try {
    previous = await deps.readCredentialStore(plan.credentialStorePath)
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error
    storeExisted = false
    previous = null
  }
  const issued = await deps.issueCredential(plan.credentialStorePath, plan.credentialName)
  try {
    await deps.writeProfile(options.profile, entry)
  } catch (error) {
    try {
      if (storeExisted && previous) await deps.writeCredentialStore(plan.credentialStorePath, previous)
      else await deps.removeStore(plan.credentialStorePath)
    } catch (rollbackError) {
      throw new Error(
        `profile write failed and credential-store rollback failed: ${error instanceof Error ? error.message : String(error)}; ${rollbackError instanceof Error ? rollbackError.message : String(rollbackError)}`,
      )
    }
    throw new Error(`profile write failed; credential store rolled back: ${error instanceof Error ? error.message : String(error)}`)
  }
  io.stdout.write(`Issued ${issued.principalId}. The raw secret is shown once and is not stored.\n`)
  io.stdout.write(`${issued.secret}\n`)
  return { written: true, issued }
}

export async function setupCommand(options, io, deps = {}) {
  const resolved = {
    detect: deps.detect ?? detectProviders,
    fetchJwks: deps.fetchJwks ?? fetchJwksDocument,
    probeAccess: deps.probeAccess ?? probeAccessAttachment,
    tailscaleJson: deps.tailscaleJson ?? tailscaleJson,
    writeProfile: deps.writeProfile ?? writeInitialProfileEntry,
    issueCredential: deps.issueCredential ?? issueCredential,
    readCredentialStore: deps.readCredentialStore ?? readCredentialStore,
    writeCredentialStore: deps.writeCredentialStore ?? writeCredentialStore,
    removeStore: deps.removeStore ?? unlink,
  }
  const detected = resolved.detect()
  const inspected = inspectControlPlane(detected, resolved.tailscaleJson)
  const setupOptions = await resolveSetupProvider(options, inspected.detected, io, { controlPlane: inspected.controlPlane })
  if (setupOptions.provider === PROVIDER_TAILSCALE && inspected.controlPlane?.kind === 'headscale') {
    throw new Error('this node is on a Headscale control plane; Tailscale HTTPS Serve identity is not available. Use --provider headscale-tcp-serve')
  }
  await maybeConfirmWeakerAuth(setupOptions, io, inspected.controlPlane)
  const plan = setupOptions.provider === PROVIDER_TAILSCALE
    ? await buildTailscalePlan(setupOptions, io, resolved)
    : setupOptions.provider === PROVIDER_HEADSCALE_TCP_SERVE
      ? await buildHeadscaleTcpPlan(setupOptions, io, resolved, {
        allowOfficial: inspected.controlPlane?.kind === 'official',
      })
      : await buildCloudflarePlan(setupOptions, io, resolved)
  const entry = renderProfileEntry(plan.config)
  io.stdout.write(`\n${describePlan(plan)}\n`)
  if (plan.probe) io.stdout.write(`Access probe: ${plan.probe.kind}. ${plan.probe.reason}\n`)
  io.stdout.write(`\nProposed DSH Web-profile entry for ${options.profile}:\n\n${entry}`)
  if (setupOptions.provider === PROVIDER_HEADSCALE_TCP_SERVE) {
    const result = await commitHeadscaleSetup(options, io, plan, entry, resolved)
    if (result.written) {
      io.stdout.write(
        `\nSaved ${options.profile}. Restart the DSH Web process you own to activate it.\n` +
        `Then run dsh-one-gateway doctor and open ${plan.externalOrigin} as an allowlisted principal.\n` +
        'Enroll client TLS trust for the operator-supplied certificate. Setup never restarts supervisors or removes provider resources.\n',
      )
    }
    return { ...result, entry, plan }
  }
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
  const tailscaleDetected = detected.some(item => item.id === PROVIDER_TAILSCALE || item.id === PROVIDER_HEADSCALE_TCP_SERVE)
  if (tailscaleDetected) {
    try {
      const status = readJson(['status', '--json'])
      const plane = classifyControlPlane(status)
      const self = status?.Self?.DNSName ?? '(unknown)'
      io.stdout.write(`Tailscale MagicDNS: ${self}\n`)
      io.stdout.write(`Control plane: ${plane.kind}${plane.hostname ? ` (${plane.hostname})` : ''}\n`)
    } catch (error) {
      io.stdout.write(`Tailscale status: ${error instanceof Error ? error.message : String(error)}\n`)
    }
    try {
      const serve = readJson(['serve', 'status', '--json'])
      const receipt = describeTcpServeStatus(serve)
      io.stdout.write(`TCP Serve handlers:\n${receipt.handlers.map(line => `  ${line}`).join('\n')}\n`)
      io.stdout.write(`TCP Serve Funnel: ${receipt.funnel ? 'enabled' : 'disabled'}\n`)
    } catch (error) {
      io.stdout.write(`TCP Serve status: ${error instanceof Error ? error.message : String(error)}\n`)
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
