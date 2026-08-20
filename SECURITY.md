# Security policy

## Supported versions

Before the first release, security fixes target the current default branch.
After the first `0.1.x` release, fixes target the latest `0.1.x` version;
older versions may not receive fixes.

## Reporting a vulnerability

Do not open a public issue for a suspected bypass, header-parsing flaw,
authentication issue, exposure of DSH, or credential leak.

After the repository is published, use GitHub's private security advisory flow.
Include a minimal reproduction, affected version or commit, impact, and any
mitigations you have identified. Allow time for triage and a coordinated fix
before public disclosure.

## In scope

- Identity provenance (`trusted-header` overwrite profile, `signed-jwt`
  validation, `gateway-credential` issuance/session handling)
- Duplicate/malformed raw headers, Host/Origin/Fetch Metadata, request-target
  smuggling
- HTTP and WebSocket proxying, credential/header stripping, upstream leak of
  provider tokens or gateway cookies
- Provider public-mode classification (Funnel, quick tunnel, Access-less tunnel)
- Loopback/upstream escape via configuration keys
- Secret leakage in logs, profile YAML, credential stores, or package contents
- Destructive setup (overwriting unrelated YAML, resetting provider routes)

## Trust boundary

Every allowlisted principal is a full DSH administrator. The gateway does not
reduce DSH privileges.

A loopback TCP connection cannot prove which local executable opened it.
Same-host administrators, local root, and any process that can already connect
to `127.0.0.1:3080` or read DSH configuration are out of scope.

Private network membership is never an authorization decision.

## Cloudflare signing keys

v1 loads JWKS from the configured team origin with bounded HTTPS (timeout,
size, no redirects, hostname match). Fresh keys are used inside the cache TTL;
a short stale window may reuse last-known-good keys; after that, authentication
and readiness fail closed. A provider key outage intentionally denies access.

## Credential incidents

If a gateway credential may be stolen:

1. `dsh-gateway credential revoke --store /path/to/dsh-gateway/credentials.json --name operator-1`
2. Restart the DSH Web sidecar so in-memory sessions drop.
3. Issue a replacement credential. The raw secret is shown once and is never
   stored.

There is no permanent account lockout. Login throttling is bounded and recovers
automatically.

## Disclosure

Please do not publicly disclose a bypass until a fix is available or you have
heard from a maintainer. After publication, advisories will follow GitHub's
security advisory process.
