# DSH One Gateway

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-4c1.svg" alt="MIT license"></a>
  <a href="https://github.com/deepseek-ai/deepseek-harness"><img src="https://img.shields.io/badge/DSH-Web%20profile-0ea5e9.svg" alt="DSH Web-profile bundle"></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/node-%E2%89%A520-339933.svg" alt="Node.js 20 or later"></a>
</p>

<p align="center"><a href="README.md">English</a> · <a href="README.zh-CN.md">简体中文</a></p>

<p align="center"><strong>Share DSH Web with the people you choose — not your whole network.</strong></p>

A [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH) plugin
that puts a private, zero-trust gateway in front of DSH Web. Callers authenticate
through Tailscale Serve or Cloudflare Access; one private allowlist decides who
gets in, and there is no password for you to manage.

The gateway and DSH stay on loopback. Tailscale Serve, or Cloudflare Tunnel with
Cloudflare Access, is only the private ingress. Joining that private network is
**never** an authorization decision. Every request must resolve one unambiguous,
allowlisted principal before anything is forwarded to DSH. That is self-hosted
access control for a zero trust homelab: reachability is not permission.

```text
Allowlisted browser ─ HTTPS ─> provider ingress (Tailscale Serve or Cloudflare Access)
                                      │
                                      └─ identity-aware loopback gateway ─> local DSH
                                         127.0.0.1:3088                127.0.0.1:3080
```

**What you get:** an exact principal allowlist in front of DSH, a loopback-only
HTTP/WebSocket proxy, and a single onboarding command that previews a plan and
refuses public or anonymous defaults. Installing the plugin does nothing until
you run setup.

The full command is `dsh-one-gateway`; a shorter `dsh-gateway` alias is installed too, for typing convenience.

## How this is different

Other DSH gateways often bind the LAN, put a login page in front of DSH, or wrap
a public tunnel. This plugin is a different contract:

1. **Private network membership is never authorization.** Binding `0.0.0.0` or
   treating RFC1918 as an allow is out of scope. The listener stays on loopback.
   Being on the same Wi-Fi, tailnet, or mesh does not get you in.
2. **There is no login page, password, or shared token as the trust root.**
   Password forms, shared tokens, and session-cookie doors are a large auth
   surface and a common source of bugs. Identity comes from the provider itself:
   Serve's injected `Tailscale-User-Login`, or a locally verified Cloudflare
   Access JWT. We check an allowlist. We do not ask you to invent a password.
3. **One plugin, one onboarding command, one allowlist.** Instead of a different
   bespoke setup per provider, Tailscale Serve and Cloudflare Tunnel with Access
   share one loopback gateway. A new provider is another adapter, not another
   product.

## What this plugin does not do

- Make DSH itself multi-tenant, or reduce the privileges of an allowlisted user
  (every allowlisted principal is a full DSH administrator).
- Treat device, node, or mesh membership as human identity.
- Expose a configurable generic reverse proxy or an arbitrary trusted-header
  name.
- Support public anonymous tunnels, Funnel, or Cloudflare quick tunnels.
- Manage provider-wide ACLs, DNS zones, or account policies.
- Auto-remove persistent provider routes on uninstall.
- Accept user-chosen passwords.
- Run more than one ingress provider in one gateway instance.
- Protect you from a malicious same-host administrator or any process that can
  already read DSH memory/configuration or connect directly to DSH loopback.

## Supported providers

| Provider | Auth mode | What identity it proves | What setup does |
| --- | --- | --- | --- |
| Tailscale Serve | `trusted-header` — Serve injects a login header | Exact `Tailscale-User-Login` injected by Serve after it overwrites a caller-supplied value. Not “anyone on the tailnet”. | Can create one missing private Serve route for you (`routeManagement: ensure`), or only check that the route already exists (`verify-only`). |
| Cloudflare Tunnel **with Access** | `signed-jwt` — locally validates an Access identity token | A locally validated Access identity JWT (`Cf-Access-Jwt-Assertion`, RS256, issuer, audience, `email`, non-empty `sub`). Not a convenience email header, not a service token, not “the hostname is private”. | You configure the Access application yourself and point it only at the gateway. Setup verifies local JWT settings (`routeManagement: verify-only`); it cannot independently prove Access stays attached to the tunnel. |
| EasyTier | `gateway-credential` — possession of a gateway secret | Possession of a distinct high-entropy gateway credential. EasyTier is transport only. | **Not shipped.** |

Private reachability is not authorization. A tailnet member, a Cloudflare
hostname that is internet-routable, or a mesh peer can reach an endpoint and
still receive 403 unless the gateway allowlist matches.

Cloudflare nuance: Access-gated applications are often reachable from the
Internet. Packets can arrive unauthenticated. The supported product shape is an
identity-gated application plus mandatory local JWT validation, never an
anonymous public tunnel. Local token validation is solid. The gateway cannot
machine-prove that Access remains attached to the tunnel without broad account
credentials; setup says so, and it still refuses a missing or invalid JWT.

## Quick start

You need a working local DSH Web profile and Node.js 20+ (normally supplied by
DSH).

1. **Install the plugin.** This neither starts a listener nor changes provider
   state. Nothing is exposed until you run setup.

   ```sh
   dsh plugin --profile web add -w /path/to/dsh-one-gateway
   ```

2. **Run guided setup and confirm the displayed plan.**

   Tailscale Serve:

   ```sh
   dsh plugin --profile web exec dsh-gateway -- setup --provider tailscale-serve
   ```

   Cloudflare Access (you configure Access yourself; the gateway only verifies
   the token locally). You must already have an Access application forwarding
   only to `127.0.0.1:3088`:

   ```sh
   dsh plugin --profile web exec dsh-gateway -- setup --provider cloudflare-access \
     --external-origin 'https://dsh.example.invalid' \
     --team-origin 'https://team.example.invalid' \
     --application-audience 'replace-with-access-application-audience' \
     --trusted-principal 'email:operator@example.invalid'
   ```

   Confirmation writes an enabled profile entry. Setup never guesses, kills, or
   restarts your supervisor. Restart the DSH Web process you already own.

3. **Open the configured HTTPS origin as an allowlisted principal.** Port 3088
   itself remains unreachable from the LAN and from the provider network.

Use `--print` to preview without writing. Non-interactive `--yes` requires every
security-sensitive value to be supplied explicitly.

## What each auth mode proves

These `auth.mode` values are the literal YAML keys. Each one is paired with a
fixed provider; you cannot mix them.

- **`trusted-header` (Tailscale only).** Serve injected exactly one
  `Tailscale-User-Login` and the value is on the allowlist as
  `login:<exact-login>`. The header name is fixed in code. You cannot configure
  a generic header.
- **`signed-jwt` (Cloudflare Access only).** The request carried exactly one
  `Cf-Access-Jwt-Assertion` that verifies against the team JWKS, with the
  configured issuer and application audience, required `exp`/`iat`/`nbf`,
  identity `type`, scalar `email`, and non-empty `sub`. The allowlist uses
  `email:<exact-email>`. The `CF_Authorization` cookie is never trusted.
- **`gateway-credential` (implemented; no shipped provider uses it yet).**
  Possession of a distinct ≥256-bit credential issued per operator, exchanged at
  a reserved login endpoint for a short-lived `__Host-` session cookie. Ready
  for a future transport-only provider such as EasyTier (deferred). Not selected
  by Tailscale or Cloudflare.

## After setup

```sh
dsh-gateway doctor
dsh-gateway credential issue --store /path/to/dsh-one-gateway/credentials.json --name operator-1
dsh-gateway credential list --store /path/to/dsh-one-gateway/credentials.json
dsh-gateway credential revoke --store /path/to/dsh-one-gateway/credentials.json --name operator-1
```

Disable by setting `enabled: false` on the generated profile entry and
restarting DSH. Uninstall does **not** remove Tailscale Serve routes, Cloudflare
tunnels, Access applications, or credential files. Remove those yourself.

## Threat model and local-host trust boundary

The gateway defends against spoofed identity headers, public-mode provider
configuration, Host/Origin/request-target smuggling, provider tokens leaking
into DSH, stale JWT keys, and config typos that would broaden exposure. See
`SECURITY.md`.

It does **not** defend against a process on the same host that can connect to
`127.0.0.1:3080` or `127.0.0.1:3088`, read the DSH profile, or act as a local
root. Loopback TCP cannot prove which local executable opened it. Same-host
compromise is out of scope.

## TLS, keys, and credentials

- Profile YAML never contains private keys, JWTs, or issued credential secrets.
- Cloudflare signing keys are fetched from the team origin JWKS path with
  bounded HTTPS; they are not written to the profile.
- Gateway credentials (when used) store only a verifier at an operator-supplied
  absolute path with restrictive permissions. The raw secret is shown once.
- Backup the credential store as you would any other secret file; revocation is
  per principal. Sessions are in-memory and drop when the gateway process
  restarts.

## Troubleshooting

Do **not** disable auth, Origin checks, TLS, or provider verification to “just
get it working”.

| Symptom | What to check |
| --- | --- |
| Gateway never becomes ready | `dsh-gateway doctor`; Tailscale Serve conflict/Funnel; Cloudflare JWKS fetch; missing allowlist |
| 403 for an expected user | Exact, case-sensitive principal (`login:` / `email:`); duplicate identity headers; missing Origin on POST/API/WebSocket |
| Setup refuses to write | Existing `dsh-gateway` or legacy `dsh-tailscale-gateway` entry; non-list YAML; missing `--yes` values |
| Cloudflare still 403 with Access | Identity token missing/expired; wrong audience; service token (no `email`); Access not attached (probe may report `unprotected`) |

## Not supported yet

These may map onto the same contracts later. “It is a VPN” is not enough.

- **EasyTier** — no application-level identity of who's actually calling (the
  correct mapping is `gateway-credential`), but overlay-only bind, forwarding,
  and post-verification were not evidenced.
- **Headscale** — no native Serve equivalent; a reverse proxy you run yourself
  would not inherit Serve's guarantee that it overwrites a caller-supplied
  identity header.
- **ZeroTier / WireGuard-only** — no application-level identity; would need
  `gateway-credential`, mTLS, or an identity proxy plus private-bind/TLS
  evidence.
- **NetBird** — claimed identity headers are unsupported until a cited overwrite
  profile and integration test exist.
- **Twingate / Pangolin** — no frozen JWT/header validation profile.
- **Generic reverse proxy / arbitrary trusted-header** — too easy to configure
  with a spoofable header.
- **Raw LAN, SSH tunnel, public tunnel** — outside the private-ingress contract.

The older `dsh-tailscale-gateway` package remains a Tailscale-only reference
product. The two gateway processes cannot bind the same fixed gateway port at
once. Setup detects a legacy profile entry and refuses to append another.

## Configuration

Only the exact fields shown below are accepted. Unknown keys are errors. There
are no `listenHost`, `listenPort`, `upstream`, `headerName`, `jwksUrl`,
`allowAnonymous`, `trustPrivateNetwork`, `public`, or `funnel` keys.

Tailscale — `trusted-header` means Serve injects the login; `routeManagement:
ensure` means setup will create one missing private Serve route:

```yaml
enabled: true
externalOrigin: 'https://gateway.example-tailnet.ts.net:8443'
provider:
  type: tailscale-serve
  routeManagement: ensure
auth:
  mode: trusted-header
  trustedPrincipals:
    - 'login:operator@example.invalid'
```

Cloudflare — `signed-jwt` means the gateway locally validates the Access
identity JWT; `routeManagement: verify-only` means you attach Access yourself:

```yaml
enabled: true
externalOrigin: 'https://dsh.example.invalid'
provider:
  type: cloudflare-access
  routeManagement: verify-only
  teamOrigin: 'https://team.example.invalid'
  applicationAudience: 'replace-with-access-application-audience'
auth:
  mode: signed-jwt
  trustedPrincipals:
    - 'email:operator@example.invalid'
```

## License

MIT. See `LICENSE`.
