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
through Tailscale Serve, Cloudflare Access, or — on Headscale — a generated
gateway credential in front of private TCP Serve. One private allowlist decides
who gets in. There is no user-chosen password to manage.

The gateway and DSH stay on loopback. Tailscale Serve, Cloudflare Tunnel with
Cloudflare Access, or Headscale via Tailscale TCP Serve is only the private
ingress. Joining that private network is **never** an authorization decision.
Every request must resolve one unambiguous, allowlisted principal before
anything is forwarded to DSH. That is self-hosted access control for a zero
trust homelab: reachability is not permission.

```text
Allowlisted browser ─ HTTPS ─> provider ingress (Tailscale Serve, Cloudflare Access,
                                      │           or Headscale TCP Serve)
                                      └─ loopback gateway ─> local DSH
                                         127.0.0.1:3088   127.0.0.1:3080
```

**What you get:** an exact principal allowlist in front of DSH, a loopback-only
HTTP/WebSocket proxy, and a single onboarding command that previews a plan and
refuses public or anonymous defaults. Installing the plugin does nothing until
you run setup.

The full command is `dsh-one-gateway`; a shorter `dsh-gateway` alias is installed too, for typing convenience.

## How this is different

Other DSH gateways may bind off loopback, patch DSH internals so a gate stays
exhaustive after upgrades, or run a reverse proxy in front of DSH. Those
designs can cover `/api` and WebSockets too; the difference is not who covers
more of the surface. This plugin is a different contract: DSH itself never
leaves loopback.

1. **Private network membership is never authorization.** Binding `0.0.0.0` or
   treating RFC1918 as an allow is out of scope. The listener stays on loopback.
   Being on the same Wi-Fi, tailnet, or mesh does not get you in.
2. **Fail-closed DSH origin.** DSH stays on loopback; the gateway is the only
   listener in front of it. A DSH upgrade cannot silently add a route that
   becomes reachable off-host — there is no gate route table to keep
   exhaustive, because DSH was never reachable off-host to begin with. A missed
   route in a full-coverage gate is a silent bypass; a missed route in this
   bridge just breaks that one proxied path. It does not expose DSH.
3. **No DSH-core or client-library patches.** Some gates stay exhaustive by
   patching DSH HTTP and upgrade entry points, then re-applying those patches
   after every upgrade — because an upstream change can silently undo them.
   This gateway is an external process. DSH's own code is never modified.
4. **For Tailscale Serve and Cloudflare Access, identity comes from the
   provider — not a login page, password, or shared token.**
   Password forms, shared tokens, and session-cookie doors are a large auth
   surface and a common source of bugs. Those two shipped modes use Serve's
   injected `Tailscale-User-Login`, or a locally verified Cloudflare Access
   JWT. We check an allowlist. We do not ask you to invent a password.
   `gateway-credential` is a smaller, purpose-built login for transports with
   no native identity: a generated per-principal credential (not a user-chosen
   password), verifier-only storage, a bounded
   `HttpOnly`/`Secure`/`SameSite=Strict` session, individual revocation, and
   rate limiting without permanent lockout. Compared with a typical
   user-chosen or shared password, that is stronger on guessability, storage
   disclosure, and revocation; it is not "passwordless" and not a claim of
   superiority over every password or passkey. Headscale TCP Serve is the
   shipped transport that uses this mode. For any transport-only provider with
   no native identity, the contract is a product-owned bridge from the private
   overlay to the unchanged loopback gateway, authenticated with
   `gateway-credential` — never a fabricated identity header.
5. **One plugin, one onboarding command, one allowlist.** Instead of a different
   bespoke setup per provider, Tailscale Serve, Cloudflare Tunnel with Access,
   and Headscale TCP Serve share one loopback gateway. A new provider is
   another adapter, not another product.

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
| Headscale via Tailscale TCP Serve | `gateway-credential` — possession of a gateway secret | Possession of a distinct high-entropy gateway credential issued per operator. TCP Serve supplies private reachability only; it has no HTTP identity header and does not prove who you are. | Can create one missing private TCP Serve forward to `127.0.0.1:3088` (`ensure`), or only check that it exists (`verify-only`). You supply the TLS certificate and key. Setup on Tailscale.com steers you to identity-aware Tailscale Serve instead. |
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

   In a terminal, omit `--provider` to choose from a menu. Operators on
   Tailscale.com are steered to identity-aware Tailscale Serve; Headscale TCP
   Serve is listed when the live node is on Headscale. Detection of a local
   executable is a hint and, when exactly one provider is found, a default —
   not a configuration check. Pass `--provider` to skip the menu.
   Non-interactive setup still auto-selects when exactly one provider
   executable is detected, and otherwise requires `--provider`.

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

   In a TTY, omitted Cloudflare values are collected interactively in this
   order: existing Access origin, team origin, application audience, trusted
   email. Unattended `--yes` still requires all four flags. Setup never creates
   a tunnel, DNS record, or Access application.

   Headscale TCP Serve (private reachability plus a generated gateway
   credential; you supply the certificate). Setup on Tailscale.com will not
   offer this as an equal menu choice:

   ```sh
   dsh plugin --profile web exec dsh-gateway -- setup --provider headscale-tcp-serve \
     --tls-cert /path/to/dsh-one-gateway/cert.pem \
     --tls-key /path/to/dsh-one-gateway/key.pem \
     --credential-store /path/to/dsh-one-gateway/credentials.json \
     --trusted-principal operator-1
   ```

   TCP Serve does not terminate HTTPS and does not prove identity. The gateway
   terminates TLS on `127.0.0.1:3088` with that operator-supplied certificate.
   Clients must trust the certificate; this pass does not generate a private
   CA. After confirmation, setup issues one credential, prints the raw secret
   once, and never writes it to the profile. `--print` issues nothing.

   Confirmation writes an enabled profile entry. Setup never guesses, kills, or
   restarts your supervisor. Restart the DSH Web process you already own.

3. **Open the configured HTTPS origin as an allowlisted principal.** Port 3088
   itself remains unreachable from the LAN and from the provider network.

Use `--print` to preview without writing. In a TTY, `--print` may still prompt
for a provider and missing values, but it never writes a profile, provider
resource, or credential. Non-interactive `--yes` requires every
security-sensitive value to be supplied explicitly. `--yes` skips only the
final write confirmation; it does not invent a provider or Cloudflare values.

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
- **`gateway-credential` (Headscale TCP Serve).**
  Possession of a distinct ≥256-bit credential issued per operator (CLI-
  generated, not a user-chosen password), submitted in a POST body from the
  JSON API or a same-origin login form — never a URL query parameter — and
  exchanged for a short-lived `__Host-` session cookie (`HttpOnly`, `Secure`,
  `SameSite=Strict`). The gateway stores only a verifier hash; sessions are
  individually revocable and attempts are rate-limited without permanent
  lockout. TCP Serve does not contribute identity: being able to reach the
  node is not authorization. Tailscale Serve and Cloudflare Access cannot
  select this mode.

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
- Headscale TCP Serve requires an operator-supplied certificate and private
  key (absolute paths, restrictive key permissions, matching pair, unexpired,
  SAN covering `externalOrigin`). The gateway does not generate a CA or
  self-signed certificate. Clients must enroll trust for that certificate.
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
| Gateway never becomes ready | `dsh-gateway doctor`; Tailscale Serve conflict/Funnel; TCP Serve conflict/Funnel; TLS cert/key; Cloudflare JWKS fetch; missing allowlist |
| 403 for an expected user | Exact, case-sensitive principal (`login:` / `email:`); duplicate identity headers; missing Origin on POST/API/WebSocket |
| Setup refuses to write | Existing `dsh-gateway` or legacy `dsh-tailscale-gateway` entry; non-list YAML; missing `--yes` values |
| Cloudflare still 403 with Access | Identity token missing/expired; wrong audience; service token (no `email`); Access not attached (probe may report `unprotected`) |

## Not supported yet

These may map onto the same contracts later. “It is a VPN” is not enough.

- **EasyTier / ZeroTier / WireGuard-only** — no application-level identity
  (the mapping is `gateway-credential`). All three stay out today for one
  shared reason: this codebase cannot yet prove a listener is bound exclusively
  to the private overlay interface, not merely that it reports the right local
  address. Linux and macOS have `SO_BINDTODEVICE` / `IP_BOUND_IF` for that;
  Node's `net.Server.listen()` exposes neither. That is a specific engineering
  gap, not a claim that these transports cannot work. There is no shipped
  adapter for them, and no committed schedule.
- **Headscale HTTPS Serve** — still blocked. Headscale does not provide
  Tailscale's identity-aware HTTPS Serve. The shipped Headscale path is raw
  TCP Serve plus `gateway-credential` and an operator-supplied certificate,
  not a fabricated identity header.
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

Headscale TCP Serve — `gateway-credential` means possession of a generated
secret; TCP Serve is private reachability only. `tls` is required:

```yaml
enabled: true
externalOrigin: 'https://gateway.example.invalid:8443'
provider:
  type: headscale-tcp-serve
  routeManagement: ensure
tls:
  certPath: '/path/to/dsh-one-gateway/cert.pem'
  keyPath: '/path/to/dsh-one-gateway/key.pem'
auth:
  mode: gateway-credential
  trustedPrincipals:
    - 'credential:operator-1'
  credentialStorePath: '/path/to/dsh-one-gateway/credentials.json'
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
