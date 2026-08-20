# Contributing

This package is a private, zero-trust DSH gateway. Changes must preserve the
invariants in the README.

## Invariants to preserve

- Listener and upstream are literal IPv4 loopback, fixed in code, not
  configurable.
- No request reaches DSH until an auth mode returns one unambiguous,
  allowlisted principal.
- Private-network membership is never an authorization decision.
- External origins are HTTPS and origin-only.
- Provider/auth combinations are an explicit compatibility matrix. There is no
  generic/arbitrary trusted-header name.
- Setup and startup fail closed on uncertain, public, or malformed state.
- Provider managers mutate only an absent resource whose complete desired shape
  is known. They do not reset, delete, or “fix” conflicts.
- Provider JWTs, identity headers, gateway credentials, and gateway session
  cookies never reach DSH.

## New provider adapters

An adapter evidence checklist is required:

1. Primary-doc citation for the identity signal.
2. Exact identity header or JWT profile, including overwrite/spoofing analysis.
3. Private vs public provider states (Funnel, quick tunnel, anonymous).
4. `inspect` / `plan` / `apply` / `verify` shapes, including conflict.
5. Teardown behavior (v1 does not auto-remove persistent routes).

Do not add an arbitrary trusted-header profile. Do not add a public or
anonymous provider mode. EasyTier remains out of v1 until overlay-only bind and
post-verification evidence exists; do not add `providers/easytier.mjs`.

## Tests

Every new success path needs a matching negative test. Fail closed on
ambiguous, malformed, expired, and duplicate evidence.

Fixtures and docs must use placeholders only (`example.invalid`,
`example-tailnet.ts.net`, `/path/to/...`). The publish-safety test enforces
this.

## Dependencies

Every runtime dependency needs a security and maintenance justification. v1
uses `jose` only to verify RS256 Access tokens with explicit issuer, audience,
and algorithm options. Do not implement JWT cryptography.

## Documentation

User-visible or security-relevant changes should update English and Simplified
Chinese READMEs with equivalent security content, not a translated marketing
summary.

Pull requests should cover user impact, security impact, tests, provider
versions touched, and docs.
