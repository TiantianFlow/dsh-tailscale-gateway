import assert from 'node:assert/strict'
import test from 'node:test'
import { createAuth } from '../src/auth/create.mjs'

function gatewayCredentialFactoryConfig(identityKind) {
  return {
    enabled: true,
    externalOrigin: 'https://gateway.example.invalid',
    provider: { type: 'tailscale-serve' },
    auth: {
      mode: 'gateway-credential',
      trustedPrincipals: ['credential:operator-1'],
      credentialStorePath: '/path/to/dsh-one-gateway/credentials.json',
    },
    identity: { identityKind },
  }
}

test('createAuth rejects gateway-credential for overwritten-header and signed-jwt identity kinds', async () => {
  await assert.rejects(
    createAuth(gatewayCredentialFactoryConfig('overwritten-header')),
    /gateway-credential requires identityCapability none/,
  )
  await assert.rejects(
    createAuth(gatewayCredentialFactoryConfig('signed-jwt')),
    /gateway-credential requires identityCapability none/,
  )
})
