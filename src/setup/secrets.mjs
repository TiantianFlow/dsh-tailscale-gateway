import { randomBytes } from 'node:crypto'
import { ACTIVATION_TOKEN_BYTES } from '../core/constants.mjs'
import { parseActivationToken } from '../core/config.mjs'

export function createActivationToken() {
  return parseActivationToken(randomBytes(ACTIVATION_TOKEN_BYTES).toString('base64url'))
}
