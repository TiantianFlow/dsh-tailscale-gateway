#!/usr/bin/env node
import { main } from '../src/setup/cli.mjs'

main().catch(error => {
  process.stderr.write(`dsh-one-gateway: ${error instanceof Error ? error.message : String(error)}\n`)
  process.exitCode = 1
})
