import { parseArgs } from 'node:util'
import { createRequire } from 'node:module'
import { status } from './commands/status.js'
import { key } from './commands/key.js'
import { wallet } from './commands/wallet.js'
import { attest, updateKey, reattest, revoke } from './commands/attest.js'
import { setJson, CliError, EXIT, bold, dim } from './lib/output.js'

const { version } = createRequire(import.meta.url)('../package.json') as { version: string }

const HELP = `${bold('thurin')} ${version} — your online identity, from a terminal. Never a wallet; never holds a PGP secret.

${bold('Look up')}
  thurin status <ens|0x|fingerprint|keyid>     claims, verification, proofs, EFP

${bold('Your PGP key')} (gpg does the work)
  thurin key list                               keys in your keyring, with published name + proofs
  thurin key create <name> [--expires 2y]       Ed25519 key with an encryption subkey, no email
  thurin key add-name <fpr> <name>              add a name without an email (the published name)
  thurin key export [<fpr>]                     minimal armored export
  thurin key fetch <identity> [--import]        the key stored on-chain for an identity
  thurin key default <fpr>

${bold('Your address')} (V3 keystores under ~/.config/thurin/keystores)
  thurin wallet create <name>                   fresh identity address; mnemonic shown once
  thurin wallet import <name> [--from x.json]   private key, mnemonic, or an existing keystore
  thurin wallet list | export <name> [--private-key] | default <name>

${bold('Claims')} (each runs every check before spending gas)
  thurin attest [--key <fpr>] [--include-email]
  thurin update-key [<index>] [--include-email] new proofs on the same key, no new signature
  thurin reattest [<index>] [--key <fpr>]       revoke + publish in one transaction
  thurin revoke [<index>]

${bold('Options')}
  --network mainnet|sepolia|local   --rpc <url>   --account <name>   --password-file <path>
  --json   --yes   --version   --help

Exit codes: 0 ok · 1 a check failed · 2 usage · 3 chain or network error
${dim('Docs: https://docs.thurin.id · Contract 0x9302E02e2869e129aC8516fE5eFFd51EA3082c09 on every network')}
`

async function main() {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    options: {
      json: { type: 'boolean' }, yes: { type: 'boolean', short: 'y' }, help: { type: 'boolean', short: 'h' }, version: { type: 'boolean', short: 'v' },
      network: { type: 'string', short: 'n' }, rpc: { type: 'string' }, account: { type: 'string', short: 'a' }, 'password-file': { type: 'string' },
      key: { type: 'string', short: 'k' }, 'include-email': { type: 'boolean' }, replace: { type: 'boolean' }, import: { type: 'boolean' },
      name: { type: 'string' }, expires: { type: 'string' }, from: { type: 'string' }, 'private-key': { type: 'boolean' },
    },
  })
  const opts: Record<string, any> = { ...values, passwordFile: values['password-file'], includeEmail: values['include-email'], privateKey: values['private-key'] }
  setJson(!!opts.json)
  if (opts.version) { process.stdout.write(version + '\n'); return }
  const [cmd, ...rest] = positionals
  if (opts.help || !cmd) { process.stdout.write(HELP); process.exitCode = cmd ? 0 : EXIT.USAGE; return }

  switch (cmd) {
    case 'status': return status(rest, opts)
    case 'key': return key(rest, opts)
    case 'wallet': return wallet(rest, opts)
    case 'attest': return attest(rest, opts)
    case 'update-key': return updateKey(rest, opts)
    case 'reattest': return reattest(rest, opts)
    case 'revoke': return revoke(rest, opts)
    default: throw new CliError(`Unknown command "${cmd}". Try: thurin --help`, EXIT.USAGE)
  }
}

main().catch((err) => {
  const code = err instanceof CliError ? err.code : EXIT.FAILED
  if (opts_json()) process.stdout.write(JSON.stringify({ error: err.message, code }) + '\n')
  else process.stderr.write(`thurin: ${err.message}\n`)
  process.exit(code)
})

function opts_json() { return process.argv.includes('--json') }
