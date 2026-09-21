import { parseArgs } from 'node:util'
import { createRequire } from 'node:module'
import { status } from './commands/status.js'
import { key } from './commands/key.js'
import { wallet } from './commands/wallet.js'
import { attest, updateKey, reattest, revoke, submit, finishAuthorization } from './commands/attest.js'
import { relay } from './commands/relay.js'
import { keyserver } from './commands/keyserver.js'
import { record } from './commands/record.js'
import { ens } from './commands/ens.js'
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
  … --no-key --owner <address|ens>              sign here, publish from a wallet elsewhere: prints a
                                                thurin.id/attest link that carries the signed claim
  … --authorize [--deadline 7d] [--out f.json]  no ETH here: the keystore signs a permission slip
                                                (free) that anyone can publish and pay for
      [--relayer <url> | --no-relayer]          post it to a relayer that pays, instead of a link
      [--signer <cmd>]                          sign the slip with a program (a card): typed data on its
                                                stdin, signature on its stdout. Needs --owner
      [--sign-out f.json]                       air gap: write what needs signing and stop, then
  thurin authorize finish f.json --signature 0x…   (or --signature-file) to check and hand it out
  thurin submit <link|file>                     publish someone's authorization from this keystore

${bold('Records')} (small values on your claim; the chain names what you put out)
  thurin record get <identity> <kind>           anyone can read; thurin.pointer lists releases
  thurin record add-release <name> <SHA256SUMS> [--url u]   name a release on-chain by its checksum file
  thurin record set <kind> <value|--file f> | clear <kind>

  thurin ens check <name>                       does the name's id.thurin record point at its claim?
  thurin ens link <name> [--key <fpr>]          set it from the keystore; --calldata prints the tx for
                                                the wallet that manages the name instead

${bold('Be a keyserver')} (gpg reads keys from Ethereum; no upload, no database)
  thurin keyserver [--port 11371] [--host 127.0.0.1] [--cache-seconds 60]
  then: gpg --keyserver hkp://127.0.0.1:11371 --recv-keys <fingerprint>

${bold('Run a relayer')} (the one command that spends: gas only, within a budget, from a hot key)
  thurin relay --account <hot> [--budget 0.01] [--port 8787] [--free-attests 1] [--per-hour 10] [--max-gas 3000000]

${bold('Options')}
  --network mainnet|sepolia|local   --rpc <url>   --account <name>   --password-file <path>
  --site <url>   (where --no-key / --authorize links point; default https://thurin.id)
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
      key: { type: 'string', short: 'k' }, calldata: { type: 'boolean' }, 'include-email': { type: 'boolean' }, replace: { type: 'boolean' }, import: { type: 'boolean' },
      name: { type: 'string' }, expires: { type: 'string' }, from: { type: 'string' }, 'private-key': { type: 'boolean' },
      'no-key': { type: 'boolean' }, owner: { type: 'string' }, site: { type: 'string' },
      authorize: { type: 'boolean' }, deadline: { type: 'string' }, out: { type: 'string' },
      signer: { type: 'string' }, 'sign-out': { type: 'string' }, signature: { type: 'string' }, 'signature-file': { type: 'string' },
      relayer: { type: 'string' }, 'no-relayer': { type: 'boolean' },
      budget: { type: 'string' }, port: { type: 'string' }, host: { type: 'string' }, 'cache-seconds': { type: 'string' }, file: { type: 'string' }, index: { type: 'string' }, url: { type: 'string' }, 'per-hour': { type: 'string' }, 'free-attests': { type: 'string' }, 'max-gas': { type: 'string' },
    },
  })
  const opts: Record<string, any> = { ...values, passwordFile: values['password-file'], includeEmail: values['include-email'], privateKey: values['private-key'], noKey: values['no-key'], noRelayer: values['no-relayer'], perHour: values['per-hour'], freeAttests: values['free-attests'], maxGas: values['max-gas'], cacheSeconds: values['cache-seconds'], signOut: values['sign-out'], signatureFile: values['signature-file'] }
  setJson(!!opts.json)
  if (opts.version) { process.stdout.write(version + '\n'); return }
  const [cmd, ...rest] = positionals
  if (opts.help || !cmd) { process.stdout.write(HELP); process.exitCode = opts.help ? 0 : EXIT.USAGE; return }  // bare `thurin` is a usage error; `--help` is not

  switch (cmd) {
    case 'status': return status(rest, opts)
    case 'key': return key(rest, opts)
    case 'wallet': return wallet(rest, opts)
    case 'attest': return attest(rest, opts)
    case 'update-key': return updateKey(rest, opts)
    case 'reattest': return reattest(rest, opts)
    case 'revoke': return revoke(rest, opts)
    case 'submit': return submit(rest, opts)
    case 'authorize': if (rest[0] === 'finish') return finishAuthorization(rest.slice(1), opts); throw new CliError('Usage: thurin authorize finish <sign-out.json> --signature 0x…', EXIT.USAGE)
    case 'relay': return relay(rest, opts)
    case 'keyserver': return keyserver(rest, opts)
    case 'record': return record(rest, opts)
    case 'ens': return ens(rest, opts)
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
