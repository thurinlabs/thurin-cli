import { parseArgs } from 'node:util'
import { createRequire } from 'node:module'
import { status } from './commands/status.js'
import { key } from './commands/key.js'
import { wallet } from './commands/wallet.js'
import { attest, updateKey, reattest, revoke, cancel, submit, finishAuthorization } from './commands/attest.js'
import { relay } from './commands/relay.js'
import { keyserver } from './commands/keyserver.js'
import { record } from './commands/record.js'
import { ens } from './commands/ens.js'
import { encrypt } from './commands/encrypt.js'
import { setJson, CliError, EXIT, bold, dim } from './lib/output.js'
import { watchNetwork, printNetwork } from './lib/network.js'
import { readConfig } from './lib/config.js'
import { REGISTRY_ADDRESS } from '@thurinlabs/identity-kit/core'

const { version } = createRequire(import.meta.url)('../package.json') as { version: string }

const HELP = `${bold('thurin')} ${version} · your PGP key on your Ethereum address, from a terminal.

  thurin status <ens|0x|fingerprint|keyid>   look up anyone's claims and proofs
  thurin attest                              add your PGP key to your address
  thurin reattest | update-key | revoke      change or end your claim
  thurin encrypt <identity> [file]           encrypt to anyone's verified key
  thurin record ...                          records on your claim
  thurin key ...                             your PGP key (gpg does the work)
  thurin wallet ...                          your address (keystores)
  thurin ens check | link <name>             the name's id.thurin record
  thurin keyserver | relay                   serve keys to gpg, or pay for others' claims

More: thurin help <command>   (e.g. thurin help attest)
Options: --network mainnet|sepolia|local   --json   --yes   Docs: https://docs.thurin.id
`

/** The details for each command, shown by `thurin help <command>` or `thurin <command> --help`. */
const TOPICS: Record<string, string> = {
  status: `${bold('Look up')}

  thurin status <ens|0x|fingerprint|keyid>
      Claims, verification, and proofs for anyone. No keystore needed.
      --no-proofs   ask only the Ethereum node: proofs listed, not checked
`,
  encrypt: `${bold('Encrypt')}  (to the key of the claim that counts; Thurin never sees the message)

  thurin encrypt <identity> [file]
      No file: reads stdin, writes an armored message to stdout (or -o).
      A file: writes <file>.gpg next to it (--armor: <file>.asc).
      -o <path>          where to write
      --sign             sign it with your own key too (--key picks which)
      --show-recipient   name the recipient's key in the message (hidden by default)
      Refuses an identity whose claim doesn't count or whose key can't receive.
      The recipient opens it with: gpg --decrypt
`,
  key: `${bold('Your PGP key')}  (gpg does the work)

  thurin key list
      Keys in your keyring, with the published name and proofs.

  thurin key export [<fpr>]
      A minimal armored export.

  thurin key fetch <identity> [--import]
      The key stored on-chain for an identity.

  thurin key ssh <identity>
      Its SSH keys, as authorized_keys lines, from the claim that counts.
      For sshd: AuthorizedKeysCommand /path/to/thurin key ssh 0x<address>

  thurin key default <fpr>
      The key to use when --key isn't given.

  thurin doesn't make or change keys; gpg does:
      gpg --quick-gen-key "Your Name" ed25519 sign 2y
      gpg --quick-add-key <fingerprint> cv25519 encr 2y
      gpg --quick-add-key <fingerprint> ed25519 auth 2y    an SSH key
      gpg --quick-add-uid <fingerprint> "Your Name"    a name without an email
`,
  wallet: `${bold('Your address')}  (keystores in ~/.config/thurin/keystores)

  thurin wallet create <name>
      A fresh address. The 12 words are shown once.

  thurin wallet import <name> [--from keystore.json]
      From a private key, 12 words, or an existing keystore.

  thurin wallet list
  thurin wallet export <name> [--private-key]
  thurin wallet default <name>

  THURIN_PRIVATE_KEY in the environment also works, for scripts.
`,
  claims: `${bold('Claims')}  (every check runs before any gas is spent)

  thurin attest [--key <fpr>] [--include-email]
      Add your PGP key to your address.

  thurin update-key [<index>] [--include-email]
      New names or proofs on the same key. No new signature.

  thurin reattest [<index>] --key <fpr>
      Replace a claim in one transaction. Its records move to the new one.
      --drop-records    leave the records on the old claim
      --compromised     also mark the old key compromised

  thurin revoke [<index>] [--reason compromised|retired|other]
      End a claim. "compromised" is final: this address can never claim
      that key again. Already revoked or replaced? --reason compromised
      still marks it, once.

More: thurin help no-eth   (your ETH is elsewhere, or you have none)
`,
  'no-eth': `${bold('Your ETH is elsewhere, or you have none')}
  (on attest, reattest, update-key, and record set; revoke takes --authorize only)

  --no-key --owner <address|ens>
      Sign here and publish from a wallet elsewhere, through a link.

  --statement --owner <address|ens>
      The key isn't on this machine: print the line to sign.

  --key-file pub.gpg --statement-file s.sig
      Bring the key and signature back. No gpg needed here.

  --authorize [--deadline 7d] [--out f.json]
      No ETH here: sign a free permission that anyone can publish and pay for.
      --relay <url>       post it to a relay that pays
      --no-relay          make a link instead
      --signer <cmd>      sign with a program, e.g. a card (needs --owner)
      --sign-out f.json   air gap: write what needs signing, and stop (needs --owner)

  thurin authorize finish f.json --signature 0x… | --signature-file f
      Check an air-gapped signature and hand the permission out.

  thurin cancel
      Stop every permission you've signed that hasn't been used yet.
      Your own transaction, so it needs ETH.

  thurin submit <link|file>
      Publish someone's permission from this keystore.

  --site <url>
      Where links point. Default https://thurin.id.
`,
  record: `${bold('Records')}  (small values on your claim)

  thurin record get <identity> [<name>]
      Anyone can read. Without a name, every record on the claim. With one,
      just its value, so it pipes: … get <identity> canary | gpg --verify
      (thurin.releases shows as a list at a terminal)

  thurin record set <name> <value | --file f>
      A name without a dot gets thurin. in front.

  thurin record clear <name>

  thurin record add-release <name> <SHA256SUMS> [--url u]
      Name a release on-chain by its checksum file, in thurin.releases.

  --index <n>
      Which claim, when the address has more than one active.
`,
  ens: `${bold('ENS')}  (mainnet names only)

  thurin ens check <name>
      Does the name's id.thurin record point at its claim?

  thurin ens link <name> [--key <fpr>]
      Set it from the keystore.
      --calldata    print the transaction for the wallet that manages the name
`,
  keyserver: `${bold('Keyserver')}  (gpg reads keys from Ethereum; no upload, no database)

  thurin keyserver [--port 11371] [--host 127.0.0.1] [--cache-seconds 60]
      Then: gpg --keyserver hkp://127.0.0.1:11371 --recv-keys <fingerprint>
`,
  relay: `${bold('Relay')}  (the one command that spends: gas only, within a budget)

  thurin relay --account <keystore> [options]
      Publishes other people's permissions and pays the fee.
      --budget 0.01       ETH per day
      --free-attests 1    claims paid per address
      --per-hour 10       requests per caller
      --max-gas 6000000   per transaction
      --port 8787
`,
  options: `${bold('Options')}

  --network mainnet|sepolia|local    which chain (default mainnet)
  --rpc <url>                        your own node
  --account <name>                   a keystore (or THURIN_PRIVATE_KEY)
  --password-file <path>             for the keystore
  --site <url>                       where links point
  --json                             machine-readable output
  --show-network                     list the hosts a command contacted when it ends (not for
                                     keyserver or relay); nothing is stored. THURIN_SHOW_NETWORK=1
  --yes                              don't ask before sending
  --version  --help

Exit codes: 0 ok · 1 a check failed · 2 usage · 3 chain or network error
${dim(`Contract ${REGISTRY_ADDRESS} on Ethereum mainnet and Sepolia`)}
`,
}
const TOPIC_OF: Record<string, string> = {
  attest: 'claims', reattest: 'claims', 'update-key': 'claims', revoke: 'claims', claims: 'claims',
  'no-eth': 'no-eth', submit: 'no-eth', authorize: 'no-eth', cancel: 'no-eth',
  status: 'status', encrypt: 'encrypt', key: 'key', wallet: 'wallet', record: 'record', ens: 'ens', keyserver: 'keyserver', relay: 'relay', options: 'options',
}
function topicHelp(name: string | undefined): string {
  const t = name ? TOPIC_OF[name] : undefined
  if (!t) return HELP
  return TOPICS[t] + (t === 'options' ? '' : `\n${dim('Options: thurin help options')}\n`)
}

async function main() {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    options: {
      json: { type: 'boolean' }, yes: { type: 'boolean', short: 'y' }, help: { type: 'boolean', short: 'h' }, version: { type: 'boolean', short: 'v' },
      network: { type: 'string', short: 'n' }, rpc: { type: 'string' }, account: { type: 'string', short: 'a' }, 'password-file': { type: 'string' },
      key: { type: 'string', short: 'k' }, calldata: { type: 'boolean' }, 'include-email': { type: 'boolean' }, import: { type: 'boolean' },
      from: { type: 'string' }, 'private-key': { type: 'boolean' },
      'no-key': { type: 'boolean' }, owner: { type: 'string' }, site: { type: 'string' },
      statement: { type: 'boolean' }, 'key-file': { type: 'string' }, 'statement-file': { type: 'string' },
      authorize: { type: 'boolean' }, deadline: { type: 'string' }, out: { type: 'string', short: 'o' },
      sign: { type: 'boolean' }, armor: { type: 'boolean' }, 'show-recipient': { type: 'boolean' },
      'drop-records': { type: 'boolean' }, reason: { type: 'string' }, compromised: { type: 'boolean' },
      signer: { type: 'string' }, 'sign-out': { type: 'string' }, signature: { type: 'string' }, 'signature-file': { type: 'string' },
      relay: { type: 'string' }, 'no-relay': { type: 'boolean' }, 'no-proofs': { type: 'boolean' }, 'show-network': { type: 'boolean' },
      budget: { type: 'string' }, port: { type: 'string' }, host: { type: 'string' }, 'cache-seconds': { type: 'string' }, file: { type: 'string' }, index: { type: 'string' }, url: { type: 'string' }, 'per-hour': { type: 'string' }, 'free-attests': { type: 'string' }, 'max-gas': { type: 'string' },
    },
  })
  const opts: Record<string, any> = { ...values, passwordFile: values['password-file'], includeEmail: values['include-email'], privateKey: values['private-key'], noKey: values['no-key'], noRelay: values['no-relay'], noProofs: values['no-proofs'], dropRecords: values['drop-records'], perHour: values['per-hour'], freeAttests: values['free-attests'], maxGas: values['max-gas'], cacheSeconds: values['cache-seconds'], signOut: values['sign-out'], showRecipient: values['show-recipient'], signatureFile: values['signature-file'], keyFile: values['key-file'], statementFile: values['statement-file'] }
  setJson(!!opts.json)
  if (opts.version) { process.stdout.write(version + '\n'); return }
  const [cmd, ...rest] = positionals
  if (cmd === 'help') { process.stdout.write(topicHelp(rest[0])); return }
  if (opts.help) { process.stdout.write(topicHelp(cmd)); return }
  if (!cmd) { process.stdout.write(HELP); process.exitCode = EXIT.USAGE; return }  // bare `thurin` is a usage error; `--help` is not
  // Servers never finish, so there'd be no moment to print.
  if ((values['show-network'] || process.env.THURIN_SHOW_NETWORK === '1') && cmd !== 'keyserver' && cmd !== 'relay') {
    watchNetwork([opts.relay, readConfig().relay]); watching = true
  }

  switch (cmd) {
    case 'status': return status(rest, opts)
    case 'key': return key(rest, opts)
    case 'wallet': return wallet(rest, opts)
    case 'attest': return attest(rest, opts)
    case 'update-key': return updateKey(rest, opts)
    case 'reattest': return reattest(rest, opts)
    case 'revoke': return revoke(rest, opts)
    case 'cancel': return cancel(rest, opts)
    case 'submit': return submit(rest, opts)
    case 'authorize': if (rest[0] === 'finish') return finishAuthorization(rest.slice(1), opts); throw new CliError('Usage: thurin authorize finish <sign-out.json> --signature 0x…', EXIT.USAGE)
    case 'relay': return relay(rest, opts)
    case 'keyserver': return keyserver(rest, opts)
    case 'record': return record(rest, opts)
    case 'ens': return ens(rest, opts)
    case 'encrypt': return encrypt(rest, opts)
    default: throw new CliError(`Unknown command "${cmd}". Try: thurin help`, EXIT.USAGE)
  }
}

let watching = false

main().then(() => { if (watching) printNetwork(opts_json()) }).catch((err) => {
  // node:util parseArgs throws ERR_PARSE_ARGS_* for an unknown or malformed flag: a usage error.
  const code = err instanceof CliError ? err.code : String(err?.code).startsWith('ERR_PARSE_ARGS') ? EXIT.USAGE : EXIT.FAILED
  const message = err?.code === 'ERR_PARSE_ARGS_UNKNOWN_OPTION' ? `${err.message.split('. ')[0]}. Try: thurin help` : err.message
  if (opts_json()) process.stdout.write(JSON.stringify({ error: message, code }) + '\n')
  else process.stderr.write(`thurin: ${message}\n`)
  if (watching) printNetwork(opts_json())
  process.exit(code)
})

function opts_json() { return process.argv.includes('--json') }
