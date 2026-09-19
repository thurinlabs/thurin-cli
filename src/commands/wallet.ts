import { readFileSync } from 'node:fs'
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts'
import { generateMnemonic, mnemonicToAccount } from 'viem/accounts'
import { english } from 'viem/accounts'
import { bytesToHex } from '@noble/hashes/utils'
import { encryptKeystore, decryptKeystore, saveKeystore, listKeystores, keystorePath, parseMnemonicOrKey, type KeystoreV3 } from '../lib/keystore.js'
import { readConfig, writeConfig } from '../lib/config.js'
import { prompt } from '../lib/prompt.js'
import { out, ok, dim, bold, label, warn, CliError, EXIT } from '../lib/output.js'

/** Not a wallet: create, import, list, export. No balances, no transfers. */
export async function wallet(args: string[], opts: Record<string, any>) {
  switch (args[0]) {
    case 'create': return create(args.slice(1), opts)
    case 'import': return importWallet(args.slice(1), opts)
    case 'list': return list()
    case 'export': return exportWallet(args.slice(1), opts)
    case 'default': return setDefault(args.slice(1))
    default: throw new CliError('Usage: thurin wallet <create|import|list|export|default> …', EXIT.USAGE)
  }
}

async function password(opts: Record<string, any>, confirmIt: boolean) {
  if (opts.passwordFile) return readFileSync(opts.passwordFile, 'utf8').replace(/\r?\n$/, '')
  const p = await prompt('Keystore password: ', true)
  if (!p) throw new CliError('Empty password', EXIT.USAGE)
  if (confirmIt && (await prompt('Again: ', true)) !== p) throw new CliError('Passwords differ', EXIT.USAGE)
  return p
}

async function create(args: string[], opts: Record<string, any>) {
  const name = args[0]
  if (!name) throw new CliError('Usage: thurin wallet create <name>  — a fresh identity address (never needs to hold ETH if someone else submits)', EXIT.USAGE)
  const mnemonic = generateMnemonic(english)
  const acct = mnemonicToAccount(mnemonic)
  const pk = `0x${bytesToHex(acct.getHdKey().privateKey!)}` as `0x${string}`
  const pw = await password(opts, true)
  const path = saveKeystore(name, encryptKeystore(pk, pw))
  const cfg = readConfig(); if (!cfg.account) { cfg.account = name; writeConfig(cfg) }
  out({ name, address: acct.address, path, mnemonic }, () =>
    `${ok('Created')} ${bold(acct.address)}  ${dim(path)}\n\n${label('recovery')}${mnemonic}\n${warnLine()}\n${label('next')}thurin attest --account ${name}`)
}

function warnLine() { return dim('Write those 12 words down, offline. They are shown once and the CLI does not keep them.') }

async function importWallet(args: string[], opts: Record<string, any>) {
  const name = args[0]
  if (!name) throw new CliError('Usage: thurin wallet import <name> [--from <keystore.json>]  (else you are asked for a private key or mnemonic)', EXIT.USAGE)
  let pk: `0x${string}`
  if (opts.from) {
    const ks = JSON.parse(readFileSync(opts.from, 'utf8')) as KeystoreV3
    pk = decryptKeystore(ks, await prompt(`Password for ${opts.from}: `, true))
  } else {
    pk = parseMnemonicOrKey(await prompt('Private key or mnemonic: ', true)).privateKey
  }
  const acct = privateKeyToAccount(pk)
  const pw = await password(opts, true)
  const path = saveKeystore(name, encryptKeystore(pk, pw))
  out({ name, address: acct.address, path }, () => `${ok('Imported')} ${bold(acct.address)}  ${dim(path)}`)
}

function list() {
  const ks = listKeystores(); const def = readConfig().account
  out(ks.map(k => ({ ...k, isDefault: k.name === def })), () => ks.length
    ? ks.map(k => `${k.name === def ? ok('*') : ' '} ${k.name.padEnd(16)} ${k.address}`).join('\n')
    : dim('No keystores. `thurin wallet create <name>` or `thurin wallet import <name>`.'))
}

async function exportWallet(args: string[], opts: Record<string, any>) {
  const name = args[0] || readConfig().account
  if (!name) throw new CliError('Usage: thurin wallet export <name>', EXIT.USAGE)
  const ks = JSON.parse(readFileSync(keystorePath(name), 'utf8')) as KeystoreV3
  if (opts.privateKey) {
    warn('Printing a private key to the terminal.')
    process.stdout.write(decryptKeystore(ks, await prompt(`Password for ${name}: `, true)) + '\n')
  } else {
    process.stdout.write(JSON.stringify(ks) + '\n')   // the encrypted V3 file, importable anywhere
  }
}

function setDefault(args: string[]) {
  const name = args[0]
  if (!name || !listKeystores().some(k => k.name === name)) throw new CliError('Usage: thurin wallet default <name>  (thurin wallet list)', EXIT.USAGE)
  const cfg = readConfig(); cfg.account = name; writeConfig(cfg)
  out({ default: name }, () => `${ok('Default account')} ${name}`)
}
