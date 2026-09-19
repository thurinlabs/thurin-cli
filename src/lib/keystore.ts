import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { scrypt } from '@noble/hashes/scrypt'
import { keccak_256 } from '@noble/hashes/sha3'
import { ctr } from '@noble/ciphers/aes'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils'
import { privateKeyToAccount, mnemonicToAccount, type PrivateKeyAccount, type HDAccount } from 'viem/accounts'
import { validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english'
import { KEYSTORE_DIR, ensureKeystoreDir, readConfig } from './config.js'
import { CliError, EXIT } from './output.js'

/**
 * Web3 Secret Storage (V3) keystores: the same file format as geth, cast, and
 * every wallet that imports one. scrypt + AES-128-CTR + keccak MAC. ~80 lines,
 * so the CLI carries no wallet library.
 */
export interface KeystoreV3 {
  version: 3
  id: string
  address: string
  crypto: {
    cipher: 'aes-128-ctr'
    cipherparams: { iv: string }
    ciphertext: string
    kdf: 'scrypt'
    kdfparams: { dklen: number; n: number; p: number; r: number; salt: string }
    mac: string
  }
}

export function encryptKeystore(privateKey: `0x${string}`, password: string): KeystoreV3 {
  const salt = randomBytes(32), iv = randomBytes(16)
  const kdfparams = { dklen: 32, n: 1 << 17, r: 8, p: 1, salt: bytesToHex(salt) }
  const dk = scrypt(new TextEncoder().encode(password), salt, { N: kdfparams.n, r: kdfparams.r, p: kdfparams.p, dkLen: kdfparams.dklen })
  const pk = hexToBytes(privateKey.slice(2))
  const ciphertext = ctr(dk.slice(0, 16), iv).encrypt(pk)
  const mac = keccak_256(new Uint8Array([...dk.slice(16, 32), ...ciphertext]))
  const address = privateKeyToAccount(privateKey).address.slice(2).toLowerCase()
  return {
    version: 3, id: crypto.randomUUID(), address,
    crypto: { cipher: 'aes-128-ctr', cipherparams: { iv: bytesToHex(iv) }, ciphertext: bytesToHex(ciphertext), kdf: 'scrypt', kdfparams, mac: bytesToHex(mac) },
  }
}

export function decryptKeystore(ks: KeystoreV3, password: string): `0x${string}` {
  if (ks.version !== 3 || ks.crypto.kdf !== 'scrypt' || ks.crypto.cipher !== 'aes-128-ctr') throw new CliError('Unsupported keystore (need V3, scrypt, aes-128-ctr)', EXIT.FAILED)
  const p = ks.crypto.kdfparams
  const dk = scrypt(new TextEncoder().encode(password), hexToBytes(p.salt), { N: p.n, r: p.r, p: p.p, dkLen: p.dklen })
  const ciphertext = hexToBytes(ks.crypto.ciphertext)
  const mac = bytesToHex(keccak_256(new Uint8Array([...dk.slice(16, 32), ...ciphertext])))
  if (mac !== ks.crypto.mac.toLowerCase()) throw new CliError('Wrong password', EXIT.FAILED)
  return `0x${bytesToHex(ctr(dk.slice(0, 16), hexToBytes(ks.crypto.cipherparams.iv)).decrypt(ciphertext))}`
}

export function keystorePath(name: string) { return join(KEYSTORE_DIR, `${name}.json`) }

export function listKeystores(): { name: string; address: string }[] {
  if (!existsSync(KEYSTORE_DIR)) return []
  return readdirSync(KEYSTORE_DIR).filter(f => f.endsWith('.json')).map(f => {
    try { const ks = JSON.parse(readFileSync(join(KEYSTORE_DIR, f), 'utf8')); return { name: f.replace(/\.json$/, ''), address: `0x${ks.address}` } }
    catch { return { name: f.replace(/\.json$/, ''), address: '(unreadable)' } }
  })
}

export function saveKeystore(name: string, ks: KeystoreV3) {
  ensureKeystoreDir()
  const path = keystorePath(name)
  if (existsSync(path)) throw new CliError(`Keystore "${name}" already exists at ${path}`, EXIT.USAGE)
  writeFileSync(path, JSON.stringify(ks, null, 2) + '\n', { mode: 0o600 })
  return path
}

export function parseMnemonicOrKey(secret: string): { kind: 'mnemonic' | 'privateKey'; account: HDAccount | PrivateKeyAccount; privateKey: `0x${string}` } {
  const s = secret.trim()
  if (/^(0x)?[0-9a-fA-F]{64}$/.test(s)) {
    const pk = (s.startsWith('0x') ? s : `0x${s}`) as `0x${string}`
    return { kind: 'privateKey', account: privateKeyToAccount(pk), privateKey: pk }
  }
  if (validateMnemonic(s, wordlist)) {
    const acct = mnemonicToAccount(s)
    const pk = `0x${bytesToHex(acct.getHdKey().privateKey!)}` as `0x${string}`
    return { kind: 'mnemonic', account: acct, privateKey: pk }
  }
  throw new CliError('Not a private key (64 hex) or a BIP-39 mnemonic', EXIT.USAGE)
}

/**
 * The account that pays: --account <keystore name>, else THURIN_PRIVATE_KEY, else the
 * configured default keystore. Prompts for the keystore password.
 */
export async function loadAccount(opts: { account?: string; passwordFile?: string }, prompt: (q: string) => Promise<string>): Promise<PrivateKeyAccount> {
  if (!opts.account && process.env.THURIN_PRIVATE_KEY) return privateKeyToAccount(process.env.THURIN_PRIVATE_KEY as `0x${string}`)
  const name = opts.account || readConfig().account
  if (!name) throw new CliError('No account: pass --account <name>, set THURIN_PRIVATE_KEY, or `thurin wallet create`', EXIT.USAGE)
  const path = existsSync(name) ? name : keystorePath(name)   // a path to any V3 file works too (e.g. ~/.foundry/keystores/x)
  if (!existsSync(path)) throw new CliError(`No keystore "${name}" (thurin wallet list)`, EXIT.USAGE)
  const ks = JSON.parse(readFileSync(path, 'utf8')) as KeystoreV3
  const password = opts.passwordFile ? readFileSync(opts.passwordFile, 'utf8').replace(/\r?\n$/, '') : await prompt(`Password for ${name}: `)
  return privateKeyToAccount(decryptKeystore(ks, password))
}
