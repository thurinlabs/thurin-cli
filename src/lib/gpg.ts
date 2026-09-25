import { spawn } from 'node:child_process'
import { CliError, EXIT } from './output.js'

/**
 * Everything PGP goes through the user's gpg. The CLI never reads secret key
 * material; passphrases are gpg's business (pinentry).
 */
export function gpg(args: string[], input?: string): Promise<string> {
  return gpgBytes(args, input).then(b => b.toString('utf8'))
}

/** gpg with binary output (a raw signature or key). */
export function gpgBytes(args: string[], input?: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const child = spawn('gpg', ['--batch', '--no-tty', ...args], { stdio: ['pipe', 'pipe', 'pipe'] })
    const out: Buffer[] = []
    let err = ''
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (d: Buffer) => { out.push(d) })
    child.stderr.on('data', d => { err += d })
    child.on('error', (e: any) => {
      if (e.code === 'ENOENT') reject(new CliError('gpg not found. Install GnuPG 2.2 or newer.', EXIT.FAILED))
      else reject(new CliError(`gpg failed to start: ${e.message}`, EXIT.FAILED))
    })
    child.on('close', code => {
      if (code === 0) resolve(Buffer.concat(out))
      else reject(new CliError(`gpg ${args.find(a => a.startsWith('--')) ?? ''} failed: ${err.trim().split('\n').slice(-3).join(' ')}`, EXIT.FAILED))
    })
    if (input !== undefined) child.stdin.write(input)
    child.stdin.end()
  })
}

export interface KeyListing {
  fingerprint: string
  algorithm: string
  created: string
  expires: string | null
  userIDs: string[]
  hasSecret: boolean
  hasEncryptionSubkey: boolean
  publishedName: string | null   // first user ID without an email
}

/** Keys in the keyring, secret ones marked. Parses gpg's colon format. */
export async function listKeys(onlySecret = false): Promise<KeyListing[]> {
  const pub = await gpg(['--with-colons', '--with-fingerprint', '--list-keys'])
  const sec = await gpg(['--with-colons', '--with-fingerprint', '--list-secret-keys']).catch(() => '')
  const secretFps = new Set([...sec.matchAll(/^fpr:.*?:([0-9A-F]{40,64}):/gm)].map(m => m[1]))
  const keys: KeyListing[] = []
  let cur: KeyListing | null = null
  let awaitingPrimaryFpr = false
  for (const line of pub.split('\n')) {
    const f = line.split(':')
    if (f[0] === 'pub') {
      cur = { fingerprint: '', algorithm: algoName(f[3], f[16]), created: isoDate(f[5]), expires: f[6] ? isoDate(f[6]) : null, userIDs: [], hasSecret: false, hasEncryptionSubkey: false, publishedName: null }
      keys.push(cur); awaitingPrimaryFpr = true
    } else if (f[0] === 'fpr' && cur && awaitingPrimaryFpr) {
      cur.fingerprint = f[9]; cur.hasSecret = secretFps.has(f[9]); awaitingPrimaryFpr = false
    } else if (f[0] === 'uid' && cur && f[1] !== 'r') {
      cur.userIDs.push(f[9])
      if (!cur.publishedName && !f[9].includes('@')) cur.publishedName = f[9]
    } else if (f[0] === 'sub' && cur && f[11]?.includes('e') && f[1] !== 'r' && f[1] !== 'e') {
      cur.hasEncryptionSubkey = true
    }
  }
  return onlySecret ? keys.filter(k => k.hasSecret) : keys
}

export async function findKey(fprOrName: string): Promise<KeyListing> {
  const keys = await listKeys(true)
  const q = fprOrName.replace(/\s+/g, '').toUpperCase()
  const hit = keys.find(k => k.fingerprint === q || k.fingerprint.endsWith(q) || k.userIDs.some(u => u.toLowerCase().includes(fprOrName.toLowerCase())))
  if (!hit) throw new CliError(`No secret key matching "${fprOrName}" in your gpg keyring (thurin key list)`, EXIT.FAILED)
  return hit
}

/** The exact statement Thurin verifies. Must match the app and the kit. */
export function attestStatement(address: string) {
  return `I control the Ethereum address: ${address.toLowerCase()}`
}

/**
 * Which key signs for a given primary. If the primary itself can sign (an [SC]
 * key, like most YubiKey-era keys) we pin it with "!": letting gpg pick "the
 * signing subkey" chose a subkey sitting in a card's Authentication slot and
 * produced bad signatures (2026-09-14). If the primary is certify-only (the shape
 * `thurin key create` makes, and the company key) we pin its live signing subkey.
 */
export async function signingKeyFor(fingerprint: string): Promise<string> {
  const out = await gpg(['--with-colons', '--with-fingerprint', '--with-fingerprint', '--list-secret-keys', fingerprint])
  const lines = out.split('\n').map(l => l.split(':'))
  let inPrimary = false, primaryCanSign = false, pendingSub = false, subValid = false
  const subs: string[] = []
  for (const f of lines) {
    if (f[0] === 'sec') { inPrimary = true; primaryCanSign = (f[11] || '').includes('s'); pendingSub = false }
    else if (f[0] === 'fpr' && inPrimary) { inPrimary = false }
    else if (f[0] === 'ssb') { pendingSub = (f[11] || '').includes('s') && !['r', 'e', 'i', 'd'].includes(f[1]); subValid = pendingSub }
    else if (f[0] === 'fpr' && pendingSub) { if (subValid) subs.push(f[9]); pendingSub = false }
  }
  if (primaryCanSign) return `${fingerprint}!`
  if (subs.length) return `${subs[subs.length - 1]}!`   // newest live signing subkey
  throw new CliError(`Key ${fingerprint} has no usable signing key (primary is certify-only and no signing subkey)`, EXIT.FAILED)
}

/** A raw detached text-mode signature over exactly `text` (no trailing line break), as a claim stores it. */
export async function detachSign(fingerprint: string, text: string): Promise<Uint8Array> {
  const signer = await signingKeyFor(fingerprint)
  return new Uint8Array(await gpgBytes(['--detach-sign', '--textmode', '-u', signer], text))
}

export async function exportMinimal(fingerprint: string): Promise<string> {
  return gpg(['--export-options', 'export-minimal,no-export-attributes', '--armor', '--export', fingerprint])
}

export async function quickGenKey(name: string, expires: string): Promise<string> {
  // Certify+sign primary, encryption subkey, no email unless the user typed one.
  await gpg(['--quick-gen-key', name, 'ed25519', 'cert', expires])
  const keys = await listKeys(true)
  const created = keys.filter(k => k.userIDs.includes(name)).sort((a, b) => b.created.localeCompare(a.created))[0]
  if (!created) throw new CliError('Key was created but could not be found in the keyring', EXIT.FAILED)
  await gpg(['--quick-add-key', created.fingerprint, 'ed25519', 'sign', expires])
  await gpg(['--quick-add-key', created.fingerprint, 'cv25519', 'encr', expires])
  return created.fingerprint
}

export async function quickAddUid(fingerprint: string, name: string) {
  await gpg(['--quick-add-uid', fingerprint, name])
}

export async function importKey(armored: string): Promise<string> {
  return gpg(['--import'], armored)
}

function algoName(algo: string, curve: string) {
  const c = (curve || '').toLowerCase()
  if (c.startsWith('ed25519')) return 'Ed25519'
  if (c.startsWith('cv25519') || c.startsWith('curve25519')) return 'Cv25519'
  if (c) return curve
  return ({ '1': 'RSA', '17': 'DSA', '18': 'ECDH', '19': 'ECDSA', '22': 'EdDSA' } as Record<string, string>)[algo] || `algo ${algo}`
}
function isoDate(unix: string) { return new Date(Number(unix) * 1000).toISOString().slice(0, 10) }
