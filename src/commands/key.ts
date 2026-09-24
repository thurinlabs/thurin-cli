import { listKeys, findKey, exportMinimal, quickGenKey, quickAddUid, importKey, type KeyListing } from '../lib/gpg.js'
import { parsePgpKey, identifyProof, hasEmailUserID } from '@thurinlabs/identity-kit/core'
import { chainCtx, claimsOf, detectLookup, resolveOwners } from '../lib/chain.js'
import { readConfig, writeConfig } from '../lib/config.js'
import { out, ok, bad, dim, bold, label, info, CliError, EXIT } from '../lib/output.js'

export async function key(args: string[], opts: Record<string, any>) {
  const sub = args[0]
  switch (sub) {
    case 'list': return keyList()
    case 'create': return keyCreate(args.slice(1), opts)
    case 'add-name': return keyAddName(args.slice(1))
    case 'export': return keyExport(args.slice(1))
    case 'fetch': return keyFetch(args.slice(1), opts)
    case 'default': return keyDefault(args.slice(1))
    default: throw new CliError('Usage: thurin key <list|create|add-name|export|fetch|default> …', EXIT.USAGE)
  }
}

async function keyList() {
  const keys = await listKeys(true)
  const def = readConfig().key
  const rows: (KeyListing & { proofs: number; isDefault: boolean })[] = []
  for (const k of keys) {
    const armored = await exportMinimal(k.fingerprint).catch(() => null)
    const info = armored ? await parsePgpKey(armored) : null
    const proofs = info ? info.notations.map(identifyProof).filter(Boolean).length : 0
    rows.push({ ...k, proofs, isDefault: k.fingerprint === def })
  }
  out(rows, () => rows.length ? rows.map(k =>
    `${k.isDefault ? ok('*') : ' '} ${bold(k.fingerprint)}  ${k.algorithm} · ${k.created}${k.expires ? ` → ${k.expires}` : ''}\n` +
    k.userIDs.map(u => `    ${u.includes('@') ? dim(u) : u}`).join('\n') + '\n' +
    `    ${k.publishedName ? ok('published name: ' + k.publishedName) : bad('no name without an email (thurin key add-name)')} · ${k.hasEncryptionSubkey ? 'encrypt ✓' : dim('no encryption subkey')} · proofs: ${k.proofs}`
  ).join('\n') : dim('No secret keys in your gpg keyring. `thurin key create` makes one.'))
}

async function keyCreate(args: string[], opts: Record<string, any>) {
  const name = opts.name || args[0]
  if (!name) throw new CliError('Usage: thurin key create <name> [--expires 2y]  (a name with no email, e.g. "Your Name")', EXIT.USAGE)
  const expires = opts.expires || '2y'
  info(`Creating an Ed25519 key "${name}" (certify + sign, Cv25519 encryption subkey, expires ${expires}). gpg will ask for a passphrase.`)
  const fpr = await quickGenKey(name, expires)
  const cfg = readConfig(); if (!cfg.key) { cfg.key = fpr; writeConfig(cfg) }
  out({ fingerprint: fpr, name, expires, default: cfg.key === fpr }, () =>
    `${ok('Created')} ${bold(fpr)}\n${label('name')}${name}\n${label('backup')}gpg --export-secret-keys --armor ${fpr} > ${name}-secret.asc   ${dim('(keep it offline; the CLI never reads it)')}\n${label('next')}thurin attest --key ${fpr}`)
}

async function keyAddName(args: string[]) {
  const [fprOrName, name] = args
  if (!fprOrName || !name) throw new CliError('Usage: thurin key add-name <fingerprint> <name>', EXIT.USAGE)
  if (name.includes('@')) throw new CliError('The published name must not contain an email address', EXIT.USAGE)
  const k = await findKey(fprOrName)
  await quickAddUid(k.fingerprint, name)
  out({ fingerprint: k.fingerprint, added: name }, () => `${ok('Added')} "${name}" to ${k.fingerprint}`)
}

async function keyExport(args: string[]) {
  const k = await findKey(args[0] || readConfig().key || '')
  const armored = await exportMinimal(k.fingerprint)
  process.stdout.write(armored)
}

async function keyFetch(args: string[], opts: Record<string, any>) {
  if (!args[0]) throw new CliError('Usage: thurin key fetch <ens|0x|fingerprint|keyid> [--import]', EXIT.USAGE)
  const ctx = chainCtx(opts)
  const { owners } = await resolveOwners(ctx, detectLookup(args[0]))
  for (const owner of owners) {
    const claims = await claimsOf(ctx, owner)
    const current = claims.find(c => !c.revokedAt && c.verification?.verified)
    if (!current?.pgpPublicKey) continue
    if (opts.import) { const r = await importKey(current.pgpPublicKey); info(r.trim().split('\n').pop() || ''); }
    else process.stdout.write(current.pgpPublicKey)
    return
  }
  throw new CliError('No verified active claim found for that identity', EXIT.FAILED)
}

async function keyDefault(args: string[]) {
  const k = await findKey(args[0] || '')
  const cfg = readConfig(); cfg.key = k.fingerprint; writeConfig(cfg)
  out({ default: k.fingerprint }, () => `${ok('Default key')} ${k.fingerprint}`)
}
