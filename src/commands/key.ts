import { listKeys, findKey, exportMinimal, importKey, MAKE_KEY_HINT, addNameHint, type KeyListing } from '../lib/gpg.js'
import { parsePgpKey, identifyProof, hasEmailUserID } from '@thurinlabs/identity-kit/core'
import { chainCtx, claimsOf, detectLookup, resolveOwners } from '../lib/chain.js'
import { readConfig, writeConfig } from '../lib/config.js'
import { out, ok, bad, dim, bold, info, CliError, EXIT } from '../lib/output.js'

export async function key(args: string[], opts: Record<string, any>) {
  const sub = args[0]
  switch (sub) {
    case 'list': return keyList()
    case 'create': throw new CliError(`thurin doesn't make keys; gpg does. ${MAKE_KEY_HINT}`, EXIT.USAGE)
    case 'add-name': throw new CliError(`Add a name with gpg: ${addNameHint(args[1] || '<fingerprint>')}`, EXIT.USAGE)
    case 'export': return keyExport(args.slice(1))
    case 'fetch': return keyFetch(args.slice(1), opts)
    case 'default': return keyDefault(args.slice(1))
    default: throw new CliError('Usage: thurin key <list|export|fetch|default> …', EXIT.USAGE)
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
    `    ${k.publishedName ? ok('published name: ' + k.publishedName) : bad(`no name without an email (${addNameHint(k.fingerprint)})`)} · ${k.hasEncryptionSubkey ? 'encryption subkey ✓' : dim('no encryption subkey')} · proofs: ${k.proofs}`
  ).join('\n') : dim(`No secret keys in your gpg keyring. ${MAKE_KEY_HINT}`))
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
  throw new CliError('No active, verified claim for that identity. See: thurin status <identity>', EXIT.FAILED)
}

async function keyDefault(args: string[]) {
  const k = await findKey(args[0] || '')
  const cfg = readConfig(); cfg.key = k.fingerprint; writeConfig(cfg)
  out({ default: k.fingerprint }, () => `${ok('Default key')} ${k.fingerprint}`)
}
