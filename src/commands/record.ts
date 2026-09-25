import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { type Address } from 'viem'
import { chainCtx, claimsOf, resolveOwners, detectLookup, readRegistry, type ChainCtx } from '../lib/chain.js'
import { parseReleases, addRelease, renderReleases, checkKindName, checkRecordValue, KNOWN_KINDS } from '@thurinlabs/identity-kit/core'
import { send, ownerFor, pickIndex, handoff, authorize } from './attest.js'
import { out, info, ok, bad, dim, bold, label, isJson, CliError, EXIT } from '../lib/output.js'

export async function record(args: string[], opts: Record<string, any>) {
  switch (args[0]) {
    case 'get': return recordGet(args.slice(1), opts)
    case 'set': return recordSet(args.slice(1), opts)
    case 'clear': return recordSet([args[1], ''], opts)
    case 'add-release': return addReleaseCommand(args.slice(1), opts)
    default: throw new CliError('Usage: thurin record get|set|clear|add-release …  (thurin help record)', EXIT.USAGE)
  }
}

/** A claim's records from `recordsOf`, as [name, value] pairs in the order they were first set. */
async function recordsOnClaim(ctx: ChainCtx, owner: Address, index: number): Promise<[string, string][]> {
  const [names, values] = await readRegistry<[string[], string[]]>(ctx, 'recordsOf', [owner, BigInt(index)])
  return names.map((n, i) => [n, values[i]] as [string, string])
}

/** thurin record get <identity> [kind]: anyone can read; one kind, or every record on each active claim. */
async function recordGet(args: string[], opts: Record<string, any>) {
  if (!args[0]) throw new CliError('Usage: thurin record get <ens|0x|fingerprint|keyid> [name]  (Thurin.id names: ' + KNOWN_KINDS.join(', ') + ')', EXIT.USAGE)
  const ctx = chainCtx(opts)
  let kind: string | null = null
  if (args[1]) { try { kind = checkKindName(args[1]) } catch (e: any) { throw new CliError(e.message, EXIT.USAGE) } }
  const { owners } = await resolveOwners(ctx, detectLookup(args[0]))
  const results: { owner: Address; index: number; fingerprint: string; kind: string; value: string }[] = []
  for (const owner of owners) {
    const claims = (await claimsOf(ctx, owner)).filter(c => !c.revokedAt)
    for (const c of claims) {
      for (const [k, value] of await recordsOnClaim(ctx, owner, c.index)) {
        if (value && (!kind || k === kind)) results.push({ owner, index: c.index, fingerprint: c.fingerprint, kind: k, value })
      }
    }
  }
  if (!results.length) throw new CliError(`No ${kind ?? ''} record${kind ? '' : 's'} on any active claim of ${args[0]}`.replace('  ', ' '), EXIT.FAILED)
  // One record asked for by name: its value exactly as stored on stdout (pipe it: … canary | gpg --verify),
  // where it's from on stderr.
  if (kind && results.length === 1 && !isJson()) {
    const r = results[0]
    process.stderr.write(dim(`${r.owner}  claim #${r.index}  ${r.fingerprint}  ${r.kind}`) + '\n')
    // The release list reads as a list at a terminal; piped, it stays the JSON as stored.
    if (r.kind === 'thurin.releases' && process.stdout.isTTY) { try { process.stdout.write(renderReleases(parseReleases(r.value)) + '\n'); return } catch { /* shown as stored */ } }
    process.stdout.write(r.value.endsWith('\n') ? r.value : r.value + '\n')
    return
  }
  // One header per claim, then its records: the name, and the value beside it (or indented below it
  // when it runs over one line, like a clearsigned canary or the release list).
  const claims = new Map<string, typeof results>()
  for (const r of results) { const k = `${r.owner} ${r.index}`; claims.set(k, [...(claims.get(k) ?? []), r]) }
  out({ name: kind, records: results.map(({ kind: name, ...r }) => ({ name, ...r })) }, () => [...claims.values()].map(rs => {
    const width = Math.max(...rs.map(r => r.kind.length))
    const lines = rs.map(r => {
      let text = r.value
      if (r.kind === 'thurin.releases') { try { text = renderReleases(parseReleases(r.value)) } catch { /* shown as stored */ } }
      text = text.replace(/\s+$/, '')
      return text.includes('\n')
        ? `  ${bold(r.kind)}\n${text.split('\n').map(l => (l ? `      ${l}` : '')).join('\n')}`
        : `  ${bold(r.kind.padEnd(width))}   ${text}`
    })
    return `${rs[0].owner}  claim #${rs[0].index}  ${dim(rs[0].fingerprint)}\n${lines.join('\n')}`
  }).join('\n\n'))
}

/** thurin record set <kind> <value|--file f> [--index n]: the owner writes; '' clears. */
async function recordSet(args: string[], opts: Record<string, any>) {
  if (!args[0]) throw new CliError('Usage: thurin record set <name> <value | --file f> [--index n]', EXIT.USAGE)
  let kind: string, value: string
  try {
    kind = checkKindName(args[0])
    value = checkRecordValue(opts.file ? readFileSync(opts.file, 'utf8') : (args[1] ?? ''))
  } catch (e: any) { throw new CliError(e.message, EXIT.USAGE) }
  const ctx = chainCtx(opts)
  const owner = await ownerFor(ctx, opts)
  const claims = await claimsOf(ctx, owner)
  const idx = pickIndex(opts.index, claims)
  if (!claims[idx]) throw new CliError(`No claim #${idx}`, EXIT.USAGE)
  if (!isJson()) process.stderr.write(`${label('claim')}#${idx} ${claims[idx].fingerprint}\n${label('name')}${kind}\n${label('value')}${value ? `${new TextEncoder().encode(value).length} bytes` : dim('(clear)')}\n`)
  const o = { ...opts, _record: { kind, value } }
  if (opts.authorize) return authorize(ctx, o, 'set-record', owner, claims[idx].fingerprint, null, idx)
  if (opts.noKey) return handoff(ctx, o, 'set-record', owner, claims[idx].fingerprint, null, idx)
  const r = await send(ctx, opts, 'setRecord', [BigInt(idx), kind, value], value ? `Set ${kind} on claim #${idx}` : `Clear ${kind} on claim #${idx}`)
  out({ ...r, owner, index: idx, name: kind, bytes: value.length }, () => `${ok(value ? 'Set' : 'Cleared')} ${kind} on claim #${idx}\n${label('tx')}${ctx.explorerUrl ? `${ctx.explorerUrl}/tx/${r.hash}` : r.hash}`)
}

/**
 * thurin record add-release <name> <SHA256SUMS> [--url u] [--index n]: hash the checksum file,
 * append it to the thurin.releases record (newest first), and set it. What the chain then says:
 * this identity put out <name>, whose checksum file hashes to this.
 */
async function addReleaseCommand(args: string[], opts: Record<string, any>) {
  if (!args[0] || !args[1]) throw new CliError('Usage: thurin record add-release <name> <path/to/SHA256SUMS> [--url <release url>] [--index n]', EXIT.USAGE)
  const name = args[0]
  const sha256 = createHash('sha256').update(readFileSync(args[1])).digest('hex')
  const ctx = chainCtx(opts)
  const owner = await ownerFor(ctx, opts)
  const claims = await claimsOf(ctx, owner)
  const idx = pickIndex(opts.index, claims)
  if (!claims[idx]) throw new CliError(`No claim #${idx}`, EXIT.USAGE)
  const existingText = await readRegistry<string>(ctx, 'recordText', [owner, BigInt(idx), 'thurin.releases'])
  let existing = null
  if (existingText) { try { existing = parseReleases(existingText) } catch { throw new CliError("The thurin.releases record on this claim can't be read. Replace it: thurin record set thurin.releases --file f", EXIT.FAILED) } }
  const { record: rec, dropped } = addRelease(existing, { name, sha256, date: new Date().toISOString().slice(0, 10), ...(opts.url ? { url: opts.url } : {}) })
  const text = JSON.stringify(rec)
  if (!isJson()) {
    process.stderr.write(`${label('claim')}#${idx} ${claims[idx].fingerprint}\n${label('release')}${name}\n${label('sha256')}${sha256}  ${dim(`(of ${args[1]})`)}\n${label('record')}${rec.releases.length} release(s), ${new TextEncoder().encode(text).length} bytes\n`)
    if (dropped.length) process.stderr.write(`${label('dropped')}${dropped.map(d => d.name).join(', ')} ${dim('(record full; they stay in chain history)')}\n`)
  }
  const o = { ...opts, _record: { kind: 'thurin.releases', value: text } }
  if (opts.authorize) return authorize(ctx, o, 'set-record', owner, claims[idx].fingerprint, null, idx)
  if (opts.noKey) return handoff(ctx, o, 'set-record', owner, claims[idx].fingerprint, null, idx)
  const r = await send(ctx, opts, 'setRecord', [BigInt(idx), 'thurin.releases', text], `Name release "${name}" on claim #${idx}`)
  out({ ...r, owner, index: idx, name, sha256, releases: rec.releases.length }, () => `${ok('Named')} ${bold(name)} on-chain\n${label('tx')}${ctx.explorerUrl ? `${ctx.explorerUrl}/tx/${r.hash}` : r.hash}\n${label('check')}thurin record get ${owner} thurin.releases`)
}
