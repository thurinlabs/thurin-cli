import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { stringToHex, type Address, type Hex } from 'viem'
import { REGISTRY_ABI, recordKind } from '@thurinlabs/identity-kit/core'
import { chainCtx, claimsOf, resolveOwners, detectLookup, readRegistry, type ChainCtx } from '../lib/chain.js'
import { encodeRecord, decodeRecord, parsePointer, addPointer, renderPointer, kindName, KNOWN_KINDS } from '../lib/records.js'
import { send, ownerFor, pickIndex, handoff, authorize } from './attest.js'
import { out, info, ok, bad, dim, bold, label, isJson, CliError, EXIT } from '../lib/output.js'

export async function record(args: string[], opts: Record<string, any>) {
  switch (args[0]) {
    case 'get': return recordGet(args.slice(1), opts)
    case 'set': return recordSet(args.slice(1), opts)
    case 'clear': return recordSet([args[1], ''], opts)
    case 'add-release': return addRelease(args.slice(1), opts)
    default: throw new CliError('Usage: thurin record <get <identity> <kind> | set <kind> <value|--file f> | clear <kind> | add-release <name> <SHA256SUMS> [--url u]> [--index n]', EXIT.USAGE)
  }
}

async function readRecord(ctx: ChainCtx, owner: Address, index: number, kind: string): Promise<string> {
  const hex = await readRegistry<Hex>(ctx, 'record', [owner, BigInt(index), recordKind(kind)])
  return decodeRecord(hex)
}

/** thurin record get <identity> <kind>: anyone can read; prints the value (pretty for known kinds). */
async function recordGet(args: string[], opts: Record<string, any>) {
  if (!args[0] || !args[1]) throw new CliError('Usage: thurin record get <ens|0x|fingerprint> <kind>  (kinds: ' + KNOWN_KINDS.join(', ') + ')', EXIT.USAGE)
  const ctx = chainCtx(opts)
  const kind = kindName(args[1])
  const { owners } = await resolveOwners(ctx, detectLookup(args[0]))
  const results: { owner: Address; index: number; fingerprint: string; value: string }[] = []
  for (const owner of owners) {
    const claims = (await claimsOf(ctx, owner)).filter(c => !c.revokedAt)
    for (const c of claims) {
      const value = await readRecord(ctx, owner, c.index, kind)
      if (value) results.push({ owner, index: c.index, fingerprint: c.fingerprint, value })
    }
  }
  if (!results.length) throw new CliError(`No ${kind} record on any active claim of ${args[0]}`, EXIT.FAILED)
  out({ kind, records: results }, () => results.map(r => {
    const head = `${label('owner')}${r.owner}  claim #${r.index}  ${dim(r.fingerprint)}\n${label('kind')}${kind}`
    if (kind === 'thurin.pointer') { try { return `${head}\n${renderPointer(parsePointer(r.value))}` } catch { /* fall through */ } }
    return `${head}\n${r.value}`
  }).join('\n\n'))
}

/** thurin record set <kind> <value|--file f> [--index n]: the owner writes; '' clears. */
async function recordSet(args: string[], opts: Record<string, any>) {
  if (!args[0]) throw new CliError('Usage: thurin record set <kind> <value|--file f> [--index n]', EXIT.USAGE)
  const kind = kindName(args[0])
  const value = opts.file ? readFileSync(opts.file, 'utf8') : (args[1] ?? '')
  const ctx = chainCtx(opts)
  const owner = await ownerFor(ctx, opts)
  const claims = await claimsOf(ctx, owner)
  const idx = opts.index !== undefined ? Number(opts.index) : pickIndex(undefined, claims)
  if (!claims[idx]) throw new CliError(`No claim #${idx}`, EXIT.USAGE)
  let hex: Hex
  try { hex = value ? encodeRecord(value) : '0x' } catch (e: any) { throw new CliError(e.message, EXIT.FAILED) }
  if (!isJson()) process.stderr.write(`${label('claim')}#${idx} ${claims[idx].fingerprint}\n${label('kind')}${kind}\n${label('value')}${value ? `${new TextEncoder().encode(value).length} bytes` : dim('(clear)')}\n`)
  const o = { ...opts, _record: { kind, value } }
  if (opts.authorize) return authorize(ctx, o, 'set-record', owner, claims[idx].fingerprint, null, idx)
  if (opts.noKey) return handoff(ctx, o, 'set-record', owner, claims[idx].fingerprint, null, idx)
  const r = await send(ctx, opts, 'setRecord', [BigInt(idx), recordKind(kind), hex], value ? `Set ${kind} on claim #${idx}` : `Clear ${kind} on claim #${idx}`)
  out({ ...r, owner, index: idx, kind, bytes: value.length }, () => `${ok(value ? 'Set' : 'Cleared')} ${kind} on claim #${idx}\n${label('tx')}${ctx.explorerUrl ? `${ctx.explorerUrl}/tx/${r.hash}` : r.hash}`)
}

/**
 * thurin record add-release <name> <SHA256SUMS> [--url u] [--index n]: hash the checksum file,
 * append it to the thurin.pointer record (newest first), and set it. What the chain then says:
 * this identity put out <name>, whose checksum file hashes to this.
 */
async function addRelease(args: string[], opts: Record<string, any>) {
  if (!args[0] || !args[1]) throw new CliError('Usage: thurin record add-release <name> <path/to/SHA256SUMS> [--url <release url>] [--index n]', EXIT.USAGE)
  const name = args[0]
  const sha256 = createHash('sha256').update(readFileSync(args[1])).digest('hex')
  const ctx = chainCtx(opts)
  const owner = await ownerFor(ctx, opts)
  const claims = await claimsOf(ctx, owner)
  const idx = opts.index !== undefined ? Number(opts.index) : pickIndex(undefined, claims)
  if (!claims[idx]) throw new CliError(`No claim #${idx}`, EXIT.USAGE)
  const existingText = await readRecord(ctx, owner, idx, 'thurin.pointer')
  let existing = null
  if (existingText) { try { existing = parsePointer(existingText) } catch { throw new CliError('The existing thurin.pointer record is not v1; edit it with record set', EXIT.FAILED) } }
  const { record: rec, dropped } = addPointer(existing, { name, sha256, date: new Date().toISOString().slice(0, 10), ...(opts.url ? { url: opts.url } : {}) })
  const text = JSON.stringify(rec)
  if (!isJson()) {
    process.stderr.write(`${label('claim')}#${idx} ${claims[idx].fingerprint}\n${label('release')}${name}\n${label('sha256')}${sha256}  ${dim(`(of ${args[1]})`)}\n${label('record')}${rec.releases.length} release(s), ${new TextEncoder().encode(text).length} bytes\n`)
    if (dropped.length) process.stderr.write(`${label('dropped')}${dropped.map(d => d.name).join(', ')} ${dim('(record full; they stay in chain history)')}\n`)
  }
  const o = { ...opts, _record: { kind: 'thurin.pointer', value: text } }
  if (opts.authorize) return authorize(ctx, o, 'set-record', owner, claims[idx].fingerprint, null, idx)
  if (opts.noKey) return handoff(ctx, o, 'set-record', owner, claims[idx].fingerprint, null, idx)
  const r = await send(ctx, opts, 'setRecord', [BigInt(idx), recordKind('thurin.pointer'), stringToHex(text)], `Name release "${name}" on claim #${idx}`)
  out({ ...r, owner, index: idx, name, sha256, releases: rec.releases.length }, () => `${ok('Named')} ${bold(name)} on-chain\n${label('tx')}${ctx.explorerUrl ? `${ctx.explorerUrl}/tx/${r.hash}` : r.hash}\n${label('check')}thurin record get ${owner} thurin.pointer`)
}
