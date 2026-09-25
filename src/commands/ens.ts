import { encodeFunctionData, getAddress, isAddress, type Address } from 'viem'
import { normalize } from 'viem/ens'
import { chainCtx, claimsOf, rpcHost, type ChainCtx, type Claim } from '../lib/chain.js'
import { ENS_HINT_KEY, ensHintFor, ensHintWrite, type EnsHint } from '@thurinlabs/identity-kit/core'
import { send } from './attest.js'
import { out, info, ok, bad, dim, bold, label, isJson, CliError, EXIT } from '../lib/output.js'

/**
 * thurin ens check <name>: does the name's id.thurin record point at the key its address claims?
 * thurin ens link <name> [--key <fpr>] [--calldata]: set it — from the keystore, or print the
 * transaction for the wallet that manages the name.
 */
export async function ens(args: string[], opts: Record<string, any>) {
  switch (args[0]) {
    case 'check': return ensCheck(args.slice(1), opts)
    case 'link': return ensLink(args.slice(1), opts)
    default: throw new CliError('Usage: thurin ens <check <name> | link <name> [--key <fpr>] [--calldata]>', EXIT.USAGE)
  }
}

async function resolveName(ctx: ChainCtx, name: string): Promise<{ name: string; address: Address }> {
  if (ctx.network !== 'mainnet') throw new CliError(`ENS names live on mainnet; --network ${ctx.network} cannot read them`, EXIT.USAGE)
  if (!name) throw new CliError('Usage: thurin ens check|link <name>', EXIT.USAGE)
  if (isAddress(name) || !name.includes('.')) throw new CliError(`Give an ENS name, not "${name}"`, EXIT.USAGE)
  let normalized: string
  try { normalized = normalize(name) } catch { throw new CliError(`Not a valid ENS name: ${name}`, EXIT.USAGE) }
  const address = await ctx.client.getEnsAddress({ name: normalized }).catch((e: any) => { throw new CliError(`ENS lookup failed via ${rpcHost(ctx.rpcUrl)}: ${e.shortMessage || e.message} (try --rpc <url>)`, EXIT.CHAIN) })
  if (!address) throw new CliError(`${normalized} does not resolve to an address`, EXIT.FAILED)
  return { name: normalized, address: getAddress(address) }
}

/** The claim a record may point at: verified and active. `--key` picks one; otherwise the newest. */
function pickClaim(claims: Claim[], wanted?: string): Claim | null {
  const active = claims.filter(c => !c.revokedAt && c.verification?.verified)
  if (wanted) {
    const w = wanted.replace(/^0x/i, '').replace(/\s+/g, '').toUpperCase()
    const c = active.find(c => c.fingerprint === w)
    if (!c) throw new CliError(`This address has no active, verified claim for ${wanted}`, EXIT.USAGE)
    return c
  }
  return active[active.length - 1] ?? null
}

/** Read the record and compare it with the address's claim. Exported for `status`. */
export async function ensHintOf(ctx: ChainCtx, name: string, claims: Claim[]): Promise<EnsHint> {
  const record = await ctx.client.getEnsText({ name: normalize(name), key: ENS_HINT_KEY }).catch(() => null)
  return ensHintFor(record, pickClaim(claims)?.fingerprint ?? null)
}

export function renderHint(h: EnsHint, name?: string): string {
  if (h.state === 'match') return `${ok('✓')} ${ENS_HINT_KEY} points at this key`
  if (h.state === 'unset') return `${dim('–')} ${ENS_HINT_KEY} not set${name ? dim(`  (thurin ens link ${name})`) : ''}`
  return `${bad('✗')} ${ENS_HINT_KEY} ${h.reason}${h.record ? dim(`  (record: ${h.record})`) : ''}`
}

async function ensCheck(args: string[], opts: Record<string, any>) {
  const ctx = chainCtx(opts)
  const { name, address } = await resolveName(ctx, args[0])
  const claims = await claimsOf(ctx, address)
  const hint = await ensHintOf(ctx, name, claims)
  // Suggest `ens link` only when there is a verified claim to point at; link refuses otherwise.
  out({ name, address, ...hint }, () => `${bold(name)}  ${dim(address)}\n${label('claim')}${hint.expected ? `${hint.expected.toUpperCase()}  ${ok('✓ verified')}` : bad('none verified')}\n${label('ens record')}${renderHint(hint, hint.state === 'unset' && hint.expected ? name : undefined)}`)
  if (hint.state !== 'match') process.exitCode = EXIT.FAILED
}

async function ensLink(args: string[], opts: Record<string, any>) {
  const ctx = chainCtx(opts)
  const { name, address } = await resolveName(ctx, args[0])
  const claims = await claimsOf(ctx, address)
  const claim = pickClaim(claims, opts.key)
  if (!claim) throw new CliError(`${name} → ${address} has no active, verified claim to point at. Publish a claim first: thurin attest`, EXIT.FAILED)
  const before = await ensHintOf(ctx, name, claims)
  const call = ensHintWrite(name, claim.fingerprint)
  if (before.state === 'match' && !opts.key) {
    out({ name, address, ...before, changed: false }, () => `${ok('✓')} ${name} already points at ${claim.fingerprint}. Nothing to do.`)
    return
  }
  const resolver = await ctx.client.getEnsResolver({ name }).catch(() => null)
  if (!resolver || /^0x0{40}$/.test(resolver)) throw new CliError(`${name} has no resolver; set one in the ENS app first`, EXIT.FAILED)
  if (!isJson()) process.stderr.write(`${label('name')}${name}  ${dim(address)}\n${label('record')}${ENS_HINT_KEY} = ${call.args[2]}\n${label('resolver')}${resolver}\n${before.state === 'mismatch' ? `${label('replaces')}${before.record}\n` : ''}`)
  if (opts.calldata) {
    // The wallet that manages the name is elsewhere: hand over the transaction, send nothing.
    const data = encodeFunctionData({ abi: call.abi, functionName: call.functionName, args: call.args })
    out({ name, address, resolver, chainId: ctx.client.chain!.id, to: resolver, data, value: '0x0', key: ENS_HINT_KEY, record: call.args[2] }, () =>
      `${label('to')}${resolver}\n${label('data')}${data}\n${label('value')}0\n${dim('Send this from the wallet that manages the name (owner or manager). Then: thurin ens check ' + name)}`)
    return
  }
  const r = await send(ctx, opts, call.functionName, [...call.args], `Set ${ENS_HINT_KEY} on ${name}`, { address: resolver, abi: call.abi })
  out({ ...r, name, address, resolver, key: ENS_HINT_KEY, record: call.args[2] }, () => `${ok('Set')} ${ENS_HINT_KEY} on ${bold(name)} → ${call.args[2]}\n${label('tx')}${ctx.explorerUrl ? `${ctx.explorerUrl}/tx/${r.hash}` : r.hash}\n${label('check')}thurin ens check ${name}`)
}
