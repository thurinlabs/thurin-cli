import { stringToHex, isAddress, getAddress, type Address } from 'viem'
import { normalize } from 'viem/ens'
import {
  REGISTRY_ABI, parsePgpKey, verifyAttestation, stripEmailUserIDs, identifyProof, fingerprintToBytes,
} from '@thurinlabs/identity-kit/core'
import { chainCtx, claimsOf, type ChainCtx } from '../lib/chain.js'
import { findKey, clearsign, exportMinimal, attestStatement } from '../lib/gpg.js'
import { loadAccount } from '../lib/keystore.js'
import { prompt, confirm } from '../lib/prompt.js'
import { readConfig } from '../lib/config.js'
import { out, info, ok, bad, dim, bold, label, isJson, CliError, EXIT } from '../lib/output.js'
import { handoffUrl, type Handoff, type HandoffOp } from '../lib/handoff.js'

const MAX_KEY = 8192, MAX_SIG = 4096

/** Everything the registry and the explorer will check, run before any gas is spent. */
async function preflight(ctx: ChainCtx, owner: Address, fpr: string, includeEmail: boolean, needSignature: boolean) {
  const full = await exportMinimal(fpr)
  let armored = full, kept: string[] = [], removed: string[] = []
  if (includeEmail) { kept = (await parsePgpKey(full))?.userIDs ?? [] }
  else {
    const s = await stripEmailUserIDs(full)
    if (!s) throw new CliError(`Every name on ${fpr} contains an email. Add one without: thurin key add-name ${fpr} thurin — or pass --include-email`, EXIT.FAILED)
    armored = s.armored; kept = s.kept; removed = s.removed
  }
  const info_ = await parsePgpKey(armored)
  if (!info_) throw new CliError('Exported key does not parse', EXIT.FAILED)
  if (info_.fingerprint.toUpperCase() !== fpr.toUpperCase()) throw new CliError('Exported key fingerprint does not match', EXIT.FAILED)
  const proofs = info_.notations.map(identifyProof).filter(Boolean)
  const bytes = new TextEncoder().encode(armored).length
  if (bytes > MAX_KEY) throw new CliError(`Key is ${bytes} bytes; the registry accepts up to ${MAX_KEY}`, EXIT.FAILED)
  let signature: string | null = null
  if (needSignature) {
    info(`Signing "${attestStatement(owner)}" with ${fpr} (gpg will ask for the passphrase).`)
    signature = await clearsign(fpr, attestStatement(owner))
    if (new TextEncoder().encode(signature).length > MAX_SIG) throw new CliError('Signature too large', EXIT.FAILED)
    const v = await verifyAttestation({ pgpPublicKey: armored, pgpSignature: signature, fingerprint: fpr, ethAddress: owner })
    if (!v.verified) throw new CliError(`The signature does not verify against the exported key: ${v.reason}`, EXIT.FAILED)
  }
  return { armored, signature, kept, removed, proofs: proofs.length, bytes }
}

function summary(p: Awaited<ReturnType<typeof preflight>>) {
  return `${label('names')}${p.kept.join(', ')}${p.removed.length ? dim(`  (left out: ${p.removed.join(', ')})`) : ''}\n${label('proofs')}${p.proofs}\n${label('size')}${(p.bytes / 1024).toFixed(1)} KB`
}

async function send(ctx: ChainCtx, opts: Record<string, any>, functionName: string, args: unknown[], what: string) {
  const account = await loadAccount(opts, q => prompt(q, true))
  const { createWalletClient, http } = await import('viem')
  const wallet = createWalletClient({ account, chain: ctx.client.chain, transport: http(ctx.rpcUrl) })
  const gas = await ctx.client.estimateContractGas({ address: ctx.registry, abi: REGISTRY_ABI, functionName, args, account } as any).catch((e: any) => { throw new CliError(`${what} would revert: ${e.shortMessage || e.message}`, EXIT.CHAIN) })
  const price = await ctx.client.getGasPrice()
  const eth = Number(gas * price) / 1e18
  if (!opts.yes && !isJson() && !(await confirm(`${what} from ${account.address} on ${ctx.network} (~${gas} gas, ~${eth.toFixed(6)} ETH). Send?`))) throw new CliError('Cancelled', EXIT.USAGE)
  const hash = await wallet.writeContract({ address: ctx.registry, abi: REGISTRY_ABI, functionName, args, account, chain: ctx.client.chain } as any)
  info(`Sent ${hash}. Waiting for confirmation…`)
  const receipt = await ctx.client.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new CliError(`Transaction reverted: ${hash}`, EXIT.CHAIN)
  return { hash, block: receipt.blockNumber, gasUsed: receipt.gasUsed, account: account.address }
}

function identityUrl(ctx: ChainCtx, owner: Address) { return `https://thurin.id/eth/${owner}` }
function txUrl(ctx: ChainCtx, hash: string) { return ctx.explorerUrl ? `${ctx.explorerUrl}/tx/${hash}` : hash }

async function ownerFor(ctx: ChainCtx, opts: Record<string, any>): Promise<Address> {
  if (opts.noKey) {
    // Hand-off: the wallet that will publish lives elsewhere, so the address is given, not derived.
    const given: string = opts.owner || ''
    if (!given) throw new CliError('--no-key needs --owner <address|ens>: the wallet that will publish the claim', EXIT.USAGE)
    if (isAddress(given)) return getAddress(given)
    if (!given.endsWith('.eth')) throw new CliError(`--owner must be an address or an ENS name, not "${given}"`, EXIT.USAGE)
    const resolved = await ctx.client.getEnsAddress({ name: normalize(given) }).catch((e: any) => { throw new CliError(`ENS lookup failed for ${given}: ${e.shortMessage || e.message}`, EXIT.CHAIN) })
    if (!resolved) throw new CliError(`${given} does not resolve to an address on ${ctx.network}`, EXIT.FAILED)
    info(`${given} → ${resolved}`)
    return resolved
  }
  // The address the claim is published from = the paying account.
  const acct = await loadAccount(opts, q => prompt(q, true))
  return acct.address
}

/**
 * --no-key: print a thurin.id/attest link instead of sending. The signed statement and
 * the key ride in the URL fragment; the page reads them and asks the connected wallet
 * to publish. Nothing is sent from here, so no account, password, or gas is needed.
 */
function handoff(ctx: ChainCtx, opts: Record<string, any>, op: HandoffOp, owner: Address, fpr: string, p: Awaited<ReturnType<typeof preflight>>, index?: number) {
  const site: string = opts.site || readConfig().site || 'https://thurin.id'
  const h: Handoff = {
    v: 1, op, network: ctx.network, owner: owner.toLowerCase(), fingerprint: fpr.toUpperCase(),
    key: p.armored, includeEmail: !!opts.includeEmail,
    ...(p.signature ? { signature: p.signature } : {}),
    ...(index !== undefined ? { index } : {}),
  }
  const url = handoffUrl(site, h)
  if (ctx.network !== 'mainnet' && !opts.site) info(`thurin.id runs mainnet; for ${ctx.network} open this on a ${ctx.network} build (--site http://localhost:5173).`)
  out({ handoff: true, op, owner, fingerprint: fpr, network: ctx.network, index, proofs: p.proofs, url }, () =>
    `${ok('Ready to publish')} ${bold(fpr)} for ${owner}${index !== undefined ? ` (claim #${index})` : ''}
` +
    `Open this link where that wallet is (the part after # never leaves your browser) and confirm:

${url}
`)
}

export async function attest(_args: string[], opts: Record<string, any>) {
  const ctx = chainCtx(opts)
  const k = await findKey(opts.key || readConfig().key || '')
  const owner = await ownerFor(ctx, opts)
  const existing = (await claimsOf(ctx, owner)).filter(c => !c.revokedAt)
  const dup = existing.find(c => c.fingerprint === k.fingerprint)
  if (dup && !opts.replace) throw new CliError(`${owner} already has an active claim for ${k.fingerprint} (#${dup.index}). Use thurin reattest ${dup.index}, or thurin update-key ${dup.index} to change its key.`, EXIT.FAILED)
  const p = await preflight(ctx, owner, k.fingerprint, !!opts.includeEmail, true)
  if (!isJson()) process.stderr.write(summary(p) + '\n')
  if (opts.noKey) return handoff(ctx, opts, 'attest', owner, k.fingerprint, p)
  const r = await send(ctx, opts, 'attest', [fingerprintToBytes(k.fingerprint), stringToHex(p.signature!), stringToHex(p.armored)], 'Publish claim')
  out({ ...r, owner, fingerprint: k.fingerprint, proofs: p.proofs, identity: identityUrl(ctx, owner), tx: txUrl(ctx, r.hash) }, () =>
    `${ok('Published')} ${bold(k.fingerprint)} for ${owner}\n${label('tx')}${txUrl(ctx, r.hash)}\n${label('identity')}${identityUrl(ctx, owner)}`)
}

export async function updateKey(args: string[], opts: Record<string, any>) {
  const ctx = chainCtx(opts)
  const owner = await ownerFor(ctx, opts)
  const claims = await claimsOf(ctx, owner)
  const idx = pickIndex(args[0], claims)
  const c = claims[idx]
  if (c.revokedAt) throw new CliError(`Claim #${idx} is revoked`, EXIT.FAILED)
  const includeEmail = opts.includeEmail ?? (c.keyInfo?.userIDs.some(u => u.includes('@')) ?? false)
  const p = await preflight(ctx, owner, c.fingerprint, includeEmail, false)
  if (p.armored === c.pgpPublicKey) throw new CliError('The exported key is identical to the one on-chain; nothing to update', EXIT.FAILED)
  if (!isJson()) process.stderr.write(summary(p) + '\n')
  if (opts.noKey) return handoff(ctx, { ...opts, includeEmail }, 'update-key', owner, c.fingerprint, p, idx)
  const r = await send(ctx, opts, 'updateKey', [BigInt(idx), stringToHex(p.armored)], `Update key on claim #${idx}`)
  out({ ...r, owner, index: idx, proofs: p.proofs, identity: identityUrl(ctx, owner), tx: txUrl(ctx, r.hash) }, () =>
    `${ok('Updated')} claim #${idx}: ${p.proofs} proofs\n${label('tx')}${txUrl(ctx, r.hash)}\n${label('identity')}${identityUrl(ctx, owner)}`)
}

export async function reattest(args: string[], opts: Record<string, any>) {
  const ctx = chainCtx(opts)
  const k = await findKey(opts.key || readConfig().key || '')
  const owner = await ownerFor(ctx, opts)
  const claims = await claimsOf(ctx, owner)
  const idx = pickIndex(args[0], claims)
  if (claims[idx].revokedAt) throw new CliError(`Claim #${idx} is already revoked`, EXIT.FAILED)
  const p = await preflight(ctx, owner, k.fingerprint, !!opts.includeEmail, true)
  if (!isJson()) process.stderr.write(summary(p) + '\n')
  if (opts.noKey) return handoff(ctx, opts, 'reattest', owner, k.fingerprint, p, idx)
  const r = await send(ctx, opts, 'reattest', [BigInt(idx), fingerprintToBytes(k.fingerprint), stringToHex(p.signature!), stringToHex(p.armored)], `Revoke #${idx} and publish a new claim`)
  out({ ...r, owner, revoked: idx, fingerprint: k.fingerprint, identity: identityUrl(ctx, owner), tx: txUrl(ctx, r.hash) }, () =>
    `${ok('Replaced')} claim #${idx} with ${bold(k.fingerprint)}\n${label('tx')}${txUrl(ctx, r.hash)}\n${label('identity')}${identityUrl(ctx, owner)}`)
}

export async function revoke(args: string[], opts: Record<string, any>) {
  const ctx = chainCtx(opts)
  if (opts.noKey) throw new CliError('revoke has nothing to sign; do it from Your claims on thurin.id/attest', EXIT.USAGE)
  const owner = await ownerFor(ctx, opts)
  const claims = await claimsOf(ctx, owner)
  const idx = pickIndex(args[0], claims)
  if (claims[idx].revokedAt) throw new CliError(`Claim #${idx} is already revoked`, EXIT.FAILED)
  const r = await send(ctx, opts, 'revoke', [BigInt(idx)], `Revoke claim #${idx} (${claims[idx].fingerprint})`)
  out({ ...r, owner, index: idx, tx: txUrl(ctx, r.hash) }, () => `${bad('Revoked')} claim #${idx}\n${label('tx')}${txUrl(ctx, r.hash)}`)
}

function pickIndex(arg: string | undefined, claims: { revokedAt: number | null }[]): number {
  if (arg !== undefined) { const i = Number(arg); if (!Number.isInteger(i) || i < 0 || i >= claims.length) throw new CliError(`No claim #${arg} (this address has ${claims.length})`, EXIT.USAGE); return i }
  const active = claims.map((c, i) => [c, i] as const).filter(([c]) => !c.revokedAt)
  if (active.length === 1) return active[0][1]
  throw new CliError(active.length ? 'Several active claims; give the index (thurin status <address>)' : 'No active claim for this address', EXIT.USAGE)
}
