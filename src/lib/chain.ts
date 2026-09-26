import { createPublicClient, http, type Address, type Hex, type PublicClient, type Chain } from 'viem'
import { normalize } from 'viem/ens'
import {
  REGISTRY_ABI, getRegistry, chainFor, isNetworkName, parsePgpKey, readClaims, findOwners, sameFingerprint, keyIdOf, contractErrorText,
  type NetworkName, type PGPKeyInfo, type Attestation,
} from '@thurinlabs/identity-kit/core'
import { readConfig } from './config.js'
import { CliError, EXIT } from './output.js'

export interface ChainCtx {
  network: NetworkName
  rpcUrl: string
  client: PublicClient
  registry: Address
  explorerUrl: string
  /** Where identity links point: --site, the config's site, or thurin.id on mainnet (it reads mainnet only). */
  site: string | null
}

export function chainCtx(opts: { network?: string; rpc?: string; site?: string }): ChainCtx {
  const cfg = readConfig()
  const net = opts.network || process.env.THURIN_NETWORK || cfg.network || 'mainnet'
  if (!isNetworkName(net)) throw new CliError(`Unknown network "${net}" (mainnet, sepolia, local)`, EXIT.USAGE)
  const reg = getRegistry(net)
  const rpcUrl = opts.rpc || process.env.THURIN_RPC_URL || cfg.rpc?.[net] || reg.defaultRpcUrl
  // `as Chain`: with the kit linked from a sibling checkout there are two copies of viem's types.
  const client = createPublicClient({ chain: chainFor(net) as unknown as Chain, transport: http(rpcUrl) })
  const site = opts.site || cfg.site || (net === 'mainnet' ? 'https://thurin.id' : null)
  return { network: net, rpcUrl, client, registry: reg.address as Address, explorerUrl: reg.explorerUrl, site: site ? site.replace(/\/+$/, '') : null }
}

/** A claim as the CLI shows it: the kit's, with the fingerprint uppercase as gpg prints it, and the key parsed. */
export type Claim = Attestation & { keyInfo: PGPKeyInfo | null }

export async function claimsOf(ctx: ChainCtx, owner: Address): Promise<Claim[]> {
  let claims: Attestation[]
  try { claims = await readClaims(ctx.client, owner, { registry: ctx.registry }) }
  catch (err) { throw readError(ctx, err) }
  return Promise.all(claims.map(async c => ({
    ...c, fingerprint: c.fingerprint.toUpperCase(), keyInfo: c.pgpPublicKey ? await parsePgpKey(c.pgpPublicKey) : null,
  })))
}

export async function readRegistry<T>(ctx: ChainCtx, functionName: string, args: unknown[]): Promise<T> {
  try {
    return await ctx.client.readContract({ address: ctx.registry, abi: REGISTRY_ABI, functionName, args } as any) as T
  } catch (err) { throw readError(ctx, err) }
}

/** A would-be write that failed: the registry's own reason (exit 1) when it refused, else a chain error (exit 3). */
export function refusal(what: string, err: any): CliError {
  const text = contractErrorText(err)
  return text ? new CliError(`${what}: ${text}`, EXIT.FAILED) : new CliError(`${what}: ${err.shortMessage || err.message}`, EXIT.CHAIN)
}

function readError(ctx: ChainCtx, err: any): CliError {
  return new CliError(`Couldn't read the registry on ${ctx.network} via ${rpcHost(ctx.rpcUrl)} (${err.shortMessage || err.message}). Try again, or --rpc <url>`, EXIT.CHAIN)
}

export type Lookup = { type: 'address' | 'ens' | 'fingerprint' | 'keyId'; value: string }

/** Whether a claim is for the key a lookup names; address and ENS lookups name no key, so every claim is. */
export function claimMatches(c: { fingerprint: string }, lookup: Lookup): boolean {
  if (lookup.type === 'fingerprint') return sameFingerprint(c.fingerprint, lookup.value)
  if (lookup.type === 'keyId') return keyIdOf(c.fingerprint).slice(2) === lookup.value.replace(/^0x/i, '').toLowerCase()
  return true
}

export function detectLookup(value: string): Lookup {
  const v = value.trim()
  if (/^0x[0-9a-fA-F]{40}$/.test(v)) return { type: 'address', value: v }
  if (/^[0-9a-fA-F]{40}$/.test(v) || /^[0-9a-fA-F]{64}$/.test(v)) return { type: 'fingerprint', value: v.toUpperCase() }
  if (/^(0x)?[0-9a-fA-F]{16}$/.test(v)) return { type: 'keyId', value: v.replace(/^0x/, '').toUpperCase() }
  if (v.includes('.') && v.length > 3) return { type: 'ens', value: v }
  throw new CliError(`Not an address, ENS name, fingerprint, or key ID: ${value}`, EXIT.USAGE)
}

/** Resolve any lookup to the owner address(es) that hold claims for it. */
export async function resolveOwners(ctx: ChainCtx, lookup: Lookup): Promise<{ owners: Address[]; ensName?: string }> {
  if (lookup.type === 'address') return { owners: [lookup.value as Address] }
  if (lookup.type === 'ens') {
    if (ctx.network !== 'mainnet') throw new CliError(`ENS names resolve on mainnet only; use the address on ${ctx.network}`, EXIT.USAGE)
    let addr: Address | null
    try { addr = await ctx.client.getEnsAddress({ name: normalize(lookup.value) }) }
    catch (err: any) { throw new CliError(`ENS lookup failed via ${rpcHost(ctx.rpcUrl)}: ${err.shortMessage || err.message} (try --rpc <url>)`, EXIT.CHAIN) }
    if (!addr) throw new CliError(`${lookup.value} does not resolve to an address`, EXIT.FAILED)
    return { owners: [addr], ensName: lookup.value }
  }
  let found: { owner: Address }[]
  try { found = await findOwners(ctx.client, lookup.type === 'keyId' ? { keyId: lookup.value } : { fingerprint: lookup.value }, { registry: ctx.registry }) }
  catch (err) { throw readError(ctx, err) }
  if (!found.length) throw new CliError(`No claim in the registry for ${lookup.type === 'keyId' ? 'key ID' : 'fingerprint'} ${lookup.value}`, EXIT.FAILED)
  return { owners: [...new Set(found.map(f => f.owner))] }
}

export async function ensNameOf(ctx: ChainCtx, address: Address): Promise<string | null> {
  if (ctx.network !== 'mainnet') return null
  return ctx.client.getEnsName({ address }).catch(() => null)   // cosmetic: a failure here just hides the name
}

/** Just the host of an RPC URL, for messages: providers put API keys in the path or query. */
export function rpcHost(url: string): string {
  try { return new URL(url).host } catch { return 'the RPC' }
}
