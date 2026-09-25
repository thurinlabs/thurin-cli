import { createPublicClient, http, type Address, type Hex, type PublicClient, type Chain } from 'viem'
import { normalize } from 'viem/ens'
import {
  REGISTRY_ABI, getRegistry, chainFor, isNetworkName, parsePgpKey, verifyAttestation, payloadText,
  bytesToFingerprint, fingerprintToBytes, keyIdToBytes,
  type NetworkName, type PGPKeyInfo, type PGPVerification,
} from '@thurinlabs/identity-kit/core'
import { readConfig } from './config.js'
import { CliError, EXIT } from './output.js'

export interface ChainCtx {
  network: NetworkName
  rpcUrl: string
  client: PublicClient
  registry: Address
  explorerUrl: string
}

export function chainCtx(opts: { network?: string; rpc?: string }): ChainCtx {
  const cfg = readConfig()
  const net = opts.network || process.env.THURIN_NETWORK || cfg.network || 'mainnet'
  if (!isNetworkName(net)) throw new CliError(`Unknown network "${net}" (mainnet, sepolia, local)`, EXIT.USAGE)
  const reg = getRegistry(net)
  const rpcUrl = opts.rpc || process.env.THURIN_RPC_URL || cfg.rpc?.[net] || reg.defaultRpcUrl
  // `as Chain`: with the kit linked from a sibling checkout there are two copies of viem's types.
  const client = createPublicClient({ chain: chainFor(net) as unknown as Chain, transport: http(rpcUrl) })
  return { network: net, rpcUrl, client, registry: reg.address as Address, explorerUrl: reg.explorerUrl }
}

/** A claim as the CLI shows it: the on-chain row plus the stored key and signature, and their verification. */
export interface Claim {
  index: number
  fingerprint: string
  createdAt: number
  revokedAt: number | null
  state: 'active' | 'revoked' | 'replaced'
  replacedBy: number | null
  revokeReason: string
  messageVersion: number
  /** The key exactly as stored, 0x hex. */
  keyHex: Hex | null
  /** The key as armored text. */
  pgpPublicKey: string | null
  /** The signature as armored text, or the stored clearsigned message. */
  pgpSignature: string | null
  verification: PGPVerification | null
  keyInfo: PGPKeyInfo | null
}

export async function claimsOf(ctx: ChainCtx, owner: Address): Promise<Claim[]> {
  const rows = await readRegistry<any[]>(ctx, 'claimsOf', [owner])
  const claims: Claim[] = []
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i]
    const fingerprint = bytesToFingerprint(r.fingerprint).toUpperCase()
    let keyHex: Hex | null = null, pgpPublicKey: string | null = null, pgpSignature: string | null = null
    try {
      keyHex = await readRegistry<Hex>(ctx, 'keyBytes', [owner, BigInt(i)])
      pgpPublicKey = await payloadText(keyHex, 'key')
      pgpSignature = await payloadText(await readRegistry<Hex>(ctx, 'signatureBytes', [owner, BigInt(i)]), 'signature')
    } catch { /* unreadable: shown as unverified */ }
    const verification = pgpPublicKey && pgpSignature
      ? await verifyAttestation({ pgpPublicKey, pgpSignature, fingerprint, ethAddress: owner })
      : { verified: false, reason: 'No PGP data stored' }
    const keyInfo = pgpPublicKey ? await parsePgpKey(pgpPublicKey) : null
    claims.push({
      index: i, fingerprint, createdAt: Number(r.createdAt), revokedAt: Number(r.revokedAt) || null,
      state: r.state, replacedBy: r.state === 'replaced' ? Number(r.replacedBy) : null, revokeReason: r.revokeReason,
      messageVersion: Number(r.messageVersion), keyHex, pgpPublicKey, pgpSignature, verification, keyInfo,
    })
  }
  return claims
}

export async function readRegistry<T>(ctx: ChainCtx, functionName: string, args: unknown[]): Promise<T> {
  try {
    return await ctx.client.readContract({ address: ctx.registry, abi: REGISTRY_ABI, functionName, args } as any) as T
  } catch (err: any) {
    throw new CliError(`Registry read failed (${functionName}) on ${ctx.network} via ${ctx.rpcUrl}: ${err.shortMessage || err.message}`, EXIT.CHAIN)
  }
}

export type Lookup = { type: 'address' | 'ens' | 'fingerprint' | 'keyId'; value: string }

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
    catch (err: any) { throw new CliError(`ENS lookup failed via ${ctx.rpcUrl}: ${err.shortMessage || err.message} (try --rpc <url>)`, EXIT.CHAIN) }
    if (!addr) throw new CliError(`${lookup.value} does not resolve to an address`, EXIT.FAILED)
    return { owners: [addr], ensName: lookup.value }
  }
  let fps: `0x${string}`[]
  if (lookup.type === 'keyId') {
    const kid = keyIdToBytes(lookup.value)
    if (!kid) throw new CliError('Invalid key ID', EXIT.USAGE)
    fps = await readRegistry(ctx, 'fingerprintsForKeyId', [kid])
    if (!fps.length) throw new CliError(`No claim in the registry for key ID ${lookup.value}`, EXIT.FAILED)
  } else {
    fps = [fingerprintToBytes(lookup.value) as `0x${string}`]
  }
  const owners: Address[] = []
  for (const fp of fps) owners.push(...await readRegistry<Address[]>(ctx, 'ownersOf', [fp]))
  if (!owners.length) throw new CliError(`No claim in the registry for fingerprint ${lookup.value}`, EXIT.FAILED)
  return { owners: [...new Set(owners)] }
}

export async function ensNameOf(ctx: ChainCtx, address: Address): Promise<string | null> {
  if (ctx.network !== 'mainnet') return null
  return ctx.client.getEnsName({ address }).catch(() => null)   // cosmetic: a failure here just hides the name
}
