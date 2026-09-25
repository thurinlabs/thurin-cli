/**
 * Hand-off link: the PGP half of a claim, done here, carried to thurin.id/attest
 * for a wallet the CLI can't drive (a Ledger, a phone). Everything rides in the
 * URL fragment, which browsers never send to a server, so the payload goes from
 * this terminal to that browser and nowhere else. Same format as
 * thurin-id/src/handoff.js (format 2); bump `v` when it changes.
 *
 * With `authorization` the owner has also signed the write as EIP-712 typed data
 * (`--authorize`), so anyone can publish it through the registry's `…For` calls and
 * pay the fee: a friend, `thurin submit`, or a relayer. The typed data is rebuilt from
 * the other fields rather than carried, so what is shown is what was signed.
 */
import { readFileSync, existsSync } from 'node:fs'
import { stringToHex, type Address, type Hex } from 'viem'
import {
  fingerprintToBytes, attestTypedData, reattestTypedData, updateKeyTypedData, revokeTypedData, setRecordTypedData, markCompromisedTypedData, OWNER_REVOKE_REASONS,
  type RevokeReason,
} from '@thurinlabs/identity-kit/core'

export type HandoffOp = 'attest' | 'reattest' | 'update-key' | 'revoke' | 'set-record' | 'mark-compromised'
const OPS: HandoffOp[] = ['attest', 'reattest', 'update-key', 'revoke', 'set-record', 'mark-compromised']

export interface Authorization {
  nonce: number
  /** Unix seconds. */
  deadline: number
  /** The owner's EIP-712 signature, 65 bytes hex. */
  signature: Hex
}

export interface Handoff {
  v: 2
  op: HandoffOp
  network: string
  /** The address the claim is for. Lowercase. */
  owner: string
  fingerprint: string
  /** The key exactly as it goes on-chain, 0x hex. Absent for revoke, set-record and mark-compromised. */
  key?: string
  /** The signature as 0x hex, or a whole clearsigned message as text; attest and reattest only. */
  signature?: string
  /** reattest: move the replaced claim's records to the new one (default true). */
  keepRecords?: boolean
  /** revoke: '', 'compromised', 'retired', or 'other'. */
  reason?: RevokeReason
  /** Claim index to replace (reattest), update (update-key), revoke, set a record on, or mark compromised. */
  index?: number
  /** set-record: the record name as submitted (e.g. canary or thurin.canary) and text value ('' clears). */
  kind?: string
  value?: string
  includeEmail: boolean
  authorization?: Authorization
}

export const HANDOFF_PARAM = 'handoff'
export const FOR_FN: Record<HandoffOp, string> = { attest: 'attestFor', reattest: 'reattestFor', 'update-key': 'updateKeyFor', revoke: 'revokeFor', 'set-record': 'setRecordFor', 'mark-compromised': 'markCompromisedFor' }

/**
 * The link's fragment: `<base64url JSON>[.<base64url key>[.<base64url signature>]]`. The key and
 * signature ride as their own raw bytes, not as hex inside the JSON: half the length. A signature part
 * starting with '-' is a clearsigned message (text); anything else is a raw signature packet.
 */
export function encodeHandoff(h: Handoff): string {
  const { key, signature, ...rest } = h
  const parts = [b64(Buffer.from(JSON.stringify(rest), 'utf8'))]
  if (key) parts.push(b64(payloadBuffer(key)))
  if (signature) parts.push(b64(payloadBuffer(signature)))
  return parts.join('.')
}

const b64 = (b: Buffer) => b.toString('base64url')
/** 0x hex → its bytes; text (a clearsigned message) → its UTF-8 bytes. */
const payloadBuffer = (v: string) => (/^0x([0-9a-fA-F]{2})+$/.test(v) ? Buffer.from(v.slice(2), 'hex') : Buffer.from(v, 'utf8'))
/** Bytes back to what the handoff carries: text if they start with '-', else 0x hex. */
const payloadValue = (b: Buffer) => (b[0] === 0x2d ? b.toString('utf8') : `0x${b.toString('hex')}`)

export function decodeHandoff(encoded: string): Handoff {
  let h: any
  const [json, keyPart, sigPart] = encoded.split('.')
  try { h = JSON.parse(Buffer.from(json, 'base64url').toString('utf8')) } catch { throw new Error('Not a Thurin.id link or permission file') }
  if (h && keyPart) h.key = payloadValue(Buffer.from(keyPart, 'base64url'))
  if (h && sigPart) h.signature = payloadValue(Buffer.from(sigPart, 'base64url'))
  if (h?.v === 1) throw new Error('This link is from an older registry; make a new one')
  if (h?.v !== 2 || !OPS.includes(h.op)) throw new Error('Not a Thurin.id link or permission file')
  if (!/^0x[0-9a-f]{40}$/.test(h.owner || '')) throw new Error('The link has no valid owner')
  if (h.op !== 'attest' && !Number.isInteger(h.index)) throw new Error('The link names no claim')
  if ((h.op === 'attest' || h.op === 'reattest' || h.op === 'update-key') && !isHex(h.key)) throw new Error('The link carries no key')
  if (h.reason != null && !(OWNER_REVOKE_REASONS as readonly string[]).includes(h.reason)) throw new Error(`Unknown revoke reason "${h.reason}"`)
  if (h.keepRecords != null && typeof h.keepRecords !== 'boolean') throw new Error('The link has an invalid keepRecords')
  if (h.op === 'set-record' && (typeof h.kind !== 'string' || typeof h.value !== 'string')) throw new Error('The link names no record')
  if ((h.op === 'attest' || h.op === 'reattest') && typeof h.signature !== 'string') throw new Error('The link carries no signature')
  if (h.authorization != null) {
    const a = h.authorization
    if (!Number.isInteger(a.nonce) || !Number.isInteger(a.deadline) || !/^0x[0-9a-f]{130}$/i.test(a.signature || '')) throw new Error("The link's permission is malformed")
  }
  return h as Handoff
}

/** `https://thurin.id/attest#handoff=…` — the site's path routing keeps /attest; the fragment stays local. */
export function handoffUrl(site: string, h: Handoff): string {
  return `${site.replace(/\/+$/, '')}/attest#${HANDOFF_PARAM}=${encodeHandoff(h)}`
}

/** A hand-off from wherever the user has it: a link, a JSON file, or the bare fragment value. */
export function readHandoffInput(input: string): Handoff {
  const m = input.trim().match(/#handoff=([A-Za-z0-9_.-]+)$/)
  if (m) return decodeHandoff(m[1])
  if (existsSync(input)) {
    const h = JSON.parse(readFileSync(input, 'utf8'))
    return decodeHandoff(encodeHandoff(h))   // same validation as the link
  }
  if (/^[A-Za-z0-9_.-]+$/.test(input.trim())) return decodeHandoff(input.trim())
  throw new Error(`"${input}" is not a link, permission file, or fragment`)
}

/** The typed data the owner signed (or will sign), rebuilt from the hand-off's own fields. */
export function typedDataFor(h: Handoff, chainId: number, registry: Address) {
  if (!h.authorization) throw new Error('No authorization to build typed data for')
  const common = { owner: h.owner as Address, nonce: BigInt(h.authorization.nonce), deadline: BigInt(h.authorization.deadline) }
  switch (h.op) {
    case 'attest': return attestTypedData(chainId, registry, { ...common, fingerprint: h.fingerprint, signature: h.signature!, key: h.key! })
    case 'reattest': return reattestTypedData(chainId, registry, { ...common, revokeIndex: BigInt(h.index!), fingerprint: h.fingerprint, signature: h.signature!, key: h.key!, keepRecords: h.keepRecords !== false })
    case 'update-key': return updateKeyTypedData(chainId, registry, { ...common, index: BigInt(h.index!), key: h.key! })
    case 'revoke': return revokeTypedData(chainId, registry, { ...common, index: BigInt(h.index!), reason: h.reason ?? '' })
    case 'set-record': return setRecordTypedData(chainId, registry, { ...common, index: BigInt(h.index!), kind: h.kind!, value: h.value ?? '' })
    case 'mark-compromised': return markCompromisedTypedData(chainId, registry, { ...common, index: BigInt(h.index!) })
  }
}

function isHex(v: unknown): v is Hex { return typeof v === 'string' && /^0x([0-9a-fA-F]{2})+$/.test(v) }

/** A payload argument: 0x hex is raw bytes; a clearsigned message goes as its text's bytes. */
export function payloadArg(v: string): Hex { return isHex(v) ? v : stringToHex(v) }

/** Arguments for the matching `…For` call. */
export function forArgsOf(h: Handoff): unknown[] {
  const a = h.authorization!
  const d = BigInt(a.deadline)
  switch (h.op) {
    case 'attest': return [h.owner, fingerprintToBytes(h.fingerprint), payloadArg(h.signature!), payloadArg(h.key!), d, a.signature]
    case 'reattest': return [h.owner, BigInt(h.index!), fingerprintToBytes(h.fingerprint), payloadArg(h.signature!), payloadArg(h.key!), h.keepRecords !== false, d, a.signature]
    case 'update-key': return [h.owner, BigInt(h.index!), payloadArg(h.key!), d, a.signature]
    case 'revoke': return [h.owner, BigInt(h.index!), h.reason ?? '', d, a.signature]
    case 'set-record': return [h.owner, BigInt(h.index!), h.kind!, h.value ?? '', d, a.signature]
    case 'mark-compromised': return [h.owner, BigInt(h.index!), d, a.signature]
  }
}

/** "1h", "2d", "1w", or unix seconds → unix seconds from now. */
export function parseDeadline(spec: string | undefined, fallback = '7d'): number {
  const s = (spec || fallback).trim()
  if (/^\d{9,}$/.test(s)) return Number(s)
  const m = s.match(/^(\d+)\s*([mhdw])$/i)
  if (!m) throw new Error(`Bad deadline "${s}": use 30m, 12h, 3d, 1w, or a unix timestamp`)
  const mult = { m: 60, h: 3600, d: 86400, w: 604800 }[m[2].toLowerCase() as 'm' | 'h' | 'd' | 'w']
  return Math.floor(Date.now() / 1000) + Number(m[1]) * mult
}

export function describeDeadline(unix: number): string {
  const left = unix - Math.floor(Date.now() / 1000)
  const when = new Date(unix * 1000).toISOString().replace('T', ' ').slice(0, 16) + ' UTC'
  if (left <= 0) return `expired ${when}`
  const n = left < 3600 ? Math.max(1, Math.floor(left / 60)) : left < 86400 ? Math.floor(left / 3600) : Math.floor(left / 86400)
  const span = `${n} ${left < 3600 ? 'minute' : left < 86400 ? 'hour' : 'day'}${n === 1 ? '' : 's'}`
  return `${span} (${when})`
}
