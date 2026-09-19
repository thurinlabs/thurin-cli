import { hexToString, stringToHex, keccak256, type Hex } from 'viem'

/**
 * Records: one small value per claim per kind, set only by the owner. Conventions (vault,
 * Railgun note): kind = keccak256("thurin.<name>"); simple kinds are UTF-8 text, structured
 * kinds small JSON with a `v`; readers ignore unknown fields. 1 KB max on-chain.
 */
export const MAX_RECORD_BYTES = 1024

/** `thurin.pointer`: things this identity put out, each named by the sha256 of its checksum file. */
export interface PointerEntry {
  /** What it is, e.g. "thurin-cli 0.5.1". */
  name: string
  /** sha256 of the SHA256SUMS (or manifest) file, hex, no 0x. */
  sha256: string
  /** ISO date. */
  date: string
  /** Optional: where to find it. */
  url?: string
}
export interface PointerRecord { v: 1; releases: PointerEntry[] }

export const KNOWN_KINDS = ['thurin.pointer', 'thurin.railgun', 'thurin.private', 'thurin.disclosure'] as const

export function kindName(input: string): string {
  return input.startsWith('thurin.') ? input : `thurin.${input}`
}

export function encodeRecord(value: string): Hex {
  const bytes = new TextEncoder().encode(value).length
  if (bytes > MAX_RECORD_BYTES) throw new Error(`Record is ${bytes} bytes; the registry accepts up to ${MAX_RECORD_BYTES}`)
  return stringToHex(value)
}

export function decodeRecord(hex: Hex): string {
  return hex === '0x' ? '' : hexToString(hex)
}

export function parsePointer(text: string): PointerRecord {
  const p = JSON.parse(text)
  if (p?.v !== 1 || !Array.isArray(p.releases)) throw new Error('Not a v1 thurin.pointer record')
  return p
}

/** Add a release, newest first; drop the oldest until it fits the 1 KB slot. */
export function addPointer(existing: PointerRecord | null, entry: PointerEntry): { record: PointerRecord; dropped: PointerEntry[] } {
  if (!/^[0-9a-f]{64}$/i.test(entry.sha256)) throw new Error('sha256 must be 64 hex characters')
  const releases = [entry, ...(existing?.releases ?? []).filter(r => r.name !== entry.name)]
  const dropped: PointerEntry[] = []
  const record: PointerRecord = { v: 1, releases }
  while (new TextEncoder().encode(JSON.stringify(record)).length > MAX_RECORD_BYTES && releases.length > 1) dropped.push(releases.pop()!)
  return { record, dropped }
}

export function renderPointer(p: PointerRecord): string {
  return p.releases.map(r => `${r.name.padEnd(22)} ${r.date}  sha256 ${r.sha256}${r.url ? `  ${r.url}` : ''}`).join('\n')
}

export { keccak256 }
