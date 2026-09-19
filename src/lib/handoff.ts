/**
 * Hand-off link: the PGP half of a claim, done here, carried to thurin.id/attest
 * for a wallet the CLI can't drive (a Ledger, a phone). Everything rides in the
 * URL fragment, which browsers never send to a server, so the payload goes from
 * this terminal to that browser and nowhere else. Same format as
 * thurin-id/src/handoff.js; bump `v` when it changes.
 */

export type HandoffOp = 'attest' | 'reattest' | 'update-key'

export interface Handoff {
  v: 1
  op: HandoffOp
  network: string
  /** The address the claim is for: the wallet that has to publish it. Lowercase. */
  owner: string
  fingerprint: string
  /** Armored public key, exactly what goes on-chain (emails already left out unless includeEmail). */
  key: string
  /** Clearsigned statement; absent for update-key, which needs no new signature. */
  signature?: string
  /** Claim index to replace (reattest) or update (update-key). */
  index?: number
  includeEmail: boolean
}

export const HANDOFF_PARAM = 'handoff'

export function encodeHandoff(h: Handoff): string {
  return Buffer.from(JSON.stringify(h), 'utf8').toString('base64url')
}

export function decodeHandoff(encoded: string): Handoff {
  const h = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'))
  if (h?.v !== 1 || !['attest', 'reattest', 'update-key'].includes(h.op)) throw new Error('Not a Thurin hand-off')
  return h as Handoff
}

/** `https://thurin.id/attest#handoff=…` — the site's path routing keeps /attest; the fragment stays local. */
export function handoffUrl(site: string, h: Handoff): string {
  return `${site.replace(/\/+$/, '')}/attest#${HANDOFF_PARAM}=${encodeHandoff(h)}`
}
