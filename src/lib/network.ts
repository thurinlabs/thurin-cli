import { bold, dim } from './output.js'

export type Purpose = 'RPC' | 'proof check' | 'relay' | 'other'
export interface HostUse { host: string; purpose: Purpose; requests: number }

const PROOF_HOSTS = new Set(['api.github.com', 'gist.githubusercontent.com', 'codeberg.org', 'cloudflare-dns.com', 'haatz.quilibrium.com', 'hub-api.neynar.com'])
const ORDER: Purpose[] = ['RPC', 'proof check', 'relay', 'other']

/** Host only: RPC URLs often carry an API key in the path or query, and it must never be printed. */
export function hostOf(url: string): string {
  try { return new URL(url).host } catch { return 'unknown' }
}

export function classify(url: string, body: unknown, relayHosts: ReadonlySet<string> = new Set()): Purpose {
  if (typeof body === 'string' && body.includes('"jsonrpc"')) return 'RPC'
  let u: URL
  try { u = new URL(url) } catch { return 'other' }
  // Mastodon instances and Farcaster nodes are chosen per proof, so match them by API path.
  if (PROOF_HOSTS.has(u.host) || u.pathname.startsWith('/api/v1/accounts/lookup') || u.pathname.startsWith('/v1/userNameProofByName') || u.pathname.startsWith('/v1/castById')) return 'proof check'
  if (relayHosts.has(u.host)) return 'relay'
  return 'other'
}

export function tally(uses: HostUse[], host: string, purpose: Purpose): void {
  const hit = uses.find(u => u.host === host && u.purpose === purpose)
  if (hit) hit.requests++
  else uses.push({ host, purpose, requests: 1 })
}

export function sortUses(uses: HostUse[]): HostUse[] {
  return [...uses].sort((a, b) => ORDER.indexOf(a.purpose) - ORDER.indexOf(b.purpose) || a.host.localeCompare(b.host))
}

const uses: HostUse[] = []

/** Counts every fetch this process makes. Installed only with --show-network; nothing is written anywhere. */
export function watchNetwork(relayUrls: (string | undefined)[]): void {
  const relayHosts = new Set(relayUrls.filter((r): r is string => !!r).map(hostOf))
  const original = globalThis.fetch
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    tally(uses, hostOf(url), classify(url, init?.body, relayHosts))
    return original(input, init)
  }) as typeof fetch
}

export function networkReport(): HostUse[] { return sortUses(uses) }

let gpgRan = false
/** gpg reaches keyservers through its own dirmngr, which this report can't see. */
export function noteGpg(): void { gpgRan = true }

/** To stderr, so --json results on stdout stay parseable. */
export function printNetwork(json: boolean): void {
  const report = networkReport()
  if (json) { process.stderr.write(JSON.stringify({ network: report }) + '\n'); return }
  const gpgLine = gpgRan ? dim("  gpg ran; its own network use (dirmngr) isn't seen here") + '\n' : ''
  if (!report.length) { process.stderr.write(dim('network     no hosts contacted') + '\n' + gpgLine); return }
  const w = Math.max(...report.map(r => r.host.length))
  const rows = report.map(r => `  ${r.purpose.padEnd(12)} ${r.host.padEnd(w)}  ${r.requests} request${r.requests === 1 ? '' : 's'}`)
  process.stderr.write(`${bold('network')}     hosts this command contacted (nothing is stored)\n${rows.join('\n')}\n${gpgLine}`)
}
