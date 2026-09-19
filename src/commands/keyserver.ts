import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { createRequire } from 'node:module'
import type { Address } from 'viem'
import { chainCtx, claimsOf, resolveOwners, detectLookup, ensNameOf, type ChainCtx, type Claim } from '../lib/chain.js'
import { CliError, EXIT, ok, bold, dim, label } from '../lib/output.js'

/**
 * thurin keyserver — the registry served over HKP, the protocol gpg has spoken since the
 * 1990s. Point dirmngr at it (`keyserver hkp://127.0.0.1:11371`) and every --recv-keys,
 * --refresh-keys, --locate-keys, and auto-key-retrieve on the machine reads Ethereum.
 *
 * Stateless: no database, nothing but chain reads and a short in-memory cache. There is no
 * /pks/add — publishing is attesting — so certificate flooding is structurally impossible.
 * A fetch by full fingerprint is self-authenticating: gpg checks what it gets hashes to what
 * it asked for, so even a hostile server can only withhold, never substitute.
 */

const VERSION: string = (() => { try { return createRequire(import.meta.url)('../package.json').version } catch { return process.env.npm_package_version || '0' } })()

export async function keyserver(_args: string[], opts: Record<string, any>) {
  const ctx = chainCtx(opts)
  const host: string = opts.host || '127.0.0.1'
  const port = Number(opts.port || 11371)
  const ttl = Number(opts.cacheSeconds ?? 60) * 1000
  const cache = new Map<string, { at: number; value: Entry[] }>()

  process.stderr.write(`${ok('thurin keyserver')} on ${ctx.network} · ${bold(`hkp://${host}:${port}`)}\n` +
    `${label('gpg')}gpg --keyserver hkp://${host}:${port} --recv-keys <fingerprint>\n` +
    `${label('dirmngr')}echo "keyserver hkp://${host}:${port}" >> ~/.gnupg/dirmngr.conf && gpgconf --kill dirmngr\n` +
    `${dim('No /pks/add: keys are published by attesting. Cache ' + ttl / 1000 + 's.')}\n`)

  async function lookup(search: string): Promise<Entry[]> {
    const hit = cache.get(search)
    if (hit && Date.now() - hit.at < ttl) return hit.value
    const value = await find(ctx, search)
    cache.set(search, { at: Date.now(), value })
    return value
  }

  const server = createServer((req, res) => handle(req, res).catch(e => text(res, 500, `error: ${e.message}`)))
  async function handle(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`)
    res.setHeader('access-control-allow-origin', '*')
    if (req.method === 'POST' && url.pathname === '/pks/add') {
      log(req, 'add refused')
      return text(res, 405, 'This keyserver has no upload. Keys are published by their owner attesting at https://thurin.id/attest or with `thurin attest`.')
    }
    if (url.pathname === '/' || url.pathname === '/health') return text(res, 200, `thurin keyserver ${VERSION} · ${ctx.network} · HKP over the Thurin registry. GET /pks/lookup?op=get&search=0x<fingerprint>`)
    if (url.pathname !== '/pks/lookup' || req.method !== 'GET') return text(res, 404, 'not found')
    const op = url.searchParams.get('op') || 'get'
    const search = (url.searchParams.get('search') || '').trim()
    if (!search) return text(res, 400, 'search parameter required')
    if (op !== 'get' && op !== 'index' && op !== 'vindex') return text(res, 501, `op=${op} not supported`)

    let entries: Entry[]
    try { entries = await lookup(search) }
    catch (e: any) {
      if (e instanceof CliError && e.code === EXIT.USAGE) { log(req, `refused: ${e.message}`); return text(res, 404, e.message) }   // an email or a word: nothing to find by design
      if (e instanceof CliError && e.code === EXIT.FAILED) { log(req, 'not found'); return text(res, 404, 'No key found') }
      throw e
    }
    if (!entries.length) { log(req, 'not found'); return text(res, 404, 'No key found') }
    log(req, `${op} ${entries.length} key(s)`)
    if (op === 'get') {
      const body = entries.map(e => e.armored).join('\n')
      // gpg gets the keyserver media type. A browser (Accept: text/html) gets the same bytes
      // shown as text instead of a download; anything else downloads under a sensible name.
      const browser = /text\/html/.test(req.headers.accept || '')
      const name = `${entries.map(e => e.fingerprint).join('+')}.asc`
      res.writeHead(200, browser
        ? { 'content-type': 'text/plain; charset=utf-8', 'cache-control': `max-age=${ttl / 1000}` }
        : { 'content-type': 'application/pgp-keys', 'content-disposition': `inline; filename="${name}"`, 'cache-control': `max-age=${ttl / 1000}` })
      res.end(body)
      return
    }
    // Machine-readable index (options=mr), the form dirmngr parses.
    const lines = [`info:1:${entries.length}`]
    for (const e of entries) {
      lines.push(`pub:${e.fingerprint}:${e.algo}:${e.bits}:${e.created}:${e.expires}:${e.revoked ? 'r' : ''}`)
      lines.push(`fpr:${e.fingerprint}`)   // gpg shows the full fingerprint in --search-keys only from this line
      for (const u of e.uids) lines.push(`uid:${encodeURIComponent(u)}:${e.created}::`)
    }
    res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': `max-age=${ttl / 1000}` })
    res.end(lines.join('\n') + '\n')
  }

  server.listen(port, host)
  await new Promise<void>(resolve => { for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, () => { server.close(); resolve() }) })
}

interface Entry { fingerprint: string; armored: string; algo: number; bits: number; created: number; expires: number | ''; revoked: boolean; uids: string[]; owner: Address }

/** Every verified, active key for a search term: fingerprint, key ID, address, or (mainnet) ENS name. */
/**
 * The search terms served: fingerprint, key ID (gpg sends both 0x-prefixed), address, ENS.
 * Email and free text return nothing, by design: emails are off-chain unless the owner chose
 * otherwise, and fingerprint / key ID were the only keyserver searches that were ever safe.
 */
export function hkpSearchTerm(search: string): string {
  // gpg sends 0x + 16 hex for a key ID and 0x + 40 hex for a fingerprint; an Ethereum address is
  // also 0x + 40 hex. A bare 40-hex is treated as a fingerprint, 0x-prefixed as an address, so
  // only the key-ID form loses its prefix here. Fingerprint lookups from gpg still work because
  // an address that has no claim falls through to nothing, and gpg always sends the full 0x40.
  const q = search.trim().replace(/^0x(?=[0-9a-fA-F]{16}$)/, '')
  if (!/^([0-9a-fA-F]{16}|[0-9a-fA-F]{40}|0x[0-9a-fA-F]{40}|[a-z0-9-]+(\.[a-z0-9-]+)+)$/i.test(q)) throw new CliError('Search by fingerprint, key ID, address, or ENS name', EXIT.USAGE)
  return q
}

async function find(ctx: ChainCtx, search: string): Promise<Entry[]> {
  const q = hkpSearchTerm(search)
  // 0x + 40 hex is how gpg spells a fingerprint, and also an Ethereum address. Try it as a
  // fingerprint first (a registry index read, never throws on shape); if no claim, as an address.
  const hex40 = /^0x[0-9a-fA-F]{40}$/.test(q) ? q.slice(2).toUpperCase() : null
  let lookup = hex40 ? { type: 'fingerprint' as const, value: hex40 } : detectLookup(q)
  let owners: Address[] = []
  try { owners = (await resolveOwners(ctx, lookup)).owners }
  catch (e) {
    if (!hex40) throw e
    lookup = { type: 'address', value: q }
    try { owners = (await resolveOwners(ctx, lookup)).owners } catch { throw e }
    // an address that is not checksummed correctly is not an address gpg would send us; viem will say so below
  }
  const out: Entry[] = []
  for (const owner of owners) {
    const claims = await claimsOf(ctx, owner)
    // Current-only: the active, verified claim per key. Revoked history is not served — a
    // `--refresh-keys` against a revoked key gets 404, which is the point.
    const current = claims.filter(c => !c.revokedAt && c.verification?.verified && c.pgpPublicKey)
    for (const c of current) {
      if (lookup.type === 'fingerprint' && c.fingerprint !== lookup.value) continue
      out.push(toEntry(c, owner))
    }
  }
  return out
}

function toEntry(c: Claim, owner: Address): Entry {
  const k = c.keyInfo
  const algoNum: Record<string, number> = { RSA: 1, DSA: 17, ElGamal: 16, ECDSA: 19, Ed25519: 22, EdDSA: 22, ECDH: 18 }
  return {
    fingerprint: c.fingerprint, armored: c.pgpPublicKey!, owner,
    algo: algoNum[k?.algorithm ?? ''] ?? 0, bits: (k as any)?.bits ?? 0,
    created: k?.created ? Math.floor(Date.parse(k.created) / 1000) : c.createdAt,
    expires: k?.expires ? Math.floor(Date.parse(k.expires) / 1000) : '',
    revoked: false, uids: k?.userIDs ?? [],
  }
}

function text(res: ServerResponse, status: number, body: string) {
  res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8' })
  res.end(body + '\n')
}

function log(req: IncomingMessage, msg: string) {
  const caller = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').split(',')[0].trim()
  process.stdout.write(`${new Date().toISOString()} ${caller} ${req.method} ${req.url} ${msg}\n`)
}
