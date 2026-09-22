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
    const browser = /text\/html/.test(req.headers.accept || '')
    if (url.pathname === '/' && browser) return html(res, 200, frontDoor(req, ctx))
    if (url.pathname === '/' || url.pathname === '/health') return text(res, 200, `thurin keyserver ${VERSION} · ${ctx.network} · HKP over the Thurin registry. GET /pks/lookup?op=get&search=0x<fingerprint>`)
    if (url.pathname !== '/pks/lookup' || req.method !== 'GET') return text(res, 404, 'not found')
    const op = url.searchParams.get('op') || 'get'
    const search = (url.searchParams.get('search') || '').trim()
    if (!search) return text(res, 400, 'search parameter required')
    if (op !== 'get' && op !== 'index' && op !== 'vindex') return text(res, 501, `op=${op} not supported`)

    // gpg sends options=mr and Accept: */*; a person arrives from the form with Accept: text/html.
    const human = browser && op !== 'get' && !/\bmr\b/.test(url.searchParams.get('options') || '')
    const miss = (msg: string) => human ? html(res, 404, frontDoor(req, ctx, '', msg === 'No key found' ? `No key found for ${search}.` : `No key for ${search}. ${msg}.`)) : text(res, 404, msg)
    let entries: Entry[]
    try { entries = await lookup(search) }
    catch (e: any) {
      if (e instanceof CliError && e.code === EXIT.USAGE) { log(req, `refused: ${e.message}`); return miss(e.message) }   // an email or a word: nothing to find by design
      if (e instanceof CliError && e.code === EXIT.FAILED) { log(req, 'not found'); return miss('No key found') }
      throw e
    }
    if (!entries.length) { log(req, 'not found'); return miss('No key found') }
    log(req, `${op} ${entries.length} key(s)`)
    if (op === 'get') {
      const body = entries.map(e => e.armored).join('\n')
      // gpg gets the keyserver media type. A browser (Accept: text/html) gets the same bytes
      // shown as text instead of a download; anything else downloads under a sensible name.
      const name = `${entries.map(e => e.fingerprint).join('+')}.asc`
      res.writeHead(200, browser
        ? { 'content-type': 'text/plain; charset=utf-8', 'cache-control': `max-age=${ttl / 1000}` }
        : { 'content-type': 'application/pgp-keys', 'content-disposition': `inline; filename="${name}"`, 'cache-control': `max-age=${ttl / 1000}` })
      res.end(body)
      return
    }
    if (human) {
      // The primary name if the address set one; else the name that was searched, which resolved here.
      const searchedName = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(search) ? search.toLowerCase() : null
      const names = new Map<string, string | null>()
      for (const e of entries) if (!names.has(e.owner)) names.set(e.owner, (await ensNameOf(ctx, e.owner)) ?? searchedName)
      return html(res, 200, frontDoor(req, ctx, search, undefined, indexListing(entries, names)))
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

function html(res: ServerResponse, status: number, body: string) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' })
  res.end(body)
}

const ALGO_NAME: Record<number, string> = { 1: 'rsa', 16: 'elg', 17: 'dsa', 18: 'ecdh', 19: 'ecdsa', 22: 'ed25519' }
const esc = (s: string) => s.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!))
const day = (t: number) => new Date(t * 1000).toISOString().slice(0, 10)
const spaced = (fpr: string) => fpr.replace(/(.{4})/g, '$1 ').trim().replace(/^(.{24}) /, '$1  ')

/**
 * The index a person sees: the listing every keyserver printed since the 1990s, one entry per
 * key, plus the line no keyserver could print — who claims it, on-chain — linking to the claim.
 */
export function indexListing(entries: Entry[], names: Map<string, string | null>): string {
  const L: string[] = []
  for (const e of entries) {
    const keyId = e.fingerprint.slice(-16)
    const algo = `${ALGO_NAME[e.algo] ?? 'pgp'}${e.algo === 1 && e.bits ? e.bits : ''}`
    const exp = e.expires ? ` [expires: ${day(e.expires)}]` : ''
    L.push(`pub   ${algo}/<a href="/pks/lookup?op=get&amp;search=0x${e.fingerprint}">${keyId}</a> ${day(e.created)}${exp}`)
    L.push(`      Fingerprint=${spaced(e.fingerprint)}`)
    for (const u of e.uids) L.push(`uid   ${esc(u)}`)
    const name = names.get(e.owner)
    const who = name ? `${esc(name)} <span class="dim">${e.owner}</span>` : e.owner
    L.push(`      claimed by <a href="https://thurin.id/eth/${e.owner}" target="_blank" rel="noopener noreferrer">${who}</a>`)
    L.push('')
  }
  return L.join('\n')
}

/** One screen, no scripts: what this is, the dirmngr line, a search box, and the results if any. */
export function frontDoor(req: IncomingMessage, ctx: ChainCtx, search = '', message?: string, listing?: string): string {
  const host = req.headers.host || 'localhost'
  const scheme = /https/.test(String(req.headers['x-forwarded-proto'] || '')) ? 'hkps' : 'hkp'
  const self = `${scheme}://${host}`
  const dotId = /\.id(:\d+)?$/.test(host)
  return `<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(host)}</title>
<style>
body { background: #1a1a12; color: #faf9f5; font-family: 'Share Tech Mono', ui-monospace, monospace; max-width: 78ch; margin: 3rem auto; padding: 0 1rem; line-height: 1.55; }
h1 { font-weight: 400; font-size: 1.6rem; margin: 0 0 1.25rem; color: #7c9a3e; }
h1 span { color: #c9a227; }
p { margin: 0 0 1.25rem; }
a { color: #96b84e; }
form { display: flex; gap: .5rem; flex-wrap: wrap; margin: 0 0 1.5rem; }
input { flex: 1 1 30ch; font: inherit; background: #141010; color: #faf9f5; border: 1px solid #3a3a2c; border-radius: 3px; padding: .45rem .6rem; }
input:focus { outline: none; border-color: #7c9a3e; }
button { font: inherit; background: #7c9a3e; color: #141010; border: 0; border-radius: 3px; padding: .45rem .9rem; cursor: pointer; }
pre.cmd { white-space: pre; overflow-x: auto; }
pre { background: #141010; border: 1px solid #3a3a2c; border-radius: 3px; padding: .9rem 1rem; margin: 0 0 1.5rem; white-space: pre-wrap; overflow-wrap: anywhere; font-size: .92rem; }
.dim { color: #a8a598; }
.note { color: #a8a598; font-size: .85rem; margin: 0 0 1.5rem; }
footer { margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid #3a3a2c; font-size: .82rem; letter-spacing: .06em; color: #a8a598; display: flex; justify-content: space-between; align-items: flex-start; gap: 2rem; flex-wrap: wrap; }
footer .version { opacity: .6; }
footer .cols { display: flex; gap: 3rem; }
footer .col { display: flex; flex-direction: column; gap: .35rem; }
footer .col b { color: #faf9f5; font-weight: 600; text-transform: uppercase; font-size: .7rem; letter-spacing: .12em; margin-bottom: .2rem; }
footer .col a { color: #a8a598; text-decoration: none; }
footer .col a:hover { color: #7c9a3e; }
</style>
<h1>${esc(dotId ? host.replace(/\.id(:\d+)?$/, '') : host)}${dotId ? '<span>.id</span>' : ''}</h1>
<p>A PGP keyserver whose database is Ethereum. A key is here because its owner published a claim from their own address on the <a href="https://docs.thurin.id/#/contracts" target="_blank" rel="noopener noreferrer">Thurin registry</a>. There is no upload, and nothing to poison: revoke the claim and the key is gone.</p>
<form action="/pks/lookup" method="get">
  <input type="hidden" name="op" value="index">
  <input name="search" value="${esc(search)}" placeholder="fingerprint, key ID, address, or ENS name" aria-label="Search" autofocus>
  <button>Search for a key</button>
</form>
${message ? `<p class="note">${esc(message)}</p>` : ''}
${listing ? `<pre>${listing}</pre>` : ''}
<p>Point gpg at it, once:</p>
<pre class="cmd">echo "keyserver ${esc(self)}" &gt;&gt; ~/.gnupg/dirmngr.conf &amp;&amp; gpgconf --kill dirmngr
gpg --recv-keys &lt;fingerprint&gt;</pre>
<footer>
  <span class="version">thurin keyserver ${VERSION} · ${ctx.network}</span>
  <div class="cols">
    <div class="col"><b>Thurin</b>
      <a href="https://thurin.id" target="_blank" rel="noopener noreferrer">Thurin.id</a>
      <a href="https://thurin.id/attest" target="_blank" rel="noopener noreferrer">Attest</a>
      <a href="https://thurinlabs.id" target="_blank" rel="noopener noreferrer">Thurin Labs</a>
    </div>
    <div class="col"><b>Keyserver</b>
      <a href="https://docs.thurin.id/#/cli?id=be-a-keyserver" target="_blank" rel="noopener noreferrer">Run your own</a>
      <a href="https://docs.thurin.id/#/guides/verify-commits" target="_blank" rel="noopener noreferrer">Verify commits</a>
      <a href="https://docs.thurin.id/#/guides/verify-release" target="_blank" rel="noopener noreferrer">Verify a release</a>
    </div>
    <div class="col"><b>Dev</b>
      <a href="https://github.com/thurinlabs/thurin-cli" target="_blank" rel="noopener noreferrer">GitHub</a>
      <a href="https://docs.thurin.id" target="_blank" rel="noopener noreferrer">Docs</a>
      <a href="https://docs.thurin.id/#/roadmap" target="_blank" rel="noopener noreferrer">Roadmap</a>
    </div>
  </div>
</footer>
`
}

function log(req: IncomingMessage, msg: string) {
  const caller = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').split(',')[0].trim()
  process.stdout.write(`${new Date().toISOString()} ${caller} ${req.method} ${req.url} ${msg}\n`)
}
