import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import { createWalletClient, http, formatEther, type Address } from 'viem'
import { REGISTRY_ABI } from '@thurinlabs/identity-kit/core'
import { chainCtx, type ChainCtx } from '../lib/chain.js'
import { loadAccount } from '../lib/keystore.js'
import { prompt } from '../lib/prompt.js'
import { decodeHandoff, encodeHandoff, forArgsOf, FOR_FN, type Handoff } from '../lib/handoff.js'
import { checkAuthorization } from './attest.js'
import { Limits, LimitError, DEFAULT_LIMITS } from '../lib/limits.js'
import { CliError, EXIT, ok, warn, bold, dim, label } from '../lib/output.js'

/**
 * thurin relay — `thurin submit` behind an HTTP port. Accepts the same JSON a hand-off
 * link carries, runs the same checks, applies a budget and rate limits, and pays for the
 * `…For` call from a hot keystore. Anyone can run one; Thurin runs one with a small budget.
 *
 * This is the one command that spends unattended. It spends gas only, within the budget
 * you set, from a key you should treat as pocket money.
 */

const MAX_BODY = 64 * 1024   // a hand-off is ~2–12 KB; the registry caps the key at 8 KB anyway

export async function relay(_args: string[], opts: Record<string, any>) {
  const ctx = chainCtx(opts)
  const account = await loadAccount(opts, q => prompt(q, true))
  const limits = new Limits({
    budgetEth: opts.budget !== undefined ? Number(opts.budget) : DEFAULT_LIMITS.budgetEth,
    perCallerPerHour: opts.perHour !== undefined ? Number(opts.perHour) : DEFAULT_LIMITS.perCallerPerHour,
    attestsPerOwner: opts.freeAttests !== undefined ? Number(opts.freeAttests) : DEFAULT_LIMITS.attestsPerOwner,
    maxGas: opts.maxGas !== undefined ? BigInt(opts.maxGas) : DEFAULT_LIMITS.maxGas,
  })
  if (!(limits.cfg.budgetEth > 0)) throw new CliError('--budget must be a positive amount of ETH per day', EXIT.USAGE)
  const host: string = opts.host || '127.0.0.1'
  const port = Number(opts.port || 8787)
  const wallet = createWalletClient({ account, chain: ctx.client.chain, transport: http(ctx.rpcUrl) })

  const balance = await ctx.client.getBalance({ address: account.address })
  process.stderr.write(`${ok('thurin relay')} on ${ctx.network} · paying from ${bold(account.address)} (${formatEther(balance)} ETH)\n` +
    `${label('budget')}${limits.cfg.budgetEth} ETH/day · ${limits.cfg.attestsPerOwner} free attest per address · ${limits.cfg.perCallerPerHour} requests/hour per caller · ≤ ${limits.cfg.maxGas} gas/tx\n` +
    `${label('listen')}http://${host}:${port}  ${dim('(put nginx or another TLS proxy in front)')}\n`)
  if (balance === 0n) warn('The paying account holds no ETH; every request will fail until it is funded.')

  // One transaction at a time: a hot wallet with concurrent sends races its own nonce.
  let chain: Promise<unknown> = Promise.resolve()
  const serial = <T,>(fn: () => Promise<T>) => { const p = chain.then(fn, fn); chain = p.catch(() => {}); return p }

  const server = createServer((req, res) => handle(req, res).catch(e => reply(res, 500, { error: e.message })))
  async function handle(req: IncomingMessage, res: ServerResponse) {
    res.setHeader('access-control-allow-origin', '*')
    res.setHeader('access-control-allow-headers', 'content-type')
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return }
    if (req.method === 'GET') {
      return reply(res, 200, { ok: true, network: ctx.network, payer: account.address, budgetEth: limits.cfg.budgetEth, spentTodayEth: limits.spentLast24h(), freeAttestsPerOwner: limits.cfg.attestsPerOwner })
    }
    if (req.method !== 'POST') return reply(res, 405, { error: 'POST a hand-off with an authorization' })
    const caller = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '?').split(',')[0].trim()
    const raw = await readBody(req)
    let h: Handoff
    try { h = decodeHandoff(encodeHandoff(JSON.parse(raw))) } catch (e: any) { return reply(res, 400, { error: `Not a hand-off: ${e.message}` }) }
    if (h.network !== ctx.network) return reply(res, 400, { error: `This relayer publishes to ${ctx.network}; the authorization is for ${h.network}` })
    if (!h.authorization) return reply(res, 400, { error: 'No authorization: only the owner can publish this' })

    const t0 = Date.now()
    try {
      const result = await serial(async () => {
        const { owner, proofs } = await checkAuthorization(ctx, h)
        const fn = FOR_FN[h.op], args = forArgsOf(h)
        const gas = await ctx.client.estimateContractGas({ address: ctx.registry, abi: REGISTRY_ABI, functionName: fn, args, account } as any)
          .catch((e: any) => { throw new CliError(`The registry would reject this: ${e.shortMessage || e.message}`, EXIT.CHAIN) })
        const price = await ctx.client.getGasPrice()
        const estEth = Number(gas * price * 12n / 10n) / 1e18   // 20 % headroom for a price move
        limits.check(caller, owner, h.op, gas, estEth)
        limits.record(caller, owner, h.op, estEth)
        const hash = await wallet.writeContract({ address: ctx.registry, abi: REGISTRY_ABI, functionName: fn, args, account, chain: ctx.client.chain } as any)
        const receipt = await ctx.client.waitForTransactionReceipt({ hash })
        if (receipt.status !== 'success') throw new CliError(`Transaction reverted: ${hash}`, EXIT.CHAIN)
        return { hash, block: receipt.blockNumber.toString(), owner, op: h.op, proofs, payer: account.address as Address, identity: `https://thurin.id/eth/${owner}` }
      })
      log(caller, h, `ok ${result.hash} ${Date.now() - t0}ms`)
      reply(res, 200, result)
    } catch (e: any) {
      const status = e instanceof LimitError ? e.status : e instanceof CliError ? (e.code === EXIT.CHAIN ? 502 : 400) : 500
      log(caller, h, `refused ${status}: ${e.message}`)
      reply(res, status, { error: e.message })
    }
  }

  server.listen(port, host)
  await new Promise<void>(resolve => { for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, () => { server.close(); resolve() }) })
}

function log(caller: string, h: Handoff, msg: string) {
  process.stdout.write(`${new Date().toISOString()} ${caller} ${h.op} ${h.owner} ${msg}\n`)
}

function reply(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(JSON.stringify(body) + '\n')
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks: Buffer[] = []
    req.on('data', (c: Buffer) => { size += c.length; if (size > MAX_BODY) { reject(new Error('Body too large')); req.destroy() } else chunks.push(c) })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}
