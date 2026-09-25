/**
 * What a relayer refuses before it spends: a daily gas budget, one free `attest` per
 * address, and a per-caller rate. All in memory — a restart forgets, which errs toward
 * generosity and needs no database. The chain is the record of what was actually paid.
 */
export interface LimitsConfig {
  /** ETH the relayer may spend per rolling 24 h. */
  budgetEth: number
  /** Requests per caller per hour (the relay keys callers by a salted hash of the IP). */
  perCallerPerHour: number
  /** `attest` calls per owner address, ever (per process). Other ops are rate-limited only. */
  attestsPerOwner: number
  /**
   * Hard cap on gas per transaction; bounds an owner whose contract wallet burns gas in
   * isValidSignature. An attest stores the key + signature (SSTORE2, ~200 gas/byte): ~1.1M
   * for a normal key, ~5.5M at the registry's 24,000-byte limit. 6M covers every honest call.
   */
  maxGas: bigint
}

export const DEFAULT_LIMITS: LimitsConfig = { budgetEth: 0.01, perCallerPerHour: 10, attestsPerOwner: 1, maxGas: 6_000_000n }

export class LimitError extends Error {
  constructor(message: string, public status: number) { super(message) }
}

export class Limits {
  private spent: { at: number; eth: number }[] = []
  private callers = new Map<string, number[]>()
  private attests = new Map<string, number>()
  constructor(public cfg: LimitsConfig, private now: () => number = () => Date.now()) {}

  spentLast24h(): number {
    const cutoff = this.now() - 86_400_000
    this.spent = this.spent.filter(s => s.at > cutoff)
    return this.spent.reduce((a, s) => a + s.eth, 0)
  }

  /** Throws a LimitError naming the first limit hit. `estEth` is the worst-case cost of this tx. */
  check(caller: string, owner: string, op: string, gas: bigint, estEth: number) {
    if (gas > this.cfg.maxGas) throw new LimitError(`This call needs ${gas} gas; the relayer caps at ${this.cfg.maxGas}`, 403)
    const cutoff = this.now() - 3_600_000
    const recent = (this.callers.get(caller) || []).filter(t => t > cutoff)
    if (recent.length >= this.cfg.perCallerPerHour) throw new LimitError('Too many requests from this address; try again in an hour', 429)
    if (op === 'attest' && (this.attests.get(owner.toLowerCase()) || 0) >= this.cfg.attestsPerOwner) throw new LimitError(`This relayer pays for ${this.cfg.attestsPerOwner} attest per address`, 403)
    if (this.spentLast24h() + estEth > this.cfg.budgetEth) throw new LimitError('The relayer has spent its budget for today; try again tomorrow, or publish it yourself', 503)
  }

  /** Record a request that was sent (whatever it ends up costing). */
  record(caller: string, owner: string, op: string, eth: number) {
    // Callers seen only more than an hour ago are forgotten: the hourly limit is all they're for.
    const cutoff = this.now() - 3_600_000
    for (const [k, ts] of this.callers) if (!ts.some(t => t > cutoff)) this.callers.delete(k)
    this.callers.set(caller, [...(this.callers.get(caller) || []).filter(t => t > cutoff), this.now()])
    if (op === 'attest') this.attests.set(owner.toLowerCase(), (this.attests.get(owner.toLowerCase()) || 0) + 1)
    this.spent.push({ at: this.now(), eth })
  }
}
