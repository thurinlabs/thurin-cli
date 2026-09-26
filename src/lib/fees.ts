import type { PublicClient } from 'viem'

/** Never tip less than this: many nodes suggest 0, and a zero-tip transaction waits for spare room. */
export const MIN_TIP = 50_000_000n // 0.05 gwei

/** The median of what recent blocks actually tipped (their 50th-percentile rewards), never below `floor`. */
export function pickTip(rewards: readonly (readonly bigint[])[], floor: bigint = MIN_TIP): bigint {
  const tips = rewards.map(r => r[0]).filter((t): t is bigint => typeof t === 'bigint').sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
  const median = tips.length ? tips[Math.floor(tips.length / 2)] : 0n
  return median > floor ? median : floor
}

/**
 * EIP-1559 fees for the next transaction: the tip from the last 20 blocks, and a max fee of twice the
 * base fee plus the tip, so a rising base fee can't strand it (only base fee + tip is charged). Null
 * where the chain can't say (a local chain without fee history): viem's own estimate is used then.
 */
export async function feesFor(client: PublicClient): Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint; expected: bigint } | null> {
  try {
    const [block, history] = await Promise.all([
      client.getBlock({ blockTag: 'latest' }),
      client.getFeeHistory({ blockCount: 20, rewardPercentiles: [50] }),
    ])
    if (block.baseFeePerGas == null) return null
    const tip = pickTip(history.reward ?? [])
    return { maxFeePerGas: block.baseFeePerGas * 2n + tip, maxPriorityFeePerGas: tip, expected: block.baseFeePerGas + tip }
  } catch {
    return null
  }
}
