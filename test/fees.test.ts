// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { pickTip, MIN_TIP } from '../src/lib/fees.js'

const gwei = (n: number) => BigInt(Math.round(n * 1e9))

describe('pickTip', () => {
  it('uses the median of what recent blocks tipped', () => {
    expect(pickTip([[gwei(0.06)], [gwei(0.07)], [gwei(0.2)], [gwei(0.07)], [gwei(0.08)]])).toBe(gwei(0.07))
  })
  it('never goes below the floor, even when blocks tipped nothing', () => {
    expect(pickTip([[0n], [0n], [gwei(0.001)]])).toBe(MIN_TIP)
    expect(pickTip([])).toBe(MIN_TIP)
  })
  it('takes a custom floor', () => {
    expect(pickTip([[0n]], gwei(0.1))).toBe(gwei(0.1))
  })
})
