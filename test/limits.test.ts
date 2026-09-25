// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { Limits, LimitError } from '../src/lib/limits.js'

const cfg = { budgetEth: 0.01, perCallerPerHour: 2, attestsPerOwner: 1, maxGas: 500_000n }

describe('relayer limits', () => {
  it('lets a normal request through and records it', () => {
    const l = new Limits(cfg)
    l.check('1.2.3.4', '0xaa', 'attest', 200_000n, 0.001)
    l.record('1.2.3.4', '0xaa', 'attest', 0.001)
    expect(l.spentLast24h()).toBeCloseTo(0.001)
  })
  it('pays for one attest per owner, but still relays their updates', () => {
    const l = new Limits(cfg)
    l.record('a', '0xAA', 'attest', 0.001)
    expect(() => l.check('b', '0xaa', 'attest', 1n, 0)).toThrow(/1 attest per address/)
    expect(() => l.check('b', '0xaa', 'update-key', 1n, 0)).not.toThrow()
  })
  it('rate-limits a caller per hour and forgets after', () => {
    let t = 0
    const l = new Limits(cfg, () => t)
    l.record('ip', '0x1', 'revoke', 0); l.record('ip', '0x2', 'revoke', 0)
    expect(() => l.check('ip', '0x3', 'revoke', 1n, 0)).toThrow(LimitError)
    t = 3_600_001
    expect(() => l.check('ip', '0x3', 'revoke', 1n, 0)).not.toThrow()
    l.record('other', '0x4', 'revoke', 0)
    expect((l as any).callers.has('ip')).toBe(false)   // not just allowed again: gone from memory
  })
  it('stops at the daily budget and resets after 24 h', () => {
    let t = 0
    const l = new Limits(cfg, () => t)
    l.record('a', '0x1', 'revoke', 0.009)
    expect(() => l.check('b', '0x2', 'revoke', 1n, 0.002)).toThrow(/budget/)
    t = 86_400_001
    expect(() => l.check('b', '0x2', 'revoke', 1n, 0.002)).not.toThrow()
  })
  it('refuses a gas-burning call outright', () => {
    const l = new Limits(cfg)
    expect(() => l.check('a', '0x1', 'attest', 600_000n, 0)).toThrow(/gas/)   // cfg.maxGas is 500k here
  })
})
