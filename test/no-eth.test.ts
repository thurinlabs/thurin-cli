// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { notEnoughEth } from '../src/commands/attest.js'

describe('notEnoughEth', () => {
  it('no ETH on a claim: the fact, then where the docs cover claiming without', () => {
    const e = notEnoughEth('attest', 0n, 10n ** 15n)
    expect(e.message).toBe('This address has no ETH to pay the fee.\nWays to claim without ETH: thurin help no-eth  ·  https://docs.thurin.id/#/cli?id=no-eth-on-this-machine')
  })
  it('some ETH, not enough: both amounts', () => {
    expect(notEnoughEth('setRecord', 10n ** 14n, 8n * 10n ** 14n).message).toMatch(/^This address has 0.0001 ETH; the fee can be up to 0.0008\.\nWays to do this without ETH:/)
  })
  it('after a send failed for funds: no amounts to show', () => {
    expect(notEnoughEth('revoke', null, null).message).toMatch(/^This address doesn't have enough ETH to pay the fee\.\n/)
  })
  it('writes with no way round the fee get only the fact', () => {
    expect(notEnoughEth('cancelAuthorization', 0n, 1n).message).toBe('This address has no ETH to pay the fee.')
    expect(notEnoughEth('attestFor', 0n, 1n).message).toBe('This address has no ETH to pay the fee.')
  })
})
