// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { privateKeyToAccount } from 'viem/accounts'
import { recoverTypedDataAddress } from 'viem'
import {
  encodeHandoff, decodeHandoff, handoffUrl, readHandoffInput, typedDataFor, forArgsOf, parseDeadline, type Handoff,
} from '../src/lib/handoff.js'

const h: Handoff = {
  v: 2, op: 'attest', network: 'mainnet',
  owner: '0xd730182053bb2365d15b2b1be68542c760cb7f10',
  fingerprint: '03E53D807CE38C130ED42ECECD3D0D7F0C9E5FB8',
  key: '0xc60b0400000000160900000000',
  signature: '0xc20b0401160a00000000000000',
  includeEmail: false,
}
const REGISTRY = '0x4f2d70799cAAD651C7c564426AA74A842c1331B6'
// Hardhat/anvil account #0 — a well-known test key, never funded on a real network.
const acct = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80')

describe('hand-off link', () => {
  it('round-trips through base64url', () => {
    expect(decodeHandoff(encodeHandoff(h))).toEqual(h)
  })
  it('lands the payload in the fragment, with nothing URL-unsafe in it', () => {
    const url = handoffUrl('https://thurin.id/', h)
    expect(url.startsWith('https://thurin.id/attest#handoff=')).toBe(true)
    expect(url.split('#')[1]).toMatch(/^handoff=[A-Za-z0-9_-]+$/)
    expect(readHandoffInput(url)).toEqual(h)
  })
  it('refuses anything that is not a hand-off', () => {
    expect(() => decodeHandoff(Buffer.from('{"v":2}').toString('base64url'))).toThrow(/Not a Thurin hand-off/)
    expect(() => decodeHandoff(encodeHandoff({ ...h, v: 1 } as any))).toThrow(/format 1/)
    expect(() => decodeHandoff(encodeHandoff({ ...h, key: '-----BEGIN PGP PUBLIC KEY BLOCK-----' }))).toThrow(/no key/)
    expect(() => decodeHandoff(encodeHandoff({ ...h, op: 'revoke', index: 0, reason: 'lost' as any }))).toThrow(/revoke reason/)
    expect(() => decodeHandoff(encodeHandoff({ ...h, authorization: { nonce: 0, deadline: 1, signature: '0x12' } }))).toThrow(/malformed authorization/)
    expect(() => readHandoffInput('what')).toThrow(/hand-off/)
  })
})

describe('authorization', () => {
  it('signs typed data the registry can recover, for every op', async () => {
    const owner = acct.address.toLowerCase()
    const base = { ...h, owner, authorization: { nonce: 3, deadline: 1_800_000_000, signature: '0x' as `0x${string}` } }
    const cases: Handoff[] = [
      { ...base, op: 'attest' },
      { ...base, op: 'reattest', index: 1, keepRecords: false },
      { ...base, op: 'update-key', index: 0, signature: undefined },
      { ...base, op: 'revoke', index: 2, key: undefined, signature: undefined, reason: 'compromised' },
      { ...base, op: 'set-record', index: 0, key: undefined, signature: undefined, kind: 'security', value: 'mailto:x@example.com' },
    ]
    for (const c of cases) {
      const typed = typedDataFor(c, 1, REGISTRY)
      const sig = await acct.signTypedData(typed as any)
      const signer = await recoverTypedDataAddress({ ...(typed as any), signature: sig })
      expect(signer.toLowerCase()).toBe(owner)
      const args = forArgsOf({ ...c, authorization: { ...c.authorization!, signature: sig } })
      expect(args[0]).toBe(owner)
      expect(args[args.length - 1]).toBe(sig)
      expect(args[args.length - 2]).toBe(1_800_000_000n)
    }
    const re = forArgsOf({ ...cases[1], authorization: { ...cases[1].authorization!, signature: '0x' } })
    expect(re[5]).toBe(false)                              // keepRecords
    const rv = forArgsOf({ ...cases[3], authorization: { ...cases[3].authorization!, signature: '0x' } })
    expect(rv[2]).toBe('compromised')
  })
  it('binds the chain: a Sepolia signature does not recover on mainnet', async () => {
    const c: Handoff = { ...h, owner: acct.address.toLowerCase(), authorization: { nonce: 0, deadline: 1_800_000_000, signature: '0x' } }
    const sig = await acct.signTypedData(typedDataFor(c, 11155111, REGISTRY) as any)
    const signer = await recoverTypedDataAddress({ ...(typedDataFor(c, 1, REGISTRY) as any), signature: sig })
    expect(signer.toLowerCase()).not.toBe(c.owner)
  })
  it('parses deadlines', () => {
    const now = Math.floor(Date.now() / 1000)
    expect(parseDeadline(undefined)).toBeGreaterThanOrEqual(now + 7 * 86400 - 1)
    expect(parseDeadline('90m')).toBeGreaterThanOrEqual(now + 5400 - 1)
    expect(parseDeadline('1800000000')).toBe(1_800_000_000)
    expect(() => parseDeadline('soon')).toThrow(/Bad deadline/)
  })
})
