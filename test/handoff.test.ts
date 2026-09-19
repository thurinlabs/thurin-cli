// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { encodeHandoff, decodeHandoff, handoffUrl, type Handoff } from '../src/lib/handoff.js'

const h: Handoff = {
  v: 1, op: 'attest', network: 'mainnet',
  owner: '0xd730182053bb2365d15b2b1be68542c760cb7f10',
  fingerprint: '03E53D807CE38C130ED42ECECD3D0D7F0C9E5FB8',
  key: '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZ…\n-----END PGP PUBLIC KEY BLOCK-----\n',
  signature: '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nI control the Ethereum address: 0xd730182053bb2365d15b2b1be68542c760cb7f10\n-----BEGIN PGP SIGNATURE-----\n…\n-----END PGP SIGNATURE-----\n',
  includeEmail: false,
}

describe('hand-off link', () => {
  it('round-trips through base64url', () => {
    expect(decodeHandoff(encodeHandoff(h))).toEqual(h)
  })
  it('lands the payload in the fragment, with nothing URL-unsafe in it', () => {
    const url = handoffUrl('https://thurin.id/', h)
    expect(url.startsWith('https://thurin.id/attest#handoff=')).toBe(true)
    expect(url.split('#')[1]).toMatch(/^handoff=[A-Za-z0-9_-]+$/)
    expect(new URL(url).hash.length).toBeGreaterThan(100)
  })
  it('refuses anything that is not a hand-off', () => {
    expect(() => decodeHandoff(Buffer.from('{"v":2}').toString('base64url'))).toThrow(/Not a Thurin hand-off/)
  })
})
