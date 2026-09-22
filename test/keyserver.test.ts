// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { hkpSearchTerm } from '../src/commands/keyserver.js'

describe('keyserver search terms', () => {
  it('accepts what gpg sends and the identifiers Thurin knows', () => {
    expect(hkpSearchTerm('0x08B9374FDFBEC67EFFA24E669D3D86E35361EF7B')).toBe('0x08B9374FDFBEC67EFFA24E669D3D86E35361EF7B')   // 0x40: tried as address, then fingerprint
    expect(hkpSearchTerm('0x9D3D86E35361EF7B')).toBe('9D3D86E35361EF7B')
    expect(hkpSearchTerm('9D3D86E35361EF7B')).toBe('9D3D86E35361EF7B')
    expect(hkpSearchTerm('thurinlabs.eth')).toBe('thurinlabs.eth')
    expect(hkpSearchTerm('0x539C7e1E454296Dc150B95a0acCC05bCa3b33538')).toBe('0x539C7e1E454296Dc150B95a0acCC05bCa3b33538')
  })
  it('refuses email and free text, by design', () => {
    for (const bad of ['hello@thurin.id', 'Thurin Labs', 'thurin', '<hello@thurin.id>', '']) expect(() => hkpSearchTerm(bad)).toThrow(/fingerprint, key ID/)
  })
})

describe('keyserver front door', () => {
  const entry = {
    fingerprint: '6E0053911942A889426C1866E34D9266098F7FE7', armored: '', algo: 22, bits: 0,
    created: Date.parse('2026-01-23') / 1000, expires: '' as const, revoked: false,
    uids: ['Ben Woodall (Ben Thurin Key) <ben@thurin.id>'], owner: '0xd32e18C735E89fA7616dF3CEAEb5E33f3280e9fe' as const,
  }
  it('prints the classic index with the claim line', async () => {
    const { indexListing } = await import('../src/commands/keyserver.js')
    const out = indexListing([entry], new Map([[entry.owner, 'ben.thurinlabs.eth']]))
    expect(out).toContain('pub   ed25519/<a href="/pks/lookup?op=get&amp;search=0x6E0053911942A889426C1866E34D9266098F7FE7">E34D9266098F7FE7</a> 2026-01-23')
    expect(out).toContain('Fingerprint=6E00 5391 1942 A889 426C  1866 E34D 9266 098F 7FE7')
    expect(out).toContain('uid   Ben Woodall (Ben Thurin Key) &lt;ben@thurin.id&gt;')
    expect(out).toContain('claimed by <a href="https://thurin.id/eth/0xd32e18C735E89fA7616dF3CEAEb5E33f3280e9fe" target="_blank" rel="noopener noreferrer">ben.thurinlabs.eth')
  })
  it('names the keyserver the request came to and the matching scheme', async () => {
    const { frontDoor } = await import('../src/commands/keyserver.js')
    const ctx = { network: 'mainnet' } as any
    const hosted = frontDoor({ headers: { host: 'keys.thurin.id', 'x-forwarded-proto': 'https' } } as any, ctx)
    expect(hosted).toContain('<h1>keys.thurin<span>.id</span></h1>')
    expect(hosted).toContain('keyserver hkps://keys.thurin.id')
    expect(hosted).toContain('>Run your own<')
    const local = frontDoor({ headers: { host: '127.0.0.1:11371' } } as any, ctx, '', 'No key found: x@y.z')
    expect(local).toContain('<h1>127.0.0.1:11371</h1>')
    expect(local).toContain('keyserver hkp://127.0.0.1:11371')
    expect(local).toContain('value=""')
    expect(local).toContain('No key found: x@y.z')
    expect(local).not.toContain('<script')
  })
})
