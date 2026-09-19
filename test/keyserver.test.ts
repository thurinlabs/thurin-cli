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
