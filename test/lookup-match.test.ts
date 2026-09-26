// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { claimMatches } from '../src/lib/chain.js'

describe('claimMatches', () => {
  const v4 = { fingerprint: '08B9374FDFBEC67EFFA24E669D3D86E35361EF7B' }
  const v6 = { fingerprint: '00112233445566778899aabbccddeeff0f1e2d3c4b5a69788796a5b4c3d2e1f0' }
  it('a fingerprint names only its key, whatever the case', () => {
    expect(claimMatches(v4, { type: 'fingerprint', value: '08b9374fdfbec67effa24e669d3d86e35361ef7b' })).toBe(true)
    expect(claimMatches(v6, { type: 'fingerprint', value: '08B9374FDFBEC67EFFA24E669D3D86E35361EF7B' })).toBe(false)
  })
  it('a key ID is the last 8 bytes of a v4 fingerprint and the first 8 of a v6', () => {
    expect(claimMatches(v4, { type: 'keyId', value: '9D3D86E35361EF7B' })).toBe(true)
    expect(claimMatches(v6, { type: 'keyId', value: '0011223344556677' })).toBe(true)
    expect(claimMatches(v6, { type: 'keyId', value: '8796A5B4C3D2E1F0' })).toBe(false)
  })
  it('an address names no key', () => {
    expect(claimMatches(v4, { type: 'address', value: '0x539C7e1E454296Dc150B95a0acCC05bCa3b33538' })).toBe(true)
  })
})
