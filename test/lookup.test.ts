import { describe, it, expect } from 'vitest'
import { detectLookup } from '../src/lib/chain.js'
import { attestStatement } from '../src/lib/gpg.js'

describe('detectLookup', () => {
  it('classifies each identifier', () => {
    expect(detectLookup('0xD730182053Bb2365d15B2b1bE68542c760cb7f10').type).toBe('address')
    expect(detectLookup('bendoubleu.eth').type).toBe('ens')
    expect(detectLookup('03e53d807ce38c130ed42ececd3d0d7f0c9e5fb8')).toEqual({ type: 'fingerprint', value: '03E53D807CE38C130ED42ECECD3D0D7F0C9E5FB8' })
    expect(detectLookup('0xCD3D0D7F0C9E5FB8')).toEqual({ type: 'keyId', value: 'CD3D0D7F0C9E5FB8' })
    expect(detectLookup('9D3D86E35361EF7B').type).toBe('keyId')
  })
  it('rejects junk with a usage error', () => {
    expect(() => detectLookup('hello')).toThrow(/Not an address/)
  })
})

describe('attestStatement', () => {
  it('is the exact line the registry and the app expect, lowercased', () => {
    expect(attestStatement('0xD730182053Bb2365d15B2b1bE68542c760cb7f10')).toBe('I control the Ethereum address: 0xd730182053bb2365d15b2b1be68542c760cb7f10')
  })
})
