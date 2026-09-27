import { describe, it, expect } from 'vitest'
import { requireTerminal } from '../src/commands/wallet.js'

describe('secrets only to a terminal', () => {
  it('refuses when stdout is a pipe or file', () => {
    expect(() => requireTerminal('a private key', { isTTY: false })).toThrow(/Run this yourself in a terminal/)
    expect(() => requireTerminal('a private key', {})).toThrow(/anywhere but a terminal/)
  })
  it('allows a terminal', () => {
    expect(() => requireTerminal('a private key', { isTTY: true })).not.toThrow()
  })
})
