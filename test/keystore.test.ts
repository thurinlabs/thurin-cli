import { describe, it, expect } from 'vitest'
import { encryptKeystore, decryptKeystore, parseMnemonicOrKey } from '../src/lib/keystore.js'
import { privateKeyToAccount } from 'viem/accounts'

const PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const // anvil #0, public

describe('V3 keystore', () => {
  it('round-trips a private key through encrypt/decrypt', () => {
    const ks = encryptKeystore(PK, 'hunter2')
    expect(ks.version).toBe(3)
    expect(ks.address).toBe(privateKeyToAccount(PK).address.slice(2).toLowerCase())
    expect(decryptKeystore(ks, 'hunter2')).toBe(PK)
  })
  it('rejects the wrong password by MAC, not by garbage output', () => {
    const ks = encryptKeystore(PK, 'hunter2')
    expect(() => decryptKeystore(ks, 'hunter3')).toThrow(/Wrong password/)
  })
  it('parses a hex private key with or without 0x', () => {
    expect(parseMnemonicOrKey(PK.slice(2)).account.address).toBe(privateKeyToAccount(PK).address)
    expect(parseMnemonicOrKey(PK).kind).toBe('privateKey')
  })
  it('parses a mnemonic', () => {
    const m = 'test test test test test test test test test test test junk'
    const r = parseMnemonicOrKey(m)
    expect(r.kind).toBe('mnemonic')
    expect(r.account.address).toBe('0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266')
  })
  it('refuses anything else', () => {
    expect(() => parseMnemonicOrKey('not a key')).toThrow()
  })
}, 30000)
