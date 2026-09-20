// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { privateKeyToAccount } from 'viem/accounts'
import { recoverTypedDataAddress } from 'viem'
import { commandSigner, parseSignature, bigintReplacer, accountSigner } from '../src/lib/signer.js'
import { typedDataFor, type Handoff } from '../src/lib/handoff.js'

// anvil #0: a public test key
const acct = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80')
const REGISTRY = '0x9302E02e2869e129aC8516fE5eFFd51EA3082c09'
const h: Handoff = { v: 1, op: 'revoke', network: 'mainnet', owner: acct.address.toLowerCase(), fingerprint: 'A'.repeat(40), index: 0, includeEmail: false, authorization: { nonce: 0, deadline: 1_800_000_000, signature: '0x' } }

describe('signer hook', () => {
  it('parses what a signer might print', () => {
    const sig = '0x' + 'ab'.repeat(65)
    expect(parseSignature(sig)).toBe(sig)
    expect(parseSignature('ab'.repeat(65) + '\n')).toBe(sig)
    expect(parseSignature(`{"signature":"${sig}"}`)).toBe(sig)
    expect(() => parseSignature('0x1234')).toThrow(/65-byte/)
  })
  it('serialises typed data with bigints as decimal strings', () => {
    const typed = typedDataFor(h, 1, REGISTRY)
    const json = JSON.parse(JSON.stringify(typed, bigintReplacer))
    expect(json.message.nonce).toBe('0'); expect(json.message.deadline).toBe('1800000000'); expect(json.domain.chainId).toBe(1)
  })
  it('an external command that signs the typed data recovers to the owner', async () => {
    // The "hardware": a node one-liner reading typed data on stdin and printing a signature.
    const script = `node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',async()=>{const {privateKeyToAccount}=require('viem/accounts');const t=JSON.parse(d);t.message.nonce=BigInt(t.message.nonce);t.message.deadline=BigInt(t.message.deadline);if(t.message.index!==undefined)t.message.index=BigInt(t.message.index);const a=privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');process.stdout.write(await a.signTypedData(t))})"`
    const typed = typedDataFor(h, 1, REGISTRY)
    const sig = await commandSigner(script).signTypedData(typed)
    const who = await recoverTypedDataAddress({ ...(typed as any), signature: sig })
    expect(who.toLowerCase()).toBe(h.owner)
    // and it matches what the in-process keystore signer produces
    expect(sig).toBe(await accountSigner(acct).signTypedData(typed))
  })
  it('surfaces a failing signer', async () => {
    await expect(commandSigner('exit 3').signTypedData({})).rejects.toThrow(/exited with code 3/)
    await expect(commandSigner('echo nope').signTypedData({})).rejects.toThrow(/65-byte/)
  })
})

describe('air gap round trip', () => {
  it('sign-out carries the hand-off and the finish step reuses those exact bytes', async () => {
    const { fileSigner, readSignOut, SignLater } = await import('../src/lib/signer.js')
    const { mkdtempSync } = await import('node:fs'); const { join } = await import('node:path'); const { tmpdir } = await import('node:os')
    const path = join(mkdtempSync(join(tmpdir(), 'thurin-')), 'slip.json')
    const typed = typedDataFor(h, 1, REGISTRY)
    await expect(fileSigner(path, h).signTypedData(typed)).rejects.toBeInstanceOf(SignLater)
    const back = readSignOut(path)
    expect(back.handoff.owner).toBe(h.owner); expect(back.handoff.authorization.nonce).toBe(0)
    // what a card signs from the file recovers to the owner against the re-read typed data
    const sig = await acct.signTypedData(JSON.parse(JSON.stringify(typed, bigintReplacer)) as any)
    const who = await recoverTypedDataAddress({ ...(back.typedData as any), signature: sig })
    expect(who.toLowerCase()).toBe(h.owner)
  })
})
