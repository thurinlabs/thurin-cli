import { describe, it, expect, vi } from 'vitest'
import { privateKeyToAccount } from 'viem/accounts'
import { serializeErc6492Signature, type Address } from 'viem'
import { permissionSigned } from '../src/lib/permission.js'

// Public anvil test keys.
const alice = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80')
const bob = privateKeyToAccount('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d')
const safe = '0x5AfE000000000000000000000000000000000001' as Address

const typed = {
  domain: { name: 'PGPRegistry', version: '3', chainId: 1, verifyingContract: '0xFa6956c11163517249f8A67F5560a4406B519451' as Address },
  types: { Test: [{ name: 'owner', type: 'address' }, { name: 'nonce', type: 'uint256' }] },
  primaryType: 'Test' as const,
  message: { owner: alice.address, nonce: 0n },
}

function chain(code: string, answer?: string) {
  const readContract = vi.fn(async () => { if (answer === undefined) throw new Error('reverted'); return answer })
  return { client: { getCode: vi.fn(async () => code), readContract } as any, readContract }
}

describe('permissionSigned: the registry\'s rules, off-chain', () => {
  it('accepts a plain signature from the owner', async () => {
    const sig = await alice.signTypedData(typed)
    expect(await permissionSigned(chain('0x'), typed, sig, alice.address)).toEqual({ ok: true })
  })

  it('accepts a 7702 account signing with its own key, without asking the contract', async () => {
    const sig = await alice.signTypedData(typed)
    const c = chain('0xef0100' + '5a7fc11397e9a8ad41bf10bf13f22b0a63f96f6d')
    expect(await permissionSigned(c, typed, sig, alice.address)).toEqual({ ok: true })
    expect(c.readContract).not.toHaveBeenCalled()
  })

  it('names the real signer when someone else signed', async () => {
    const sig = await bob.signTypedData(typed)
    const r = await permissionSigned(chain('0x'), typed, sig, alice.address)
    expect(r.ok).toBe(false)
    expect(r.ok === false && r.signer).toBe(bob.address)
  })

  it('accepts a contract account that says the signature is its own (EIP-1271)', async () => {
    const sig = await bob.signTypedData(typed)   // e.g. one of a Safe's owners
    expect(await permissionSigned(chain('0x6080', '0x1626ba7e'), typed, sig, safe)).toEqual({ ok: true })
  })

  it('refuses when the contract account says no, or reverts', async () => {
    const sig = await bob.signTypedData(typed)
    expect((await permissionSigned(chain('0x6080', '0xffffffff'), typed, sig, safe)).ok).toBe(false)
    expect((await permissionSigned(chain('0x6080'), typed, sig, safe)).ok).toBe(false)
  })

  it('explains an ERC-6492 signature from an account not on-chain yet', async () => {
    const inner = await bob.signTypedData(typed)
    const wrapped = serializeErc6492Signature({ address: '0x0000000000000000000000000000000000000abc', data: '0x1234', signature: inner })
    const r = await permissionSigned(chain('0x'), typed, wrapped, safe)
    expect(r.ok).toBe(false)
    expect(r.ok === false && r.reason).toMatch(/isn't on-chain yet/)
  })
})
