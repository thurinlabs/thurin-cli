import { hashTypedData, recoverTypedDataAddress, isErc6492Signature, type Address, type Hex } from 'viem'
import type { ChainCtx } from './chain.js'

const ERC1271_MAGIC = '0x1626ba7e'
const ERC1271_ABI = [{
  type: 'function', name: 'isValidSignature', stateMutability: 'view',
  inputs: [{ name: 'hash', type: 'bytes32' }, { name: 'signature', type: 'bytes' }],
  outputs: [{ name: '', type: 'bytes4' }],
}] as const

export type PermissionCheck = { ok: true } | { ok: false; reason: string; signer?: Address }

/**
 * Is `signature` a permission from `owner`? Checked the way the registry checks it: a plain
 * signature from the owner's key (any address, 7702 accounts included), else, for an account with
 * code (a Safe, a smart-account wallet), the account's own answer (EIP-1271).
 */
export async function permissionSigned(ctx: Pick<ChainCtx, 'client'>, typed: any, signature: Hex, owner: Address): Promise<PermissionCheck> {
  const code = await ctx.client.getCode({ address: owner }).catch(() => undefined)
  const deployed = !!code && code !== '0x'

  // ERC-6492 wraps a signature from an account that isn't on-chain yet. The registry asks the
  // deployed account, so it can't accept one; the account has to exist first.
  if (isErc6492Signature(signature)) {
    return { ok: false, reason: deployed
      ? 'This signature was made before the account was on-chain. Sign again, now that it is'
      : "This smart account isn't on-chain yet, so the registry can't check its signature. Send any transaction from it first (that creates it), then sign again" }
  }

  const signer = await recoverTypedDataAddress({ ...typed, signature }).catch(() => undefined)
  if (signer && signer.toLowerCase() === owner.toLowerCase()) return { ok: true }

  if (deployed) {
    const answer = await ctx.client.readContract({
      address: owner, abi: ERC1271_ABI, functionName: 'isValidSignature', args: [hashTypedData(typed), signature],
    } as any).catch(() => undefined)
    if (answer === ERC1271_MAGIC) return { ok: true }
    return { ok: false, reason: `The account ${owner} doesn't accept this signature as its own` }
  }
  return { ok: false, reason: signer ? `The signature is from ${signer}, not ${owner}` : "The signature can't be read", signer }
}
