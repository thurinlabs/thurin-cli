import { toHex, encodeFunctionData, isAddress, getAddress, recoverTypedDataAddress, type Address } from 'viem'
import { writeFileSync, readFileSync } from 'node:fs'
import { normalize } from 'viem/ens'
import {
  REGISTRY_ABI, parsePgpKey, verifyAttestation, leanKey, claimSignature, signatureEmail, identifyProof, fingerprintToBytes, OWNER_REVOKE_REASONS,
  type RevokeReason,
} from '@thurinlabs/identity-kit/core'
import { chainCtx, claimsOf, readRegistry, type ChainCtx } from '../lib/chain.js'
import { findKey, detachSign, exportMinimal, attestStatement, MAKE_KEY_HINT, addNameHint } from '../lib/gpg.js'
import { loadAccount } from '../lib/keystore.js'
import { accountSigner, commandSigner, fileSigner, providedSigner, readSignatureFile, readSignOut, SignLater, type Signer } from '../lib/signer.js'
import { prompt, confirm } from '../lib/prompt.js'
import { offerToOpen } from '../lib/open.js'
import { readConfig } from '../lib/config.js'
import { out, info, ok, bad, dim, bold, label, isJson, CliError, EXIT } from '../lib/output.js'
import {
  handoffUrl, readHandoffInput, typedDataFor, forArgsOf, payloadArg, parseDeadline, describeDeadline, FOR_FN,
  type Handoff, type HandoffOp,
} from '../lib/handoff.js'

const MAX_KEY = 16384, MAX_SIG = 8192, MAX_PAYLOAD = 24000   // the registry's limits

/**
 * --key-file / --statement-file: the PGP half was done somewhere gpg on this machine can't reach
 * (a card behind a QR link, an air-gapped box, a phone). Take the bytes; every check still runs.
 * Either file may be armored or binary; the statement may be a detached signature or clearsigned.
 */
export interface PresignedInputs { key: string | Uint8Array; signature?: string | Uint8Array }

export function presignedInputs(opts: Record<string, any>): PresignedInputs | null {
  if (!opts.keyFile && !opts.statementFile) return null
  if (!opts.keyFile) throw new CliError('--statement-file needs --key-file <pub.gpg>: the public key the statement was signed with', EXIT.USAGE)
  const read = (path: string): string | Uint8Array => {
    let b: Buffer
    try { b = readFileSync(path) } catch (e: any) { throw new CliError(`Cannot read ${path}: ${e.message}`, EXIT.USAGE) }
    return b[0] === 0x2d ? b.toString('utf8').trim() : new Uint8Array(b)   // '-': armored text
  }
  const key = read(opts.keyFile)
  if (!opts.statementFile) return { key }
  return { key, signature: read(opts.statementFile) }
}

/** The fingerprint a run is about: from gpg, or from the key file when the key is not here. */
async function keyFor(opts: Record<string, any>, pre: PresignedInputs | null): Promise<string> {
  if (!pre) return (await findKey(opts.key || readConfig().key || '')).fingerprint
  const info_ = await parsePgpKey(pre.key)
  if (!info_) throw new CliError(`${opts.keyFile} does not parse as a PGP public key (gpg --export <fpr> > pub.gpg)`, EXIT.FAILED)
  const fpr = info_.fingerprint.toUpperCase()
  const wanted = String(opts.key || '').replace(/^0x/i, '').replace(/\s/g, '').toUpperCase()   // only an explicit --key; a configured default would false-alarm
  if (wanted && !fpr.endsWith(wanted)) throw new CliError(`${opts.keyFile} holds ${fpr}, not --key ${opts.key}`, EXIT.USAGE)
  return fpr
}

const byteLength = (v: string | Uint8Array) => typeof v === 'string' ? new TextEncoder().encode(v).length : v.length

/**
 * Everything the registry and a lookup will check, run before any gas is spent. The key goes
 * on-chain lean (raw bytes, emails left out unless asked, SSH-only subkeys left out) and the
 * signature as its raw packet: exactly what thurin.id publishes.
 */
export async function preflight(ctx: ChainCtx, owner: Address, fpr: string, includeEmail: boolean, needSignature: boolean, source: PresignedInputs | null = null) {
  const full = source ? source.key : await exportMinimal(fpr)
  const lean = await leanKey(full, { includeEmail })
  if (!lean) throw new CliError(`Every name on ${fpr} contains an email, or carries a notation that does. Add one without: ${addNameHint(fpr)}. Or pass --include-email.`, EXIT.FAILED)
  if (lean.keyNotationEmails.length) throw new CliError(`A notation on the key itself holds an email (${lean.keyNotationEmails.join(', ')}), and it would go on-chain for good. Remove it with gpg, or pass --include-email.`, EXIT.FAILED)
  const info_ = await parsePgpKey(lean.binary)
  if (!info_) throw new CliError(source ? "The key file can't be read as a PGP key" : `gpg's export of ${fpr} can't be read. Check it: gpg --export ${fpr} | gpg --list-packets`, EXIT.FAILED)
  if (info_.fingerprint.toUpperCase() !== fpr.toUpperCase()) throw new CliError(`${source ? 'The key file' : "gpg's export"} holds a different key than ${fpr}. Check --key`, EXIT.FAILED)
  const proofs = info_.notations.map(identifyProof).filter(Boolean)
  // Everything else on the published names goes on-chain too, so the summary shows it.
  const otherNotes = info_.notations.filter(n => !identifyProof(n)).map(n => `${n.name}=${n.value}`)
  if (lean.binary.length > MAX_KEY) throw new CliError(`Key is ${lean.binary.length} bytes; the registry accepts up to ${MAX_KEY}. Drop old names or subkeys with gpg`, EXIT.FAILED)
  let signature: string | null = null   // 0x hex, or a clearsigned message kept whole
  let sigBytes = 0
  if (needSignature) {
    let raw: string | Uint8Array
    if (source) {
      if (!source.signature) throw new CliError(`The signature is needed too: --statement-file <sig>. The line to sign: thurin attest --statement --owner ${owner}`, EXIT.USAGE)
      raw = source.signature
    } else {
      info(`Signing "${attestStatement(owner)}" with ${fpr} (gpg may ask for your passphrase).`)
      raw = await detachSign(fpr, attestStatement(owner))
    }
    const cs = await claimSignature({ signature: raw, key: lean.binary, address: owner })
    if (!cs) throw new CliError(`${source ? 'The statement file' : 'The signature'} is not a PGP signature`, EXIT.FAILED)
    const signedEmail = await signatureEmail(raw)
    if (signedEmail && !includeEmail) throw new CliError(`The signature carries your email (${signedEmail}); gpg adds it when told the key by email or name, or when gpg.conf sets sender. It would go on-chain for good. Sign again with --disable-signer-uid${source ? `: printf '%s' '${attestStatement(owner)}' | gpg --detach-sign --textmode --disable-signer-uid -u ${fpr}` : ''}. Or pass --include-email.`, EXIT.FAILED)
    signature = typeof cs.signature === 'string' ? cs.signature : toHex(cs.signature)
    sigBytes = byteLength(cs.signature)
    if (sigBytes > MAX_SIG) throw new CliError(`Signature is ${sigBytes} bytes; the registry accepts up to ${MAX_SIG}. Sign again with an ordinary key`, EXIT.FAILED)
    if (sigBytes + lean.binary.length > MAX_PAYLOAD) throw new CliError(`Key and signature are ${sigBytes + lean.binary.length} bytes together; the registry accepts up to ${MAX_PAYLOAD}. Drop old names or subkeys with gpg`, EXIT.FAILED)
    const v = await verifyAttestation({ pgpPublicKey: lean.binary, pgpSignature: cs.signature, fingerprint: fpr, ethAddress: owner })
    if (!v.verified) throw new CliError(`The signature does not verify against the ${source ? 'given' : 'exported'} key: ${v.reason}${source ? `\nSign exactly this line, with no line break after it: printf '%s' '${attestStatement(owner)}' | gpg --detach-sign --textmode --disable-signer-uid -u ${fpr}` : ''}`, EXIT.FAILED)
  }
  return { key: toHex(lean.binary), signature, kept: lean.kept, removed: lean.removed, proofs: proofs.length, otherNotes, bytes: lean.binary.length + sigBytes }
}

function summary(p: Awaited<ReturnType<typeof preflight>>) {
  return `${label('names')}${p.kept.join(', ')}${p.removed.length ? dim(`  (left out: ${p.removed.join(', ')})`) : ''}\n${label('proofs')}${p.proofs}\n${p.otherNotes.length ? `${label('notations')}${p.otherNotes.join('\n' + ' '.repeat(12))}\n` : ''}${label('size')}${(p.bytes / 1024).toFixed(1)} KB`
}

export async function send(ctx: ChainCtx, opts: Record<string, any>, functionName: string, args: unknown[], what: string, target?: { address: Address; abi: unknown }) {
  const account = await accountFor(opts)
  const to = target ?? { address: ctx.registry, abi: REGISTRY_ABI }   // the registry unless a caller names another contract (ens link writes a resolver)
  const { createWalletClient, http } = await import('viem')
  const wallet = createWalletClient({ account, chain: ctx.client.chain, transport: http(ctx.rpcUrl) })
  const gas = await ctx.client.estimateContractGas({ address: to.address, abi: to.abi, functionName, args, account } as any).catch((e: any) => { throw new CliError(`The registry would refuse this (${what.replace(/\.$/, '')}): ${e.shortMessage || e.message}`, EXIT.CHAIN) })
  const price = await ctx.client.getGasPrice()
  const eth = Number(gas * price) / 1e18
  if (!opts.yes && !isJson() && !(await confirm(`${what.replace(/\.$/, '')}.\n${dim(`From ${account.address} on ${ctx.network} · ~${gas.toLocaleString('en-US')} gas · ~${eth.toFixed(6)} ETH.`)} Send?`))) throw new CliError('Cancelled', EXIT.USAGE)
  const hash = await wallet.writeContract({ address: to.address, abi: to.abi, functionName, args, account, chain: ctx.client.chain } as any)
  info(`Sent ${hash}. Waiting for confirmation…`)
  const receipt = await ctx.client.waitForTransactionReceipt({ hash })
  if (receipt.status !== 'success') throw new CliError(`The transaction failed, so nothing changed: ${hash}`, EXIT.CHAIN)
  return { hash, block: receipt.blockNumber, gasUsed: receipt.gasUsed, account: account.address }
}

/** The identity page for this network, or null when there's no site for it (e.g. local without --site). */
function identityUrl(ctx: ChainCtx, owner: Address) { return ctx.site ? `${ctx.site}/eth/${owner}` : null }
/** The "identity" line of a result, or nothing when there's no page to link. */
function identityLine(ctx: ChainCtx, owner: Address) { const u = identityUrl(ctx, owner); return u ? `\n${label('identity')}${u}` : '' }
function txUrl(ctx: ChainCtx, hash: string) { return ctx.explorerUrl ? `${ctx.explorerUrl}/tx/${hash}` : hash }

export async function ownerFor(ctx: ChainCtx, opts: Record<string, any>): Promise<Address> {
  if (opts.noKey && opts.authorize) throw new CliError('Pick one: --no-key (your ETH wallet is elsewhere) or --authorize (no ETH here)', EXIT.USAGE)
  if (opts.noKey || externalSigner(opts)) {
    // Hand-off, or an external signer: the key lives elsewhere, so the address is given, not derived.
    const given: string = opts.owner || ''
    if (!given) throw new CliError(`${opts.noKey ? '--no-key' : '--signer / --sign-out / --signature'} needs --owner <address|ens>: the address the claim is for`, EXIT.USAGE)
    if (isAddress(given)) return getAddress(given)
    if (!given.endsWith('.eth')) throw new CliError(`--owner must be an address or an ENS name, not "${given}"`, EXIT.USAGE)
    const resolved = await ctx.client.getEnsAddress({ name: normalize(given) }).catch((e: any) => { throw new CliError(`ENS lookup failed for ${given}: ${e.shortMessage || e.message}`, EXIT.CHAIN) })
    if (!resolved) throw new CliError(`${given} does not resolve to an address on ${ctx.network}`, EXIT.FAILED)
    info(`${given} → ${resolved}`)
    return resolved
  }
  // The address the claim is published from = the paying (or, with --authorize, signing) account.
  return (await accountFor(opts)).address
}

function externalSigner(opts: Record<string, any>): boolean { return !!(opts.signer || opts.signOut || opts.signature || opts.signatureFile || opts.signIn) }

/**
 * Who signs an EIP-712 authorization. Thurin builds the typed data and hands it over; the
 * recovery and simulation checks afterwards are the same whoever signed.
 */
async function signerFor(opts: Record<string, any>, handoff: unknown): Promise<Signer> {
  const n = [opts.signer, opts.signOut, opts.signature, opts.signatureFile].filter(Boolean).length
  if (n > 1) throw new CliError('Pick one of --signer, --sign-out, --signature, --signature-file', EXIT.USAGE)
  if (opts.signer) return commandSigner(opts.signer)
  if (opts.signOut) return fileSigner(opts.signOut, handoff)
  if (opts.signature) return providedSigner(opts.signature)
  if (opts.signatureFile) return providedSigner(readSignatureFile(opts.signatureFile))
  return accountSigner(await accountFor(opts))
}

/**
 * thurin authorize finish <sign-out file> --signature 0x… | --signature-file f
 * The second half of the air gap: the typed data and hand-off come from the file --sign-out
 * wrote (same PGP bytes, same nonce, same deadline), only the signature is new.
 */
export async function finishAuthorization(args: string[], opts: Record<string, any>) {
  if (!args[0]) throw new CliError('Usage: thurin authorize finish <sign-out.json> (--signature 0x… | --signature-file f)', EXIT.USAGE)
  if (!opts.signature && !opts.signatureFile) throw new CliError('Give the signature: --signature 0x… or --signature-file f', EXIT.USAGE)
  const { typedData, handoff: h } = readSignOut(args[0])
  const ctx = chainCtx({ ...opts, network: h.network })
  const owner = getAddress(h.owner)
  h.authorization.signature = opts.signature ? await providedSigner(opts.signature).signTypedData(typedData) : readSignatureFile(opts.signatureFile)
  const recovered = await recoverTypedDataAddress({ ...(typedData as any), signature: h.authorization.signature })
  if (recovered.toLowerCase() !== owner.toLowerCase()) throw new CliError(`The signature is from ${recovered}, not ${owner}, so it won't be handed out`, EXIT.FAILED)
  const nonce = Number(await ctx.client.readContract({ address: ctx.registry, abi: REGISTRY_ABI, functionName: 'nonces', args: [owner] } as any))
  if (nonce !== h.authorization.nonce) throw new CliError(`${owner} has published something since this file was made. Start over with --sign-out`, EXIT.FAILED)
  await ctx.client.simulateContract({ address: ctx.registry, abi: REGISTRY_ABI, functionName: FOR_FN[h.op as HandoffOp], args: forArgsOf(h), account: owner } as any)
    .catch((e: any) => { throw new CliError(`The registry would refuse this permission: ${e.shortMessage || e.message}`, EXIT.CHAIN) })
  await emitAuthorized(ctx, opts, h, owner)
}

/** The keystore is unlocked once per run; the address is needed early and the key later. */
async function accountFor(opts: Record<string, any>) {
  if (!opts._account) opts._account = await loadAccount(opts, q => prompt(q, true))
  return opts._account as Awaited<ReturnType<typeof loadAccount>>
}

/**
 * --no-key: print a thurin.id/attest link instead of sending. The signed statement and
 * the key ride in the URL fragment; the page reads them and asks the connected wallet
 * to publish. Nothing is sent from here, so no account, password, or gas is needed.
 */
type Preflight = Awaited<ReturnType<typeof preflight>>

function buildHandoff(ctx: ChainCtx, opts: Record<string, any>, op: HandoffOp, owner: Address, fpr: string, p: Preflight | null, index?: number): Handoff {
  return {
    v: 2, op, network: ctx.network, owner: owner.toLowerCase(), fingerprint: fpr.toUpperCase(),
    ...(p ? { key: p.key } : {}),
    includeEmail: !!opts.includeEmail,
    ...(p?.signature ? { signature: p.signature } : {}),
    ...(index !== undefined ? { index } : {}),
    ...(op === 'reattest' ? { keepRecords: !opts.dropRecords } : {}),
    ...(op === 'revoke' ? { reason: revokeReason(opts) } : {}),
    ...(opts._record ? { kind: opts._record.kind, value: opts._record.value } : {}),
  }
}

function siteFor(opts: Record<string, any>): string { return opts.site || readConfig().site || 'https://thurin.id' }

export async function handoff(ctx: ChainCtx, opts: Record<string, any>, op: HandoffOp, owner: Address, fpr: string, p: Preflight | null, index?: number) {
  const h = buildHandoff(ctx, opts, op, owner, fpr, p, index)
  const url = handoffUrl(siteFor(opts), h)
  if (ctx.network !== 'mainnet' && !opts.site) info(`thurin.id runs mainnet; for ${ctx.network}, point the link at a ${ctx.network} build with --site <url>.`)
  out({ handoff: true, op, owner, fingerprint: fpr, network: ctx.network, index, proofs: p?.proofs, url }, () =>
    `${ok('Ready to publish')} ${bold(fpr)} for ${owner}${index !== undefined ? ` (claim #${index})` : ''}\n` +
    `Open this link where that wallet is (the part after # never leaves your browser) and confirm:\n\n${url}\n`)
  await offerToOpen(url, isJson())
}

/**
 * --authorize: the keystore signs the write as EIP-712 typed data (free, no ETH) and the
 * result is a link or file that *anyone* can publish through the registry's `…For` call:
 * a friend, `thurin submit`, or a relayer. The owner cannot recall it before the deadline,
 * so the deadline is shown every time.
 */
export async function authorize(ctx: ChainCtx, opts: Record<string, any>, op: HandoffOp, owner: Address, fpr: string, p: Preflight | null, index?: number) {
  const h0 = buildHandoff(ctx, opts, op, owner, fpr, p, index)
  const signer = await signerFor(opts, h0)
  if (!externalSigner(opts)) {
    const account = await accountFor(opts)
    if (account.address.toLowerCase() !== owner.toLowerCase()) throw new CliError(`--authorize signs with this keystore's address (${account.address}), not ${owner}. For another address: --signer or --sign-out with --owner`, EXIT.USAGE)
  }
  const nonce = Number(await ctx.client.readContract({ address: ctx.registry, abi: REGISTRY_ABI, functionName: 'nonces', args: [owner] } as any))
  let deadline: number
  try { deadline = parseDeadline(opts.deadline) } catch (e: any) { throw new CliError(e.message, EXIT.USAGE) }
  const h = h0
  h.authorization = { nonce, deadline, signature: '0x' }
  const typed = typedDataFor(h, ctx.client.chain!.id, ctx.registry)
  if (externalSigner(opts) && !opts.signOut) info(`Signing with ${signer.describe}`)   // --sign-out says where it wrote the file
  try { h.authorization.signature = await signer.signTypedData(typed) }
  catch (e) {
    if (e instanceof SignLater) {
      out({ signLater: true, op, owner, nonce, deadline, typedData: e.path }, () =>
        `${ok('Wrote what needs signing')} to ${e.path} (${describeDeadline(deadline)}).\n` +
        `Sign its typedData with the key for ${owner}, then: thurin authorize finish ${e.path} --signature <0x…> (or --signature-file f)\n` +
        `${dim('Sign before the deadline, and before this address publishes anything else.')}`)
      return
    }
    throw e
  }
  // Prove it back before handing it out — whoever signed, this is the check that matters.
  const recovered = await recoverTypedDataAddress({ ...(typed as any), signature: h.authorization.signature })
  if (recovered.toLowerCase() !== owner.toLowerCase()) throw new CliError(`The signature is from ${recovered}, not ${owner}, so it won't be handed out`, EXIT.FAILED)
  // Would the registry take it right now? (nonce, index, duplicate-claim rules; simulated from the owner, which needs no ETH)
  await ctx.client.simulateContract({ address: ctx.registry, abi: REGISTRY_ABI, functionName: FOR_FN[op], args: forArgsOf(h), account: owner } as any)
    .catch((e: any) => { throw new CliError(`The registry would refuse this permission: ${e.shortMessage || e.message}`, EXIT.CHAIN) })

  await emitAuthorized(ctx, opts, h, owner)
}

/** What a permission does, in words: "a claim", "a record", …. */
const OP_WORDS: Record<string, string> = {
  attest: 'a claim', reattest: 'a replacement claim', 'update-key': 'a key update', revoke: 'a revoke',
  'set-record': 'a record', 'mark-compromised': 'a compromised mark',
}
const opWords = (op: string, index?: number) => `${OP_WORDS[op] ?? op}${index !== undefined && op !== 'attest' ? ` on claim #${index}` : ''}`

/** Hand out a signed permission: to a relay, a file, or a link. Shared by --authorize and `authorize finish`. */
async function emitAuthorized(ctx: ChainCtx, opts: Record<string, any>, h: Handoff, owner: Address) {
  const { op, index, nonce, deadline } = { op: h.op, index: h.index, nonce: h.authorization!.nonce, deadline: h.authorization!.deadline }
  const fpr = h.fingerprint
  const where = describeDeadline(deadline)
  const head = `${ok('Signed a permission')} for ${opWords(op, index)} from ${owner}. Anyone can publish it for ${where}.\nIt can't be recalled before then; after that it does nothing.\n`
  if (opts.out) {
    writeFileSync(opts.out, JSON.stringify(h, null, 2) + '\n', { mode: 0o600 })   // a permission anyone holding it can publish
    out({ authorized: true, op, owner, fingerprint: fpr, network: ctx.network, index, nonce, deadline, file: opts.out }, () =>
      `${head}${label('file')}${opts.out}\n${dim(`Publish with: thurin submit ${opts.out}`)}`)
    return
  }
  const relayer: string | undefined = opts.noRelayer ? undefined : (opts.relayer || readConfig().relayer)
  if (relayer) {
    info(`Sending to ${relayer}…`)
    const r = await postToRelayer(relayer, h)
    out({ authorized: true, relayed: true, op, owner, fingerprint: fpr, network: ctx.network, index, nonce, ...r, identity: identityUrl(ctx, owner), tx: txUrl(ctx, r.hash) }, () =>
      `${ok('Published')} ${opWords(op, index)} for ${owner} via ${relayer}\n${label('tx')}${txUrl(ctx, r.hash)}${identityLine(ctx, owner)}`)
    return
  }
  const url = handoffUrl(siteFor(opts), h)
  if (ctx.network !== 'mainnet' && !opts.site) info(`thurin.id runs mainnet; for ${ctx.network}, point the link at a ${ctx.network} build with --site <url>.`)
  out({ authorized: true, op, owner, fingerprint: fpr, network: ctx.network, index, nonce, deadline, url }, () =>
    `${head}Open this link where a funded wallet is, or send it to whoever is paying:\n\n${url}\n`)
  await offerToOpen(url, isJson())
}

/** POST the permission to a relay (`thurin relay`); it runs the same checks and pays. */
async function postToRelayer(url: string, h: Handoff): Promise<{ hash: string; block?: string; payer?: string }> {
  let resp: Response
  try { resp = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(h) }) }
  catch (e: any) { throw new CliError(`Couldn't reach the relay at ${url}: ${e.message}. Use --no-relayer to get a link instead`, EXIT.CHAIN) }
  const body: any = await resp.json().catch(() => ({}))
  if (!resp.ok) throw new CliError(`The relay refused (${resp.status}): ${body.error || resp.statusText}. Use --no-relayer to get a link instead`, resp.status === 429 || resp.status === 503 ? EXIT.CHAIN : EXIT.FAILED)
  if (!body.hash) throw new CliError(`The relay answered without a transaction hash: ${JSON.stringify(body)}`, EXIT.CHAIN)
  return body
}

/**
 * Every check a submitter or relayer makes before paying for someone's authorization:
 * the signature recovers to the owner, the nonce is the chain's, the deadline is ahead,
 * the key is the key it names, and the PGP signature verifies the way a lookup will.
 */
export async function checkAuthorization(ctx: ChainCtx, h: Handoff) {
  if (!h.authorization) throw new CliError('This link has no permission in it, so only its owner can publish it: open it in a browser with that wallet', EXIT.USAGE)
  const owner = getAddress(h.owner)
  const a = h.authorization
  const typed = typedDataFor(h, ctx.client.chain!.id, ctx.registry)
  const signer = await recoverTypedDataAddress({ ...(typed as any), signature: a.signature }).catch(() => null)
  if (!signer || signer.toLowerCase() !== h.owner) throw new CliError(`The permission wasn't signed by ${owner}${signer ? ` (it's from ${signer})` : ''}, so something in it was changed`, EXIT.FAILED)
  const nonce = Number(await ctx.client.readContract({ address: ctx.registry, abi: REGISTRY_ABI, functionName: 'nonces', args: [owner] } as any))
  if (nonce !== a.nonce) throw new CliError(nonce > a.nonce ? `Already used, or ${owner} has published since signing. Ask for a new one` : `An earlier permission from ${owner} isn't published yet. Publish that one first`, EXIT.FAILED)
  if (a.deadline <= Math.floor(Date.now() / 1000)) throw new CliError(`This permission ${describeDeadline(a.deadline)}. Ask ${owner} for a new one`, EXIT.FAILED)
  let proofs = 0, names: string[] = []
  if (h.key) {
    const info_ = await parsePgpKey(h.key)
    if (!info_) throw new CliError("The key in this permission can't be read. Ask for a new one", EXIT.FAILED)
    if (info_.fingerprint.toUpperCase() !== h.fingerprint.toUpperCase()) throw new CliError('The key in this permission is not the key it names', EXIT.FAILED)
    names = info_.userIDs; proofs = info_.notations.map(identifyProof).filter(Boolean).length
    if (h.signature) {
      const v = await verifyAttestation({ pgpPublicKey: h.key, pgpSignature: h.signature, fingerprint: h.fingerprint, ethAddress: owner })
      if (!v.verified) throw new CliError(`The PGP signature does not verify: ${v.reason}`, EXIT.FAILED)
    }
  }
  return { owner, names, proofs }
}

/** thurin submit <link|file|fragment>: publish someone else's authorization from this keystore. */
export async function submit(args: string[], opts: Record<string, any>) {
  if (!args[0]) throw new CliError('Usage: thurin submit <link | permission.json>', EXIT.USAGE)
  let h: Handoff
  try { h = readHandoffInput(args[0]) } catch (e: any) { throw new CliError(e.message, EXIT.USAGE) }
  if (opts.network && opts.network !== h.network) throw new CliError(`This permission is for ${h.network}, not ${opts.network}`, EXIT.USAGE)
  const ctx = chainCtx({ ...opts, network: h.network })
  const { owner, names, proofs } = await checkAuthorization(ctx, h)
  const a = h.authorization!
  if (!isJson()) process.stderr.write(
    `${label('for')}${owner}\n${label('op')}${h.op}${h.index !== undefined ? ` #${h.index}` : ''}\n` +
    (h.key ? `${label('key')}${h.fingerprint}\n${label('names')}${names.join(', ')}\n${label('proofs')}${proofs}\n` : '') +
    `${label('checks')}${ok('signed by owner')} · ${ok('not used yet')}${h.signature ? ` · ${ok('PGP verified')}` : ''} · expires in ${describeDeadline(a.deadline)}\n`)
  const r = await send(ctx, opts, FOR_FN[h.op], forArgsOf(h), `Publish ${h.op} for ${owner}`)
  out({ ...r, owner, op: h.op, index: h.index, fingerprint: h.fingerprint, identity: identityUrl(ctx, owner), tx: txUrl(ctx, r.hash) }, () =>
    `${ok('Published')} ${opWords(h.op, h.index)} for ${owner}\n${label('tx')}${txUrl(ctx, r.hash)}${identityLine(ctx, owner)}`)
}

/**
 * The owner of a run whose PGP half came from files. --owner is honoured here even on a direct
 * send, since the statement inside names an address: the keystore then has to be that address.
 */
async function presignedOwner(ctx: ChainCtx, opts: Record<string, any>): Promise<Address> {
  if (!opts.owner || opts.noKey || opts.authorize || externalSigner(opts)) return ownerFor(ctx, opts)
  const named = await ownerFor(ctx, { ...opts, noKey: true })
  const account = await accountFor(opts)
  if (account.address.toLowerCase() !== named.toLowerCase()) throw new CliError(`--owner ${named} is not this keystore (${account.address}). To publish for it from elsewhere: --no-key, or --authorize with --signer / --sign-out`, EXIT.USAGE)
  return named
}

export async function attest(_args: string[], opts: Record<string, any>) {
  const ctx = chainCtx(opts)
  if (opts.statement) {
    // Just the line to sign, for a key gpg here can't reach. stdout carries only the line, so it pipes.
    if (!opts.owner) throw new CliError('--statement needs --owner <address|ens>: the address the claim will be for', EXIT.USAGE)
    const owner = await ownerFor(ctx, { ...opts, noKey: true })
    out({ statement: attestStatement(owner), owner }, () => attestStatement(owner))
    return
  }
  const pre = presignedInputs(opts)
  const fpr = await keyFor(opts, pre)
  const owner = pre ? await presignedOwner(ctx, opts) : await ownerFor(ctx, opts)
  await checkKeyClaimable(ctx, owner, fpr)
  const existing = (await claimsOf(ctx, owner)).filter(c => !c.revokedAt)
  const dup = existing.find(c => c.fingerprint === fpr)
  if (dup) throw new CliError(`${owner} already has an active claim for ${fpr} (#${dup.index}). New names or proofs on it: thurin update-key ${dup.index}`, EXIT.FAILED)
  const p = await preflight(ctx, owner, fpr, !!opts.includeEmail, true, pre)
  if (!isJson()) process.stderr.write(summary(p) + '\n')
  if (opts.authorize) return authorize(ctx, opts, 'attest', owner, fpr, p)
  if (opts.noKey) return handoff(ctx, opts, 'attest', owner, fpr, p)
  const r = await send(ctx, opts, 'attest', [fingerprintToBytes(fpr), payloadArg(p.signature!), p.key], 'Publish claim')
  out({ ...r, owner, fingerprint: fpr, proofs: p.proofs, identity: identityUrl(ctx, owner), tx: txUrl(ctx, r.hash) }, () =>
    `${ok('Published')} ${bold(fpr)} for ${owner}\n${label('tx')}${txUrl(ctx, r.hash)}${identityLine(ctx, owner)}`)
}

export async function updateKey(args: string[], opts: Record<string, any>) {
  const ctx = chainCtx(opts)
  if (opts.statementFile) throw new CliError('update-key signs nothing new; give only --key-file', EXIT.USAGE)
  const pre = presignedInputs(opts)
  const owner = pre ? await presignedOwner(ctx, opts) : await ownerFor(ctx, opts)
  const claims = await claimsOf(ctx, owner)
  const idx = pickIndex(args[0], claims)
  const c = claims[idx]
  if (c.revokedAt) throw new CliError(`Claim #${idx} is already revoked`, EXIT.FAILED)
  const includeEmail = opts.includeEmail ?? (c.keyInfo?.userIDs.some(u => u.includes('@')) ?? false)
  const p = await preflight(ctx, owner, c.fingerprint, includeEmail, false, pre)
  if (c.keyHex && p.key.toLowerCase() === c.keyHex.toLowerCase()) throw new CliError(`The ${pre ? 'given' : 'exported'} key is identical to the one on-chain; nothing to update`, EXIT.FAILED)
  if (!isJson()) process.stderr.write(summary(p) + '\n')
  if (opts.authorize) return authorize(ctx, { ...opts, includeEmail }, 'update-key', owner, c.fingerprint, p, idx)
  if (opts.noKey) return handoff(ctx, { ...opts, includeEmail }, 'update-key', owner, c.fingerprint, p, idx)
  const r = await send(ctx, opts, 'updateKey', [BigInt(idx), p.key], `Update key on claim #${idx}`)
  out({ ...r, owner, index: idx, proofs: p.proofs, identity: identityUrl(ctx, owner), tx: txUrl(ctx, r.hash) }, () =>
    `${ok('Updated')} claim #${idx}: ${p.proofs} proof${p.proofs === 1 ? '' : 's'}\n${label('tx')}${txUrl(ctx, r.hash)}${identityLine(ctx, owner)}`)
}

export async function reattest(args: string[], opts: Record<string, any>) {
  const ctx = chainCtx(opts)
  const pre = presignedInputs(opts)
  const fpr = await keyFor(opts, pre)
  const owner = pre ? await presignedOwner(ctx, opts) : await ownerFor(ctx, opts)
  const claims = await claimsOf(ctx, owner)
  const idx = pickIndex(args[0], claims)
  if (claims[idx].revokedAt) throw new CliError(`Claim #${idx} is already revoked`, EXIT.FAILED)
  await checkKeyClaimable(ctx, owner, fpr)
  // A canary moving to a claim with a different key was signed by the old one: say so, as the site does.
  if (!opts.dropRecords && claims[idx].fingerprint !== fpr) {
    const [names] = await readRegistry<[string[], string[]]>(ctx, 'recordsOf', [owner, BigInt(idx)])
    if (names.includes('thurin.canary')) info(`Your canary was signed by the old key. After this, set a new one signed with ${fpr}.`)
  }
  const p = await preflight(ctx, owner, fpr, !!opts.includeEmail, true, pre)
  if (!isJson()) process.stderr.write(summary(p) + '\n')
  if (opts.compromised && (opts.authorize || opts.noKey)) throw new CliError('--compromised sends two calls in one transaction from this keystore; with --authorize or --no-key, reattest first, then: thurin revoke <old index> --reason compromised', EXIT.USAGE)
  if (opts.authorize) return authorize(ctx, opts, 'reattest', owner, fpr, p, idx)
  if (opts.noKey) return handoff(ctx, opts, 'reattest', owner, fpr, p, idx)
  if (opts.compromised && claims[idx].fingerprint === fpr) throw new CliError('--compromised needs a different key: the old key would stay in use', EXIT.USAGE)
  const reattestArgs = [BigInt(idx), fingerprintToBytes(fpr), payloadArg(p.signature!), p.key, !opts.dropRecords] as const
  const what = `Revoke #${idx} and publish a new claim${opts.dropRecords ? '' : ' (its records move to the new one)'}${opts.compromised ? `; mark ${claims[idx].fingerprint} compromised (this address can never claim it again)` : ''}`
  const r = opts.compromised
    ? await send(ctx, opts, 'multicall', [[
        encodeFunctionData({ abi: REGISTRY_ABI, functionName: 'reattest', args: reattestArgs }),
        encodeFunctionData({ abi: REGISTRY_ABI, functionName: 'revoke', args: [BigInt(idx), 'compromised'] }),
      ]], what)
    : await send(ctx, opts, 'reattest', [...reattestArgs], what)
  out({ ...r, owner, revoked: idx, fingerprint: fpr, identity: identityUrl(ctx, owner), tx: txUrl(ctx, r.hash) }, () =>
    `${ok('Replaced')} claim #${idx} with ${bold(fpr)}\n${label('tx')}${txUrl(ctx, r.hash)}${identityLine(ctx, owner)}`)
}

export async function revoke(args: string[], opts: Record<string, any>) {
  const ctx = chainCtx(opts)
  if (opts.noKey) throw new CliError('revoke needs no PGP signature, so --no-key has nothing to carry. Revoke on thurin.id/attest, or use --authorize', EXIT.USAGE)
  const owner = await ownerFor(ctx, opts)
  const claims = await claimsOf(ctx, owner)
  const reason = revokeReason(opts)
  const idx = pickIndex(args[0], claims)
  const c = claims[idx]
  // A claim already revoked or replaced can still be marked compromised later, once.
  const late = !!c.revokedAt
  if (late && reason !== 'compromised') throw new CliError(`Claim #${idx} is already revoked. Found out its key was compromised? thurin revoke ${idx} --reason compromised`, EXIT.FAILED)
  if (late && c.revokeReason === 'compromised') throw new CliError(`Claim #${idx} is already marked compromised`, EXIT.FAILED)
  if (late && claims.some(o => !o.revokedAt && o.fingerprint === c.fingerprint)) throw new CliError(`${c.fingerprint} still has an active claim here; revoke that one as compromised first`, EXIT.FAILED)
  if (opts.authorize) return authorize(ctx, opts, late ? 'mark-compromised' : 'revoke', owner, c.fingerprint, null, idx)
  const what = late ? `Mark claim #${idx}'s key (${c.fingerprint}) as compromised; this address can never claim it again` : `Revoke claim #${idx} (${c.fingerprint})${reason ? ` as ${reason}` : ''}${reason === 'compromised' ? '; this address can never claim it again' : ''}`
  const r = await send(ctx, opts, 'revoke', [BigInt(idx), reason], what)
  out({ ...r, owner, index: idx, reason, markedLater: late, tx: txUrl(ctx, r.hash) }, () => `${late ? `${bad('Marked')} claim #${idx}'s key compromised` : `${bad('Revoked')} claim #${idx}${reason ? ` (${reason})` : ''}`}\n${label('tx')}${txUrl(ctx, r.hash)}`)
}

/** After "compromised" an address can never claim that key again; say so before gpg is asked to sign. */
async function checkKeyClaimable(ctx: ChainCtx, owner: Address, fpr: string) {
  const status = await readRegistry<string>(ctx, 'keyStatus', [owner, fingerprintToBytes(fpr)])
  if (status === 'compromised') throw new CliError(`${owner} revoked ${fpr} as compromised, so it can't claim that key again. Use a new key. ${MAKE_KEY_HINT}`, EXIT.FAILED)
  if (status === 'revoked') info(`${owner} revoked ${fpr} before; this makes a new claim and the old one stays revoked.`)
}

/** --reason for revoke: compromised, retired, other, or none ("superseded" is set only by reattest). */
function revokeReason(opts: Record<string, any>): RevokeReason {
  const r = String(opts.reason ?? '').toLowerCase()
  if (!(OWNER_REVOKE_REASONS as readonly string[]).includes(r)) throw new CliError(`--reason must be one of: ${OWNER_REVOKE_REASONS.filter(Boolean).join(', ')}`, EXIT.USAGE)
  return r as RevokeReason
}

export function pickIndex(arg: string | undefined, claims: { revokedAt: number | null }[]): number {
  if (arg !== undefined) { const i = Number(arg); if (!Number.isInteger(i) || i < 0 || i >= claims.length) throw new CliError(`No claim #${arg} (this address has ${claims.length})`, EXIT.USAGE); return i }
  const active = claims.map((c, i) => [c, i] as const).filter(([c]) => !c.revokedAt)
  if (active.length === 1) return active[0][1]
  throw new CliError(active.length ? 'Several active claims; give the index (thurin status <address>)' : 'No active claim for this address', EXIT.USAGE)
}
