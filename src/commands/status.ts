import { identifyProof, verifyProof, displayUrl, fetchEFPGraph, claimCheckText, expiresSoon, claimFates, type ProofResult, type ClaimFate, type PGPVerification } from '@thurinlabs/identity-kit/core'
import { listKeystores } from '../lib/keystore.js'
import { chainCtx, claimsOf, detectLookup, resolveOwners, ensNameOf, type Claim } from '../lib/chain.js'
import { out, ok, bad, dim, bold, label, CliError, EXIT } from '../lib/output.js'
import { ensHintOf, renderHint } from './ens.js'

export async function status(args: string[], opts: Record<string, any>) {
  const query = args[0]
  if (!query) throw new CliError('Usage: thurin status <ens|0x|fingerprint|keyid>', EXIT.USAGE)
  const ctx = chainCtx(opts)
  const lookup = detectLookup(query)
  const { owners, ensName } = await resolveOwners(ctx, lookup)

  const identities: any[] = []
  for (const owner of owners) {
    const claims = await claimsOf(ctx, owner)
    const name = ensName ?? await ensNameOf(ctx, owner)
    // The claim to show: when the query names a key, that key's claim; else the newest verified one.
    const active = claims.filter(c => !c.revokedAt && c.verification?.verified)
    const current = (lookup.type === 'fingerprint' ? active.find(c => c.fingerprint === lookup.value)
      : lookup.type === 'keyId' ? active.find(c => c.fingerprint.endsWith(lookup.value))
      : null) ?? active[active.length - 1] ?? null
    let proofs: { provider: string; label: string; display: string; url: string; verified: boolean; reason?: string }[] = []
    if (current?.keyInfo) {
      const ps = current.keyInfo.notations.map(identifyProof).filter((p): p is NonNullable<typeof p> => !!p)
      proofs = await Promise.all(ps.map(async p => { const r = await verifyProof(p, current.fingerprint, process.env.NEYNAR_API_KEY); return { provider: p.provider, label: p.label, display: displayUrl(p), url: p.url, verified: r.verified, reason: r.reason } }))
    }
    const efp = ctx.network === 'mainnet' ? await fetchEFPGraph(owner).catch(() => null) : null
    // The name's id.thurin record: a pointer ENS viewers can show; the claim above is the proof.
    const ensRecord = name && ctx.network === 'mainnet' ? await ensHintOf(ctx, name, claims).catch(() => null) : null
    const fates = claimFates(claims)
    identities.push({ address: owner, ensName: name, network: ctx.network, claims, current, proofs, efp, ensRecord, fates, mine: ownKeystore(owner) })
  }

  out({ query, lookup, identities: identities.map(({ fates, mine, ...i }) => ({
    ...i,
    claims: i.claims.map((c: Claim) => ({ ...stripKey(c), fate: fates.get(c.index) ?? null })),
    current: i.current ? stripKey(i.current) : null,
  })) }, () => identities.map(render).join('\n\n'))
  const anyVerified = identities.some(i => i.current)
  if (!anyVerified) process.exitCode = EXIT.FAILED
}

/** A keystore on this machine holds the owner's address: then the fix lines are for us. */
function ownKeystore(owner: string): boolean {
  try { return listKeystores().some(k => k.address.toLowerCase() === owner.toLowerCase()) } catch { return false }
}

const day = (iso: string | null | undefined) => (iso ? iso.slice(0, 10) : '?')

/** The terminal version of each fix (thurin.id says "Update key"; here it's the command). */
const CLI_FIX: Partial<Record<NonNullable<PGPVerification['kind']>, string>> = {
  expired: 'extend it (gpg --quick-set-expire), then thurin update-key',
  'signing-key-expired': 'extend that subkey, then thurin update-key',
  revoked: 'thurin reattest --key <your new key>',
  compromised: 'thurin reattest --key <a new key>',
  'signing-key-revoked': 'thurin reattest with a current key',
}

/** "✗ key expired 2029-03-05: extend it, …" (the fix only when a keystore here owns the claim). */
function checkLine(v: PGPVerification | null | undefined, mine: boolean): string {
  if (!v) return bad('✗ no PGP data stored')
  const t = claimCheckText(v, iso => day(iso))
  const when = v.at && t.kind !== 'bad-signature' && t.kind !== 'unsupported' ? ` ${day(v.at)}` : ''
  const extra = t.kind === 'unsupported' && v.algorithm ? ` (${v.algorithm})` : t.kind === 'revoked' && v.revocationReason ? ` (${v.revocationReason})` : ''
  const fix = mine && CLI_FIX[t.kind] ? `: ${CLI_FIX[t.kind]}` : ''
  return bad(`✗ ${t.label}${when}${extra}`) + fix
}

function fateWord(f: ClaimFate | undefined, revoked: boolean): string {
  if (f?.state === 'replaced') return dim(`replaced → #${f.by}`)
  return revoked ? dim('revoked') : 'active'
}

function stripKey(c: Claim) { const { pgpPublicKey, pgpSignature, keyInfo, ...rest } = c; return { ...rest, userIDs: keyInfo?.userIDs ?? [], algorithm: keyInfo?.algorithm ?? null, expires: keyInfo?.expires ?? null } }

function render(i: any): string {
  const L: string[] = []
  L.push(bold(i.ensName ? `${i.ensName}  ${dim(i.address)}` : i.address) + dim(`  (${i.network})`))
  if (!i.claims.length) { L.push(`${label('claims')}${dim('none')}`); return L.join('\n') }
  const active = i.claims.filter((c: Claim) => !c.revokedAt).length
  L.push(`${label('claims')}${i.claims.length} total · ${active} active · ${i.claims.length - active} revoked`)
  if (i.current) {
    L.push(`${label('fingerprint')}${i.current.fingerprint}  ${ok('✓ verified')}`)
    const soon = expiresSoon(i.current.verification)
    if (soon) L.push(`${' '.repeat(12)}${bad(`⚠ key expires ${soon.days === 0 ? 'today' : `in ${soon.days} day${soon.days === 1 ? '' : 's'}`} (${day(soon.at)})`)}${i.mine ? ': extend it (gpg --quick-set-expire), then thurin update-key' : ''}`)
    for (const u of i.current.keyInfo?.userIDs ?? []) L.push(`${label('name')}${u}`)
    L.push(`${label('key')}${i.current.keyInfo?.algorithm ?? '?'} · ${i.current.keyInfo?.created ? `created ${i.current.keyInfo.created.slice(0, 10)} · ` : ''}claimed ${new Date(i.current.createdAt * 1000).toISOString().slice(0, 10)}${i.current.keyInfo?.expires ? ` · expires ${i.current.keyInfo.expires.slice(0, 10)}` : ''}`)
  } else {
    const c = i.claims.find((c: Claim) => !c.revokedAt)
    L.push(`${label('fingerprint')}${c ? c.fingerprint : i.claims[0].fingerprint}  ${c ? checkLine(c.verification, i.mine) : bad('✗ no active claim')}`)
  }
  if (i.proofs.length) { L.push(label('proofs')); for (const p of i.proofs) L.push(`  ${p.verified ? ok('✓') : bad('✗')} ${p.label.padEnd(10)} ${p.display}${p.verified ? '' : dim('  ' + (p.reason || ''))}`) }
  else if (i.current) L.push(`${label('proofs')}${dim('none')}`)
  if (i.efp?.hasEfp) L.push(`${label('efp')}${i.efp.followers} followers · ${i.efp.following} following`)
  if (i.ensRecord && (i.current || i.ensRecord.state !== 'unset')) L.push(`${label('ens record')}${renderHint(i.ensRecord, i.ensRecord.state === 'unset' && i.current ? i.ensName : undefined)}`)
  if (i.claims.length > 1 || (i.claims[0] && i.claims[0] !== i.current)) {
    L.push(label('history'))
    for (const c of i.claims) L.push(`  #${c.index} ${c.fingerprint.slice(0, 8)}…${c.fingerprint.slice(-8)} ${new Date(c.createdAt * 1000).toISOString().slice(0, 10)} ${fateWord(i.fates.get(c.index), !!c.revokedAt)}${c.revokedAt ? '' : ' ' + (c.verification?.verified ? ok('verified') : bad(claimCheckText(c.verification ?? { verified: false }).label))}`)
  }
  return L.join('\n')
}
