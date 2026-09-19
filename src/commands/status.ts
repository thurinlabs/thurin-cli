import { identifyProof, verifyProof, displayUrl, fetchEFPGraph, type ProofResult } from '@thurinlabs/identity-kit/core'
import { chainCtx, claimsOf, detectLookup, resolveOwners, ensNameOf, type Claim } from '../lib/chain.js'
import { out, ok, bad, dim, bold, label, CliError, EXIT } from '../lib/output.js'

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
    const current = claims.find(c => !c.revokedAt && c.verification?.verified) || null
    let proofs: { provider: string; label: string; display: string; url: string; verified: boolean; reason?: string }[] = []
    if (current?.keyInfo) {
      const ps = current.keyInfo.notations.map(identifyProof).filter((p): p is NonNullable<typeof p> => !!p)
      proofs = await Promise.all(ps.map(async p => { const r = await verifyProof(p, current.fingerprint, process.env.NEYNAR_API_KEY); return { provider: p.provider, label: p.label, display: displayUrl(p), url: p.url, verified: r.verified, reason: r.reason } }))
    }
    const efp = ctx.network === 'mainnet' ? await fetchEFPGraph(owner).catch(() => null) : null
    identities.push({ address: owner, ensName: name, network: ctx.network, claims, current, proofs, efp })
  }

  out({ query, lookup, identities: identities.map(i => ({ ...i, claims: i.claims.map(stripKey), current: i.current ? stripKey(i.current) : null })) }, () => identities.map(render).join('\n\n'))
  const anyVerified = identities.some(i => i.current)
  if (!anyVerified) process.exitCode = EXIT.FAILED
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
    for (const u of i.current.keyInfo?.userIDs ?? []) L.push(`${label('name')}${u}`)
    L.push(`${label('key')}${i.current.keyInfo?.algorithm ?? '?'} · created ${new Date(i.current.createdAt * 1000).toISOString().slice(0, 10)}${i.current.keyInfo?.expires ? ` · expires ${i.current.keyInfo.expires.slice(0, 10)}` : ''}`)
  } else {
    const c = i.claims.find((c: Claim) => !c.revokedAt)
    L.push(`${label('fingerprint')}${c ? c.fingerprint : i.claims[0].fingerprint}  ${bad('✗ ' + (c?.verification?.reason || 'no active claim'))}`)
  }
  if (i.proofs.length) { L.push(label('proofs')); for (const p of i.proofs) L.push(`  ${p.verified ? ok('✓') : bad('✗')} ${p.label.padEnd(10)} ${p.display}${p.verified ? '' : dim('  ' + (p.reason || ''))}`) }
  else if (i.current) L.push(`${label('proofs')}${dim('none')}`)
  if (i.efp?.hasEfp) L.push(`${label('efp')}${i.efp.followers} followers · ${i.efp.following} following`)
  if (i.claims.length > 1 || (i.claims[0] && i.claims[0] !== i.current)) {
    L.push(label('history'))
    for (const c of i.claims) L.push(`  #${c.index} ${c.fingerprint.slice(0, 8)}…${c.fingerprint.slice(-8)} ${new Date(c.createdAt * 1000).toISOString().slice(0, 10)} ${c.revokedAt ? dim('revoked') : 'active'} ${c.verification?.verified ? ok('verified') : bad('unverified')}`)
  }
  return L.join('\n')
}
