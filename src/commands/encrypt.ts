import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { encryptionKeyFor, encryptRefusalText, keyChangedText, formatClaimDate, sameFingerprint, type EncryptionKeyResult } from '@thurinlabs/identity-kit/core'
import { chainCtx, claimsOf, detectLookup, resolveOwners } from '../lib/chain.js'
import { encryptTo } from '../lib/gpg.js'
import { out, info, warn, CliError, EXIT } from '../lib/output.js'

/**
 * thurin encrypt <identity> [file]: encrypt to the key of the claim that counts, with gpg, from
 * the user's own keyring (so --sign works) without importing anything. The kit picks the key.
 */
export async function encrypt(args: string[], opts: Record<string, any>) {
  const [who, file] = args
  if (!who) throw new CliError('Usage: thurin encrypt <ens|0x|fingerprint|keyid> [file] [-o out] [--sign] [--armor]', EXIT.USAGE)
  if (file && !existsSync(file)) throw new CliError(`No such file: ${file}`, EXIT.USAGE)
  const target = opts.out ?? (file ? `${file}.${opts.armor ? 'asc' : 'gpg'}` : undefined)
  if (opts.json && !target) throw new CliError('--json needs a file or -o, so the message and the JSON don\'t share stdout', EXIT.USAGE)
  if (target && existsSync(target) && !opts.yes) throw new CliError(`${target} exists. Pass --yes to overwrite it, or -o another name.`, EXIT.USAGE)

  const ctx = chainCtx(opts)
  const lookup = detectLookup(who)
  const { owners, ensName } = await resolveOwners(ctx, lookup)
  let picked: (EncryptionKeyResult & { owner: string }) | null = null
  for (const owner of owners) {
    const r = { ...(await encryptionKeyFor(await claimsOf(ctx, owner))), owner }
    // A fingerprint or key ID names one key: use it only where it is that owner's key that counts.
    if (r.ok && (lookup.type === 'address' || lookup.type === 'ens' || sameFingerprint(r.claim.fingerprint, lookup.value) || r.claim.fingerprint.toUpperCase().endsWith(lookup.value.toUpperCase()))) { picked = r; break }
    if (!picked) picked = r
  }
  if (!picked) throw new CliError(`No claim for ${who}. See: thurin status ${who}`, EXIT.FAILED)
  if (!picked.ok) throw new CliError(encryptRefusalText(picked), EXIT.FAILED)

  const name = ensName ?? picked.owner
  const fp = picked.claim.fingerprint.toUpperCase()
  info(`Encrypting to ${name} · key ${fp} · encryption subkey ${picked.subkey.algorithm}${picked.subkey.expires ? ` (expires ${formatClaimDate(picked.subkey.expires)})` : ''}`)
  const changed = keyChangedText(picked)
  if (changed) warn(changed)

  if (!file && process.stdin.isTTY) info(`Type your message, then press ${process.platform === 'win32' ? 'Ctrl-Z and Enter' : 'Ctrl-D'}.`)

  const dir = mkdtempSync(join(tmpdir(), 'thurin-'))
  try {
    const recipientFile = join(dir, 'recipient.asc')
    writeFileSync(recipientFile, picked.key, { mode: 0o600 })
    await encryptTo(recipientFile, {
      file, out: target, armor: !!opts.armor || !file, sign: !!opts.sign, signer: opts.key, hideRecipient: !opts.showRecipient,
    })
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }

  if (target) {
    out({ recipient: name, owner: picked.owner, fingerprint: fp, subkey: picked.subkey, recipientHidden: !opts.showRecipient, signed: !!opts.sign, out: target },
      () => `Wrote ${target}. Only ${name}'s key can open it: gpg --decrypt ${target}`)
  }
}
