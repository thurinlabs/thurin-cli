import { spawn } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import type { Hex } from 'viem'
import { CliError, EXIT } from './output.js'

/**
 * Where an EIP-712 authorization gets signed. Thurin builds the typed data, hands it to a
 * signer, gets 65 bytes back, and then runs its own recovery + simulation checks unchanged.
 * The keystore is one signer; the others keep the key wherever it lives (a card, an
 * air-gapped machine) without Thurin learning anything about the hardware.
 */
export interface Signer {
  /** Signs EIP-712 typed data; returns a 65-byte hex signature. */
  signTypedData(typed: unknown): Promise<Hex>
  describe: string
}

/** A local keystore or THURIN_PRIVATE_KEY account. */
export function accountSigner(account: { address: string; signTypedData: (t: any) => Promise<Hex> }): Signer {
  return { signTypedData: t => account.signTypedData(t), describe: `keystore ${account.address}` }
}

/**
 * --signer <command>: run a program, write the typed data as JSON to its stdin, read the
 * signature from its stdout. Any language, any hardware. The command is run through the shell
 * so `--signer "keycard-sign --slot 1"` works.
 */
export function commandSigner(command: string): Signer {
  return {
    describe: `command "${command}"`,
    signTypedData: typed => new Promise((resolve, reject) => {
      const child = spawn(command, { shell: true, stdio: ['pipe', 'pipe', 'inherit'] })
      let out = ''
      child.stdout.on('data', c => { out += c })
      child.on('error', reject)
      child.on('close', code => {
        if (code !== 0) return reject(new CliError(`The --signer command exited with code ${code} (its errors are above)`, EXIT.FAILED))
        try { resolve(parseSignature(out)) } catch (e) { reject(e) }
      })
      // A signer that exits without reading its input (a wrong command, a card that refused) closes
      // the pipe before the write lands: EPIPE here is noise, 'close' below reports what happened.
      child.stdin.on('error', () => {})
      child.stdin.end(JSON.stringify(typed, bigintReplacer) + '\n')
    }),
  }
}

/**
 * Two-step air gap: `--sign-out f.json` writes the typed data and stops; sign it anywhere;
 * `--signature 0x…` (or `--signature-file f`) finishes with the usual checks.
 */
export function fileSigner(outPath: string, handoff: unknown): Signer {
  return {
    describe: `typed data written to ${outPath}`,
    signTypedData: async typed => {
      // The whole unsigned hand-off rides along: the PGP signature inside it carries a timestamp,
      // so the finishing step must reuse these exact bytes rather than sign again.
      writeFileSync(outPath, JSON.stringify({ typedData: typed, handoff }, bigintReplacer, 2) + '\n', { mode: 0o600 })
      throw new SignLater(outPath)
    },
  }
}

/** The file --sign-out wrote: the typed data to sign and the hand-off it was built from. */
export function readSignOut(path: string): { typedData: unknown; handoff: any } {
  const j = JSON.parse(readFileSync(path, 'utf8'))
  if (!j?.typedData || !j?.handoff) throw new CliError(`${path} is not a --sign-out file`, EXIT.USAGE)
  return j
}

export function providedSigner(sig: string): Signer {
  const signature = parseSignature(sig)
  return { describe: 'signature given on the command line', signTypedData: async () => signature }
}

export class SignLater extends Error { constructor(public path: string) { super(`typed data written to ${path}`) } }

/** Accepts 0x-hex or bare hex, with whitespace; 65 bytes. Also a JSON object with a `signature` field. */
export function parseSignature(text: string): Hex {
  let s = text.trim()
  if (s.startsWith('{')) { try { s = String(JSON.parse(s).signature ?? '') } catch { /* fall through */ } }
  s = s.replace(/\s+/g, '')
  if (!s.startsWith('0x')) s = '0x' + s
  if (!/^0x[0-9a-fA-F]{130}$/.test(s)) throw new CliError(`Not a 65-byte signature: ${text.trim().slice(0, 40)}${text.length > 40 ? '…' : ''}`, EXIT.FAILED)
  return s as Hex
}

export function readSignatureFile(path: string): Hex { return parseSignature(readFileSync(path, 'utf8')) }

/** BigInts (nonce, deadline, index) as decimal strings, which every EIP-712 tool expects. */
export function bigintReplacer(_k: string, v: unknown) { return typeof v === 'bigint' ? v.toString() : v }
