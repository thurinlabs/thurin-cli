// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { presignedInputs, preflight } from '../src/commands/attest.js'

// The kit's fixtures: a real key and the clearsigned statement its owner published.
const F = join(__dirname, '../../identity-kit/src/core/__tests__/fixtures')
const key = readFileSync(join(F, 'company-key.asc'), 'utf8')
const statement = readFileSync(join(F, 'company-attestation.asc'), 'utf8')
const OWNER = '0x539C7e1E454296Dc150B95a0acCC05bCa3b33538'
const FPR = '08B9374FDFBEC67EFFA24E669D3D86E35361EF7B'

function files() {
  const d = mkdtempSync(join(tmpdir(), 'thurin-presigned-'))
  const keyFile = join(d, 'pub.asc'), statementFile = join(d, 'signed.asc'), detached = join(d, 'sig.asc')
  writeFileSync(keyFile, key); writeFileSync(statementFile, statement)
  writeFileSync(detached, '-----BEGIN PGP SIGNATURE-----\n\nabc\n-----END PGP SIGNATURE-----\n')
  return { keyFile, statementFile, detached }
}

describe('pre-signed attest: --key-file / --statement-file', () => {
  it('is off when neither flag is given', () => { expect(presignedInputs({})).toBeNull() })
  it('needs the key to go with the statement', () => {
    expect(() => presignedInputs({ statementFile: 'x' })).toThrow(/--key-file/)
  })
  it('refuses a detached signature: the statement must be clearsigned', () => {
    const f = files()
    expect(() => presignedInputs({ keyFile: f.keyFile, statementFile: f.detached })).toThrow(/clearsign/)
  })
  it('runs the same preflight as the gpg path on the given bytes', async () => {
    const f = files()
    const pre = presignedInputs({ keyFile: f.keyFile, statementFile: f.statementFile })!
    const p = await preflight({} as any, OWNER, FPR, true, true, pre)
    expect(p.signature).toBe(statement.trim())
    expect(p.armored).toBe(key.trim())
    expect(p.bytes).toBeLessThan(8192)
  })
  it('fails when the statement names another address, and says what the line must be', async () => {
    const f = files()
    const pre = presignedInputs({ keyFile: f.keyFile, statementFile: f.statementFile })!
    const other = '0xd32e18C735E89fA7616dF3CEAEb5E33f3280e9fe'
    await expect(preflight({} as any, other, FPR, true, true, pre)).rejects.toThrow(/does not verify.*\nThe statement must be exactly: I control the Ethereum address: 0xd32e18c735e89fa7616df3ceaeb5e33f3280e9fe/s)
  })
  it('fails when the key file is not the key named', async () => {
    const f = files()
    const pre = presignedInputs({ keyFile: f.keyFile, statementFile: f.statementFile })!
    await expect(preflight({} as any, OWNER, '6E0053911942A889426C1866E34D9266098F7FE7', true, true, pre)).rejects.toThrow(/fingerprint does not match/)
  })
  it('a key file alone is enough for update-key, not for attest', async () => {
    const f = files()
    const pre = presignedInputs({ keyFile: f.keyFile })!
    const p = await preflight({} as any, OWNER, FPR, true, false, pre)
    expect(p.signature).toBeNull()
    await expect(preflight({} as any, OWNER, FPR, true, true, pre)).rejects.toThrow(/--statement-file/)
  })
})
