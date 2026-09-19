// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { addPointer, parsePointer, encodeRecord, decodeRecord, kindName, MAX_RECORD_BYTES } from '../src/lib/records.js'

const sha = 'a'.repeat(64)

describe('records', () => {
  it('names kinds with the thurin. prefix', () => {
    expect(kindName('pointer')).toBe('thurin.pointer'); expect(kindName('thurin.pointer')).toBe('thurin.pointer')
  })
  it('round-trips text through the on-chain bytes', () => {
    expect(decodeRecord(encodeRecord('{"v":1}'))).toBe('{"v":1}'); expect(decodeRecord('0x')).toBe('')
    expect(() => encodeRecord('x'.repeat(MAX_RECORD_BYTES + 1))).toThrow(/1024/)
  })
  it('adds releases newest first and replaces a same-named one', () => {
    const a = addPointer(null, { name: 'thurin-cli 0.5.1', sha256: sha, date: '2026-09-19' }).record
    const b = addPointer(a, { name: 'thurin-cli 0.6.0', sha256: sha, date: '2026-10-01' }).record
    expect(b.releases.map(r => r.name)).toEqual(['thurin-cli 0.6.0', 'thurin-cli 0.5.1'])
    const c = addPointer(b, { name: 'thurin-cli 0.5.1', sha256: 'b'.repeat(64), date: '2026-10-02' }).record
    expect(c.releases.length).toBe(2); expect(c.releases[0].sha256).toBe('b'.repeat(64))
  })
  it('drops the oldest when the 1 KB slot is full, and says which', () => {
    let rec = null as any; const allDropped: string[] = []
    for (let i = 0; i < 15; i++) { const r = addPointer(rec, { name: `thurin-cli 0.${i}.0`, sha256: sha, date: '2026-09-19' }); rec = r.record; allDropped.push(...r.dropped.map(d => d.name)) }
    expect(new TextEncoder().encode(JSON.stringify(rec)).length).toBeLessThanOrEqual(MAX_RECORD_BYTES)
    expect(rec.releases[0].name).toBe('thurin-cli 0.14.0')
    expect(allDropped.length).toBeGreaterThan(0); expect(allDropped[0]).toBe('thurin-cli 0.0.0')   // oldest goes first
    expect(rec.releases.length + allDropped.length).toBe(15)
    expect(parsePointer(JSON.stringify(rec)).releases.length).toBe(rec.releases.length)
  })
  it('rejects a bad hash and a foreign record', () => {
    expect(() => addPointer(null, { name: 'x', sha256: 'nope', date: '' })).toThrow(/64 hex/)
    expect(() => parsePointer('{"v":2}')).toThrow(/v1/)
  })
})
