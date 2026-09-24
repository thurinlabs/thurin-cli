// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { clientIp } from '../src/commands/relay.js'

const req = (peer: string, xff?: string) => ({ socket: { remoteAddress: peer }, headers: xff ? { 'x-forwarded-for': xff } : {} }) as any

describe('relay caller IP', () => {
  it('believes the header from a local proxy, taking the entry that proxy added', () => {
    expect(clientIp(req('127.0.0.1', '9.9.9.9'))).toBe('9.9.9.9')
    expect(clientIp(req('::ffff:127.0.0.1', '6.6.6.6, 9.9.9.9'))).toBe('9.9.9.9')   // client-sent first entry ignored
  })
  it('ignores the header from anyone else', () => {
    expect(clientIp(req('203.0.113.7', '1.2.3.4'))).toBe('203.0.113.7')
  })
  it('falls back to the socket address with no header', () => {
    expect(clientIp(req('127.0.0.1'))).toBe('127.0.0.1')
  })
})
