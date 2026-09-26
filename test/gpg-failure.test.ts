// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { gpgFailure } from '../src/lib/gpg.js'

const sign = ['--detach-sign', '--textmode']

describe('gpgFailure', () => {
  it('says to touch the key on a timeout', () => {
    expect(gpgFailure(sign, 'gpg: signing failed: Timeout\ngpg: signing failed: Timeout')).toMatch(/touch it when it blinks/)
  })
  it('names a cancelled PIN prompt', () => {
    expect(gpgFailure(sign, 'gpg: signing failed: Operation cancelled')).toBe('Cancelled at the PIN prompt.')
  })
  it('says the card is missing', () => {
    expect(gpgFailure(sign, 'gpg: signing failed: Card error')).toMatch(/can't reach the card/)
  })
  it('keeps gpg\'s own words for anything else', () => {
    expect(gpgFailure(sign, 'gpg: something new happened')).toBe('gpg --detach-sign failed: gpg: something new happened')
  })
})
