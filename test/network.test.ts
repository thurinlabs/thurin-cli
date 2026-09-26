// @vitest-environment node
import { describe, it, expect } from 'vitest'
import { classify, hostOf, tally, sortUses, type HostUse } from '../src/lib/network.js'

describe('--show-network', () => {
  it('shows the host only: no path, query, or key', () => {
    expect(hostOf('https://mainnet.example-rpc.io/v2/SECRETKEY123?apikey=abc')).toBe('mainnet.example-rpc.io')
    expect(hostOf('http://127.0.0.1:8545')).toBe('127.0.0.1:8545')
  })

  it('names what each request was for', () => {
    const relays = new Set(['relay.thurin.id'])
    expect(classify('https://ethereum.publicnode.com', '{"jsonrpc":"2.0","id":1,"method":"eth_call"}')).toBe('RPC')
    expect(classify('https://api.github.com/gists/abc', undefined)).toBe('proof check')
    expect(classify('https://mastodon.social/api/v1/accounts/lookup?acct=x', undefined)).toBe('proof check')
    expect(classify('https://some-hub.example/v1/castById?fid=1', undefined)).toBe('proof check')
    expect(classify('https://relay.thurin.id/', '{"v":2}', relays)).toBe('relay')
    expect(classify('https://example.com/x', undefined, relays)).toBe('other')
  })

  it('counts requests per host and orders RPC first', () => {
    const uses: HostUse[] = []
    tally(uses, 'api.github.com', 'proof check')
    tally(uses, 'ethereum.publicnode.com', 'RPC')
    tally(uses, 'ethereum.publicnode.com', 'RPC')
    expect(sortUses(uses)).toEqual([
      { host: 'ethereum.publicnode.com', purpose: 'RPC', requests: 2 },
      { host: 'api.github.com', purpose: 'proof check', requests: 1 },
    ])
  })
})
