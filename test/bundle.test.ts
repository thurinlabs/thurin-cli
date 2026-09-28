import { describe, it, expect } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { builtinModules } from 'node:module'

// The published CLI is one file with every dependency inside it, so the signed tarball is all the
// code that runs. It may import Node's own modules and nothing else.
describe.runIf(existsSync('dist/thurin.js'))('bundle', () => {
  it('imports only Node built-ins', () => {
    const src = readFileSync('dist/thurin.js', 'utf8')
    const name = /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+(?:\/[a-zA-Z0-9._/-]+)?$/
    const specs = [...src.matchAll(/(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*)["']([^"'./][^"']*)["']/g)]
      .map(m => m[1])
      .filter(s => name.test(s))
    const allowed = new Set([...builtinModules, ...builtinModules.map(m => `node:${m}`), 'bufferutil', 'utf-8-validate'])
    const outside = [...new Set(specs.filter(s => !allowed.has(s)))]
    expect(outside).toEqual([])
  })
  it('ships the licenses of everything bundled', () => {
    const notice = readFileSync('dist/THIRD-PARTY-LICENSES.txt', 'utf8')
    expect(notice).toMatch(/^openpgp@\S+ +\(LGPL-3\.0/m)
    expect(notice).toContain('GNU LESSER GENERAL PUBLIC LICENSE')
    expect(notice).toContain('GNU GENERAL PUBLIC LICENSE')
    expect(notice).toMatch(/^viem@/m)
  })
  it('has no runtime dependencies to install', () => {
    const pkg = JSON.parse(readFileSync('package.json', 'utf8'))
    expect(Object.keys(pkg.dependencies ?? {})).toEqual([])
  })
})
