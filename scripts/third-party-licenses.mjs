// Writes dist/THIRD-PARTY-LICENSES.txt: the license of every package bundled into dist/thurin.js.
// The bundle is built from the lockfile, so the list is every package the published CLI contains.
import { readFileSync, readdirSync, writeFileSync, existsSync } from 'node:fs'

const lock = JSON.parse(readFileSync('package-lock.json', 'utf8')).packages
const pkg = JSON.parse(readFileSync('package.json', 'utf8'))

// What the bundle can reach: the former runtime dependencies and everything they depend on.
const runtime = ['@noble/ciphers', '@noble/hashes', '@scure/bip39', '@thurinlabs/identity-kit', 'picocolors', 'viem']
const seen = new Map()
const queue = [...runtime]
while (queue.length) {
  const name = queue.shift()
  if (seen.has(name)) continue
  const entry = lock[`node_modules/${name}`]
  if (!entry) continue
  seen.set(name, entry)
  queue.push(...Object.keys(entry.dependencies ?? {}), ...Object.keys(entry.optionalDependencies ?? {}))
}
for (const name of runtime) if (!pkg.devDependencies[name]) throw new Error(`${name} is not a dependency any more: update this list`)

const licenseText = name => {
  const dir = `node_modules/${name}`
  const file = existsSync(dir) && readdirSync(dir).find(f => /^(licen[cs]e|copying)(\.|$)/i.test(f))
  if (file) return readFileSync(`${dir}/${file}`, 'utf8').trim()
  const meta = JSON.parse(readFileSync(`${dir}/package.json`, 'utf8'))
  const author = typeof meta.author === 'string' ? meta.author : meta.author?.name
  return `${meta.license} license${author ? `, copyright ${author}` : ''} (no license file shipped; see the package).`
}

const names = [...seen.keys()].sort()
let out = `Third-party software bundled into @thurinlabs/thurin ${pkg.version} (dist/thurin.js).\n`
out += `The bundle is not minified; each package's source is at the npm registry under its name and version.\n`
for (const name of names) {
  const e = seen.get(name)
  out += `\n${'='.repeat(78)}\n${name}@${e.version}  (${e.license ?? 'see below'})\n${'='.repeat(78)}\n\n${licenseText(name)}\n`
}
// LGPL-3.0 (openpgp) is a set of permissions on top of the GPL-3.0, which must travel with it.
if (names.some(n => /GPL/.test(seen.get(n).license ?? ''))) {
  out += `\n${'='.repeat(78)}\nGNU General Public License, version 3 (referenced by the LGPL-3.0 above)\n${'='.repeat(78)}\n\n`
  out += readFileSync('licenses/GPL-3.0.txt', 'utf8').trim() + '\n'
}
writeFileSync('dist/THIRD-PARTY-LICENSES.txt', out)
console.log(`dist/THIRD-PARTY-LICENSES.txt: ${names.length} packages`)
