import { defineConfig } from 'tsup'

export default defineConfig({
  entry: { thurin: 'src/thurin.ts' },
  format: ['esm'],
  platform: 'node',
  target: 'node20',
  sourcemap: false,
  clean: true,
  splitting: false,
  // Every dependency is bundled: the signed tarball is every line of code the CLI runs, and
  // installing it fetches nothing else. `require` for the CommonJS parts (ws) inside an ESM bundle.
  noExternal: [/.*/],
  // Optional native speedups ws tries to load; absent is fine.
  external: ['bufferutil', 'utf-8-validate'],
  banner: { js: "#!/usr/bin/env node\nimport { createRequire as __thurinRequire } from 'node:module'; const require = __thurinRequire(import.meta.url);" },
})
