import { defineConfig } from 'tsup'

export default defineConfig({
  entry: { thurin: 'src/thurin.ts' },
  format: ['esm'],
  platform: 'node',
  target: 'node20',
  sourcemap: true,
  clean: true,
  banner: { js: '#!/usr/bin/env node' },
  // identity-kit/core, viem, openpgp and friends stay external: npm installs them.
  external: ['@thurinlabs/identity-kit', 'viem', 'openpgp', 'eckey-utils'],
})
