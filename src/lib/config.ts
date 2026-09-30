import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { homedir } from 'node:os'
import type { NetworkName } from '@thurinlabs/identity-kit/core'

export interface Config {
  network?: NetworkName
  rpc?: Partial<Record<NetworkName, string>>
  account?: string   // default keystore name
  key?: string       // default PGP fingerprint
  site?: string      // where --no-key links point (default https://thurin.id)
  relay?: string     // where --authorize posts instead of printing a link (none by default)
}

export const CONFIG_DIR = process.env.THURIN_CONFIG_DIR || join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'thurin')
export const KEYSTORE_DIR = join(CONFIG_DIR, 'keystores')
const CONFIG_FILE = join(CONFIG_DIR, 'config.json')

export function readConfig(): Config {
  try { return JSON.parse(readFileSync(CONFIG_FILE, 'utf8')) } catch { return {} }
}

export function writeConfig(c: Config) {
  mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 })
  writeFileSync(CONFIG_FILE, JSON.stringify(c, null, 2) + '\n', { mode: 0o600 })
}

export function ensureKeystoreDir() {
  if (!existsSync(KEYSTORE_DIR)) mkdirSync(KEYSTORE_DIR, { recursive: true, mode: 0o700 })
  return KEYSTORE_DIR
}

/** The relay `--authorize` tries when none is set (--relay, or `relay` in the config); `--no-relay` skips it.
 *  If it can't publish (gone, out of budget, refuses), the CLI hands out the link instead. */
export const DEFAULT_RELAY: Partial<Record<string, string>> = { mainnet: 'https://relay.thurin.id' }
