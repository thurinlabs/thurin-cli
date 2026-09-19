import pc from 'picocolors'

/** Exit codes: 0 ok · 1 a check failed · 2 usage · 3 chain / network error. */
export const EXIT = { OK: 0, FAILED: 1, USAGE: 2, CHAIN: 3 } as const

export class CliError extends Error {
  constructor(message: string, public code: number = EXIT.FAILED) { super(message) }
}

let jsonMode = false
export function setJson(on: boolean) { jsonMode = on }
export function isJson() { return jsonMode }

/** Print a result: JSON when --json, else the human rendering. */
export function out(data: unknown, human: () => string) {
  if (jsonMode) process.stdout.write(JSON.stringify(data, bigintReplacer, 2) + '\n')
  else process.stdout.write(human() + '\n')
}

export function info(line: string) { if (!jsonMode) process.stderr.write(pc.dim(line) + '\n') }
export function warn(line: string) { process.stderr.write(pc.yellow(line) + '\n') }

export const ok = (s: string) => pc.green(s)
export const bad = (s: string) => pc.red(s)
export const dim = (s: string) => pc.dim(s)
export const bold = (s: string) => pc.bold(s)
export const label = (s: string) => pc.cyan(s.padEnd(12))

function bigintReplacer(_k: string, v: unknown) { return typeof v === 'bigint' ? v.toString() : v }
