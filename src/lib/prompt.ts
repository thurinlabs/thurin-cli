import { createInterface } from 'node:readline'

/** Read a line from the terminal; hidden when `secret` (passwords). */
export function prompt(question: string, secret = false): Promise<string> {
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true })
    if (secret) {
      // Echo nothing: readline writes the prompt, we swallow the keystrokes' echo.
      const orig = (rl as any)._writeToOutput
      ;(rl as any)._writeToOutput = (s: string) => { if (s.includes(question)) orig.call(rl, question) }
    }
    rl.question(question, (answer) => { rl.close(); if (secret) process.stderr.write('\n'); resolve(answer) })
  })
}

export async function confirm(question: string): Promise<boolean> {
  const a = (await prompt(`${question} [y/N] `)).trim().toLowerCase()
  return a === 'y' || a === 'yes'
}
