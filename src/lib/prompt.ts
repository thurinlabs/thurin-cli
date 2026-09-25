import { createInterface } from 'node:readline'

/** Read a line from the terminal; hidden when `secret` (passwords). */
export function prompt(question: string, secret = false): Promise<string> {
  if (secret) return readHidden(question)
  return new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true })
    rl.question(question, (answer) => { rl.close(); resolve(answer) })
  })
}

/**
 * A password, echoing nothing: the terminal in raw mode, keys read one by one. Backspace and Ctrl-U
 * edit, arrow keys and other escape sequences are ignored, Ctrl-C cancels. Piped input (no terminal)
 * is read as one line.
 */
function readHidden(question: string): Promise<string> {
  return new Promise((resolve) => {
    const input = process.stdin
    process.stderr.write(question)
    if (!input.isTTY) {
      const rl = createInterface({ input, terminal: false })
      rl.once('line', (line) => { rl.close(); resolve(line) })
      return
    }
    let value = ''
    const finish = () => {
      input.removeListener('data', onData)
      input.setRawMode(false)
      input.pause()
      process.stderr.write('\n')
      resolve(value)
    }
    const onData = (chunk: string) => {
      for (let i = 0; i < chunk.length; i++) {
        const ch = chunk[i]
        if (ch === '\r' || ch === '\n' || ch === '\u0004') return finish()       // Enter, Ctrl-D
        if (ch === '\u0003') { input.setRawMode(false); process.stderr.write('\n'); process.exit(130) }   // Ctrl-C
        if (ch === '\u007f' || ch === '\b') { value = value.slice(0, -1); continue }   // Backspace
        if (ch === '\u0015') { value = ''; continue }                              // Ctrl-U
        if (ch === '\u001b') {                                                     // an escape sequence (arrows…): skip it
          if (chunk[i + 1] === '[' || chunk[i + 1] === 'O') { i += 2; while (i < chunk.length && !/[A-Za-z~]/.test(chunk[i])) i++ }
          continue
        }
        if (ch < ' ') continue
        value += ch
      }
    }
    input.setRawMode(true)
    input.setEncoding('utf8')
    input.resume()
    input.on('data', onData)
  })
}

export async function confirm(question: string): Promise<boolean> {
  const a = (await prompt(`${question} [y/N] `)).trim().toLowerCase()
  return a === 'y' || a === 'yes'
}
