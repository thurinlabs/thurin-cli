import { spawn } from 'node:child_process'
import { dim } from './output.js'

/**
 * After a link is printed: at an interactive terminal with a display, Enter opens it in the default
 * browser; Ctrl-C (or anything else) leaves it. Scripts, --json, and SSH sessions just get the link.
 */
export async function offerToOpen(url: string, json: boolean): Promise<void> {
  if (json || !process.stdin.isTTY || !process.stderr.isTTY) return
  const opener = process.platform === 'darwin' ? ['open', url]
    : process.platform === 'win32' ? ['cmd', '/c', 'start', '', url]
    : (process.env.DISPLAY || process.env.WAYLAND_DISPLAY) ? ['xdg-open', url] : null
  if (!opener) return
  process.stderr.write(dim('Press Enter to open it in your browser, or Ctrl-C to leave it. '))
  const pressed = await new Promise<boolean>((resolve) => {
    const input = process.stdin
    input.setRawMode(true); input.setEncoding('utf8'); input.resume()
    input.once('data', (ch: string) => { input.setRawMode(false); input.pause(); process.stderr.write('\n'); resolve(ch === '\r' || ch === '\n') })
  })
  if (!pressed) return
  try {
    const child = spawn(opener[0], opener.slice(1), { detached: true, stdio: 'ignore' })
    child.on('error', () => process.stderr.write("Couldn't open a browser; copy the link above.\n"))
    child.unref()
  } catch {
    process.stderr.write("Couldn't open a browser; copy the link above.\n")
  }
}
