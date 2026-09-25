import type { Server } from 'node:http'
import { CliError, EXIT } from './output.js'

export function listen(server: Server, port: number, host: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', (e: NodeJS.ErrnoException) => reject(new CliError(
      e.code === 'EADDRINUSE' ? `Port ${port} on ${host} is already in use; pick another with --port` : `Can't listen on ${host}:${port}: ${e.message}`, EXIT.USAGE)))
    server.listen(port, host, resolve)
  })
}
