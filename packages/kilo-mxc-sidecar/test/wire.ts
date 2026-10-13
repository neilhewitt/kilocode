import net from "node:net"

// Minimal adversarial wire client for contract tests: raw line framing without
// the production client's conveniences, so rejection paths can be exercised the
// way a non-user principal or unauthenticated caller would see them.
export class Wire {
  socket: net.Socket
  buffer = ""
  pending: { resolve: (line: string) => void; reject: (err: Error) => void }[] = []
  lines: string[] = []
  closed = false

  constructor(socket: net.Socket) {
    this.socket = socket
    socket.setEncoding("utf8")
    socket.on("data", (chunk: string) => {
      this.buffer += chunk
      let index: number
      while ((index = this.buffer.indexOf("\n")) >= 0) {
        const line = this.buffer.slice(0, index)
        this.buffer = this.buffer.slice(index + 1)
        const waiter = this.pending.shift()
        if (waiter) waiter.resolve(line)
        else this.lines.push(line)
      }
    })
    socket.on("close", () => {
      this.closed = true
      for (const waiter of this.pending) waiter.reject(new Error("connection closed"))
    })
    socket.on("error", () => {})
  }

  next() {
    const queued = this.lines.shift()
    if (queued) return Promise.resolve(queued)
    return new Promise<string>((resolve, reject) => this.pending.push({ resolve, reject }))
  }

  send(payload: object) {
    this.socket.write(JSON.stringify(payload) + "\n")
  }
}

export async function connect(endpoint: string) {
  const socket = await new Promise<net.Socket>((resolve, reject) => {
    const conn = net.connect(endpoint)
    conn.once("connect", () => resolve(conn))
    conn.once("error", reject)
  })
  return new Wire(socket)
}

export function until(predicate: () => boolean, ms = 5000) {
  return new Promise<void>((resolve, reject) => {
    const started = Date.now()
    const check = () => {
      if (predicate()) return resolve()
      if (Date.now() - started > ms) return reject(new Error("condition not met within 5s"))
      setTimeout(check, 25)
    }
    check()
  })
}
