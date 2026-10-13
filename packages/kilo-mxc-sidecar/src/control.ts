import net from "node:net"
import { chmodSync, mkdirSync, rmSync } from "node:fs"
import { dirname } from "node:path"
import { tokensMatch } from "./auth.ts"
import { PROTOCOL_VERSION, error, isRequest, ok, type Request, type Response } from "./protocol.ts"
import type { Runtime } from "./sdk.ts"

// The control-channel server. Each connection is a fresh NDJSON exchange: the
// first line must be an authenticated handshake, after which the connection stays
// authorised for its lifetime. Failed authentication answers with an
// `unauthorized` error and drops the connection.
export type ControlServer = {
  endpoint: string
  listen: () => Promise<void>
  close: () => Promise<void>
  stop: () => Promise<void>
  onShutdown: (handler: () => Promise<void>) => void
}

export type ControlOptions = {
  runtime: Runtime
  endpoint: string
  token: string
}

function respond(socket: net.Socket, response: Response) {
  return new Promise<void>((resolve) => socket.write(JSON.stringify(response) + "\n", () => resolve()))
}

export function createControlServer(options: ControlOptions): ControlServer {
  const { runtime, endpoint, token } = options
  let shutdownHandler: (() => Promise<void>) | undefined
  const connections = new Set<net.Socket>()

  const handle = async (socket: net.Socket, request: Request): Promise<void> => {
    if (request.method === "platformSupport") {
      try {
        await respond(socket, ok(request.id, await runtime.getPlatformSupport()))
      } catch (cause) {
        await respond(socket, error(request.id, "internal_error", cause instanceof Error ? cause.message : String(cause)))
      }
      return
    }
    if (request.method === "shutdown") {
      await respond(socket, ok(request.id, null))
      const handler = shutdownHandler
      if (handler) await handler()
      return
    }
    await respond(socket, error(request.id, "unknown_method", `method ${request.method} is not part of the control protocol`))
  }

  const server = net.createServer((socket) => {
    let buffer = ""
    let authorised = false
    connections.add(socket)
    socket.once("close", () => connections.delete(socket))
    socket.setEncoding("utf8")
    socket.on("data", (chunk: string) => {
      buffer += chunk
      let index: number
      while ((index = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, index)
        buffer = buffer.slice(index + 1)
        if (!line.trim()) continue
        let parsed: unknown
        try {
          parsed = JSON.parse(line)
        } catch {
          void respond(socket, error(0, "invalid_request", "requests must be single-line JSON objects"))
          socket.end()
          return
        }
        if (!isRequest(parsed)) {
          void respond(socket, error(0, "invalid_request", "requests must carry a numeric id and a known method"))
          socket.end()
          return
        }
        // Authorisation is decided synchronously with the line stream, so a
        // pipelined request right behind its handshake is never misjudged.
        if (parsed.method === "handshake") {
          if (typeof parsed.token === "string" && tokensMatch(parsed.token, token)) {
            authorised = true
            void respond(socket, ok(parsed.id, { protocol: PROTOCOL_VERSION, channel: "control", pid: process.pid }))
          } else {
            void respond(socket, error(parsed.id, "unauthorized", "control token rejected"))
            socket.end()
          }
          continue
        }
        if (!authorised) {
          void respond(socket, error(parsed.id, "unauthorized", "handshake required"))
          socket.end()
          return
        }
        void handle(socket, parsed)
      }
    })
    socket.on("error", () => {})
  })

  const close = () =>
    new Promise<void>((resolve) => {
      server.close(() => {
        if (process.platform !== "win32") {
          rmSync(endpoint, { force: true })
          rmSync(dirname(endpoint), { recursive: true, force: true })
        }
        resolve()
      })
    })

  return {
    endpoint,
    listen: () =>
      new Promise<void>((resolve, reject) => {
        if (process.platform !== "win32") {
          rmSync(endpoint, { force: true })
          mkdirSync(dirname(endpoint), { recursive: true, mode: 0o700 })
          chmodSync(dirname(endpoint), 0o700)
        }
        server.once("error", reject)
        server.listen(endpoint, () => {
          if (process.platform !== "win32") chmodSync(endpoint, 0o600)
          resolve()
        })
      }),
    close,
    stop: async () => {
      for (const socket of connections) socket.end()
      await close()
    },
    onShutdown: (handler) => {
      shutdownHandler = handler
    },
  }
}
