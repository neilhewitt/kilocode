// The sidecar-owned loopback HTTP/S proxy enforcing the hostname egress
// allowlist (ADR 0003, MXC Model 2). Each proxied run gets its own proxy bound
// to an ephemeral 127.0.0.1 port; MXC pins the container's egress to exactly
// that endpoint, so this process is the sole sanctioned loopback peer for the
// confined command.
//
// Unlike the macOS backend's proxy there is no Proxy-Authorization challenge:
// WinHTTP-stack clients inside the container receive the per-container proxy
// configuration without credentials and would fail a 407, and the containment
// boundary is what authorises the client — per-container WFP permits egress
// only to this endpoint, while host-side processes are trusted computing base.
//
// CONNECT tunnels are gated on a TLS ClientHello whose SNI matches the
// allowlisted destination (dialling happens only after validation), and plain
// HTTP is forwarded for absolute-URI requests. Everything else fails closed.

import { request as requestHttp } from "node:http"
import { request as requestHttps } from "node:https"
import { connect, type Socket } from "node:net"
import { createServer, type IncomingHttpHeaders, type Server } from "node:http"
import {
  normalizeDestinations,
  parseDestination,
  resolveDestination,
  type Destination,
  type ResolvedDestination,
} from "./destination.ts"
import { TlsClientHello } from "./tls-client-hello.ts"

export type EgressProxyResolver = (destination: Destination) => Promise<ResolvedDestination>

export type EgressProxyOptions = {
  readonly allowedHosts: ReadonlyArray<string>
  readonly resolve?: EgressProxyResolver | undefined
  readonly log?: ((message: string) => void) | undefined
}

export type EgressProxy = {
  readonly endpoint: string
  readonly port: number
  readonly close: () => Promise<void>
}

function headers(input: IncomingHttpHeaders, host?: string) {
  const connection = new Set((input.connection ?? "").split(",").map((value) => value.trim().toLowerCase()))
  const blocked = new Set([
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    ...connection,
  ])
  return Object.fromEntries(
    Object.entries({ ...input, ...(host ? { host } : {}) }).filter(
      ([key, value]) => value !== undefined && !blocked.has(key.toLowerCase()),
    ),
  )
}

function shutdown(server: Server, sockets: Set<Socket>) {
  return new Promise<void>((resolve) => {
    for (const socket of sockets) socket.destroy()
    server.close(() => resolve())
  })
}

export async function createEgressProxy(options: EgressProxyOptions): Promise<EgressProxy> {
  const allowed = new Set(normalizeDestinations(options.allowedHosts))
  const resolve = options.resolve ?? resolveDestination
  const log = options.log ?? (() => {})
  const sockets = new Set<Socket>()
  const server = createServer({ maxHeaderSize: 16 * 1024, requestTimeout: 30_000 })
  server.on("connection", (socket) => {
    sockets.add(socket)
    socket.once("close", () => sockets.delete(socket))
  })

  server.on("connect", (request, client, head) => {
    client.on("error", () => undefined)
    try {
      const destination = parseDestination(request.url ?? "")
      if (!allowed.has(destination.authority)) {
        log(`denied CONNECT ${destination.authority}`)
        client.end("HTTP/1.1 403 Forbidden\r\n\r\n")
        return
      }
      const hello = new TlsClientHello(destination.host)
      let upstream: Socket | undefined
      let dialing = false
      let connected = false
      let tunneled = false
      const fail = () => {
        clearTimeout(timer)
        upstream?.destroy()
        client.destroy()
      }
      const timer = setTimeout(fail, 30_000)
      timer.unref()
      const forward = () => {
        if (!upstream || !connected || tunneled || client.destroyed || hello.push(Buffer.alloc(0)) !== "valid") return
        clearTimeout(timer)
        client.pause()
        client.off("data", inspect)
        tunneled = true
        upstream.pipe(client)
        const pipe = () => {
          if (!upstream || client.destroyed) {
            upstream?.destroy()
            return
          }
          client.pipe(upstream)
        }
        if (upstream.write(hello.bytes())) pipe()
        else upstream.once("drain", pipe)
      }
      const inspect = (chunk: Buffer) => {
        const state = hello.push(chunk)
        if (state === "invalid") {
          log(`cut CONNECT ${destination.authority}: no matching TLS ClientHello`)
          fail()
          return
        }
        if (dialing) {
          if (state === "valid") forward()
          return
        }
        if (state === "pending") return
        dialing = true
        void resolve(destination).then(
          (resolved) => {
            if (client.destroyed) return
            log(`tunnel CONNECT ${destination.authority} -> ${resolved.address}`)
            upstream = connect({ host: resolved.address, port: destination.port, family: resolved.family })
            upstream.on("error", fail)
            upstream.once("connect", () => {
              if (!upstream || client.destroyed) {
                upstream?.destroy()
                return
              }
              connected = true
              forward()
            })
          },
          (cause) => {
            log(`refused CONNECT ${destination.authority}: ${cause instanceof Error ? cause.message : String(cause)}`)
            fail()
          },
        )
      }
      client.on("data", inspect)
      client.once("end", () => {
        if (!tunneled) fail()
      })
      client.once("close", () => {
        clearTimeout(timer)
        upstream?.destroy()
      })
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n")
      if (head.length > 0) inspect(head)
    } catch {
      client.end("HTTP/1.1 502 Bad Gateway\r\n\r\n")
    }
  })

  server.on("request", (request, response) => {
    void (async () => {
      try {
        const url = new URL(request.url ?? "")
        if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password) throw new Error()
        const destination = parseDestination(`${url.hostname}:${url.port || (url.protocol === "https:" ? "443" : "80")}`)
        if (!allowed.has(destination.authority)) {
          log(`denied ${request.method ?? ""} ${destination.authority}`)
          response.writeHead(403)
          response.end()
          return
        }
        const resolved = await resolve(destination)
        const send = url.protocol === "https:" ? requestHttps : requestHttp
        const upstream = send(
          {
            hostname: resolved.address,
            family: resolved.family,
            port: destination.port,
            servername: destination.host,
            method: request.method,
            path: `${url.pathname}${url.search}`,
            headers: headers(request.headers, url.host),
          },
          (incoming) => {
            response.writeHead(incoming.statusCode ?? 502, headers(incoming.headers))
            incoming.pipe(response)
          },
        )
        upstream.on("error", () => {
          if (!response.headersSent) response.writeHead(502)
          response.end()
        })
        response.once("close", () => upstream.destroy())
        request.pipe(upstream)
      } catch {
        response.writeHead(400)
        response.end()
      }
    })()
  })

  server.on("clientError", (_cause, socket) => socket.end("HTTP/1.1 400 Bad Request\r\n\r\n"))

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject)
    server.listen({ host: "127.0.0.1", port: 0 }, () => {
      server.off("error", reject)
      resolve()
    })
  })
  const address = server.address()
  const port = typeof address === "object" && address ? address.port : undefined
  if (!port) throw new Error("The egress proxy did not bind a TCP port")

  return {
    endpoint: `http://127.0.0.1:${port}`,
    port,
    close: () => shutdown(server, sockets),
  }
}
