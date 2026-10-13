import { after, describe, test } from "node:test"
import assert from "node:assert/strict"
import { connect, createServer, type Socket } from "node:net"
import http, { request as requestHttp } from "node:http"
import { createEgressProxy, type EgressProxyResolver } from "../src/proxy.ts"

// The egress proxy is the sidecar's enforcement point for hostname-allowlisted
// egress (ADR 0003). These tests exercise its public seam only: what a client
// can reach through it, what fails closed, and that close() leaves no listener.

const cleanup: Array<() => void> = []

function uint16(value: number) {
  const buffer = Buffer.alloc(2)
  buffer.writeUInt16BE(value, 0)
  return buffer
}

function extension(type: number, data: Buffer) {
  return Buffer.concat([uint16(type), uint16(data.length), data])
}

function record(type: number, data: Buffer, minor = 1) {
  return Buffer.concat([Buffer.from([type, 3, minor]), uint16(data.length), data])
}

function hello(host?: string, extra: Buffer[] = []) {
  const name = host ? Buffer.from(host, "ascii") : undefined
  const sni = name
    ? extension(0, Buffer.concat([uint16(name.length + 3), Buffer.from([0]), uint16(name.length), name]))
    : Buffer.alloc(0)
  const extensions = Buffer.concat([sni, ...extra])
  const body = Buffer.concat([
    Buffer.from([3, 3]),
    Buffer.alloc(32),
    Buffer.from([0]),
    uint16(2),
    Buffer.from([0x13, 0x01]),
    Buffer.from([1, 0]),
    uint16(extensions.length),
    extensions,
  ])
  const header = Buffer.alloc(4)
  header[0] = 1
  header.writeUIntBE(body.length, 1, 3)
  return record(22, Buffer.concat([header, body]))
}

function echo() {
  const accepted: Socket[] = []
  const received: Buffer[] = []
  const server = createServer((socket) => {
    accepted.push(socket)
    socket.on("data", (chunk: Buffer) => received.push(chunk))
    socket.pipe(socket)
  })
  const listening = new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  cleanup.push(() => {
    for (const socket of accepted) socket.destroy()
    server.close()
  })
  const ready = listening.then(() => server.address())
  return {
    ready,
    port: async () => {
      const address = await ready
      assert.ok(typeof address === "object" && address, "echo server must bind")
      return address.port
    },
    accepted: () => accepted.length,
    bytes: () => Buffer.concat(received).length,
  }
}

function httpUpstream() {
  const seen: string[] = []
  const sockets: Socket[] = []
  const server = http.createServer((request, response) => {
    seen.push(`${request.method} ${request.url}`)
    response.writeHead(200, { "content-type": "text/plain" })
    response.end("upstream-ok")
  })
  server.on("connection", (socket) => sockets.push(socket))
  const listening = new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  cleanup.push(() => {
    for (const socket of sockets) socket.destroy()
    server.close()
  })
  return {
    port: async () => {
      await listening
      const address = server.address()
      assert.ok(typeof address === "object" && address, "http upstream must bind")
      return address.port
    },
    seen: () => seen,
  }
}

function localResolver(port: number, calls?: string[]): EgressProxyResolver {
  return (destination) => {
    calls?.push(destination.authority)
    if (destination.port !== port) throw new Error(`unexpected port ${destination.port}`)
    return Promise.resolve({ address: "127.0.0.1", family: 4 })
  }
}

async function tunnel(proxy: { port: number }, authority: string) {
  const socket = connect(proxy.port, "127.0.0.1")
  cleanup.push(() => socket.destroy())
  const header = await new Promise<string>((resolve, reject) => {
    let buffer = ""
    const fail = (cause: Error) => {
      socket.destroy()
      reject(cause)
    }
    socket.on("error", fail)
    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("latin1")
      const end = buffer.indexOf("\r\n\r\n")
      if (end < 0) return
      socket.off("error", fail)
      socket.removeAllListeners("data")
      resolve(buffer.slice(0, end))
    })
    socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`)
  })
  return { socket, header }
}

function closed(socket: Socket) {
  return new Promise<void>((resolve) => {
    if (socket.closed) return resolve()
    socket.once("close", () => resolve())
  })
}

function receive(socket: Socket, length: number) {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = []
    const fail = (cause: Error) => reject(cause)
    socket.on("error", fail)
    socket.on("data", (chunk: Buffer) => {
      chunks.push(chunk)
      const result = Buffer.concat(chunks)
      if (result.length >= length) {
        socket.off("error", fail)
        socket.removeAllListeners("data")
        resolve(result.subarray(0, length))
      }
    })
  })
}

describe("egress proxy", () => {
  after(() => {
    for (const stop of cleanup) stop()
  })

  test("binds only loopback and reports the endpoint", async () => {
    const proxy = await createEgressProxy({ allowedHosts: [], resolve: localResolver(0) })
    cleanup.push(() => void proxy.close())
    assert.equal(proxy.endpoint, `http://127.0.0.1:${proxy.port}`)
  })

  test("tunnels CONNECT for an allowlisted authority after a matching ClientHello", async () => {
    const upstream = echo()
    const port = await upstream.port()
    const calls: string[] = []
    const proxy = await createEgressProxy({ allowedHosts: [`allowed.test:${port}`], resolve: localResolver(port, calls) })
    cleanup.push(() => void proxy.close())
    const { socket, header } = await tunnel(proxy, `allowed.test:${port}`)
    assert.match(header, /^HTTP\/1\.1 200/)
    const input = Buffer.concat([hello("ALLOWED.TEST"), record(20, Buffer.from([1]), 3)])
    const output = receive(socket, input.length)
    socket.write(input)
    assert.deepEqual(await output, input)
    assert.equal(upstream.bytes(), input.length)
    assert.deepEqual(calls, [`allowed.test:${port}`])
  })

  test("fails CONNECT closed with 403 for a non-allowlisted authority", async () => {
    const upstream = echo()
    const port = await upstream.port()
    const calls: string[] = []
    const proxy = await createEgressProxy({ allowedHosts: [`allowed.test:${port}`], resolve: localResolver(port, calls) })
    cleanup.push(() => void proxy.close())
    const { socket, header } = await tunnel(proxy, `blocked.test:${port}`)
    assert.match(header, /^HTTP\/1\.1 403/)
    await closed(socket)
    assert.equal(upstream.accepted(), 0)
    assert.deepEqual(calls, [])
  })

  test("cuts CONNECT when the ClientHello SNI does not match the dialled destination", async () => {
    const upstream = echo()
    const port = await upstream.port()
    const calls: string[] = []
    const proxy = await createEgressProxy({ allowedHosts: [`allowed.test:${port}`], resolve: localResolver(port, calls) })
    cleanup.push(() => void proxy.close())
    for (const input of [hello("blocked.test"), hello()]) {
      const { socket } = await tunnel(proxy, `allowed.test:${port}`)
      const end = closed(socket)
      socket.write(input)
      await end
    }
    assert.equal(upstream.accepted(), 0)
    assert.deepEqual(calls, [])
  })

  test("fails CONNECT closed on malformed or encrypted ClientHello", async () => {
    const upstream = echo()
    const port = await upstream.port()
    const proxy = await createEgressProxy({ allowedHosts: [`allowed.test:${port}`], resolve: localResolver(port) })
    cleanup.push(() => void proxy.close())
    const malformed = hello("allowed.test")
    malformed.writeUInt16BE(0xffff, 50)
    const encrypted = hello("allowed.test", [extension(0xfe0d, Buffer.from([0]))])
    for (const input of [Buffer.from("GET /"), malformed, encrypted]) {
      const { socket } = await tunnel(proxy, `allowed.test:${port}`)
      const end = closed(socket)
      socket.write(input)
      await end
    }
    const { socket } = await tunnel(proxy, `allowed.test:${port}`)
    const end = closed(socket)
    socket.end(hello("allowed.test").subarray(0, -1))
    await end
    assert.equal(upstream.accepted(), 0)
    assert.equal(upstream.bytes(), 0)
  })

  test("forwards absolute-URI HTTP requests for an allowlisted authority", async () => {
    const upstream = httpUpstream()
    const port = await upstream.port()
    const proxy = await createEgressProxy({ allowedHosts: [`allowed.test:${port}`], resolve: localResolver(port) })
    cleanup.push(() => void proxy.close())
    const response = await new Promise<string>((resolve, reject) => {
      const request = requestHttp({
        host: "127.0.0.1",
        port: proxy.port,
        method: "GET",
        path: `http://allowed.test:${port}/path`,
        headers: { host: `allowed.test:${port}` },
      })
      request.on("response", (incoming) => {
        let body = ""
        incoming.setEncoding("utf8")
        incoming.on("data", (chunk: string) => {
          body += chunk
        })
        incoming.on("end", () => resolve(body))
      })
      request.on("error", reject)
      request.end()
    })
    assert.equal(response, "upstream-ok")
    assert.deepEqual(upstream.seen(), ["GET /path"])
  })

  test("answers 403 for an absolute-URI request outside the allowlist", async () => {
    const upstream = httpUpstream()
    const port = await upstream.port()
    const proxy = await createEgressProxy({ allowedHosts: [`allowed.test:${port}`], resolve: localResolver(port) })
    cleanup.push(() => void proxy.close())
    const status = await new Promise<number>((resolve, reject) => {
      const request = requestHttp({
        host: "127.0.0.1",
        port: proxy.port,
        method: "GET",
        path: `http://blocked.test:${port}/path`,
        headers: { host: `blocked.test:${port}` },
      })
      request.on("response", (incoming) => resolve(incoming.statusCode ?? 0))
      request.on("error", reject)
      request.end()
    })
    assert.equal(status, 403)
    assert.deepEqual(upstream.seen(), [])
  })

  test("refuses non-public resolved addresses with the default resolver", async () => {
    const proxy = await createEgressProxy({ allowedHosts: ["localhost:443"] })
    cleanup.push(() => void proxy.close())
    const { socket, header } = await tunnel(proxy, "localhost:443")
    assert.match(header, /^HTTP\/1\.1 200/)
    const end = closed(socket)
    socket.write(hello("localhost"))
    await end
  })

  test("close() releases the listener", async () => {
    const proxy = await createEgressProxy({ allowedHosts: [], resolve: localResolver(0) })
    const port = proxy.port
    await proxy.close()
    const refused = await new Promise<boolean>((resolve) => {
      const socket = connect(port, "127.0.0.1")
      socket.once("error", (cause: NodeJS.ErrnoException) => resolve(cause.code === "ECONNREFUSED"))
      socket.once("connect", () => {
        socket.destroy()
        resolve(false)
      })
    })
    assert.equal(refused, true, "the proxy port must be free after close")
  })
})
