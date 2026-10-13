import { spawn } from "node:child_process"
import net from "node:net"
import { randomBytes } from "node:crypto"
import { fileURLToPath } from "node:url"
import { generateToken } from "./auth.ts"
import type { RunCommand, RunResult } from "./run.ts"

// Driver-side client: what the agent core uses to own a sidecar process. Plain
// Node-compatible APIs only, so it runs identically under the Bun-compiled agent
// core and under Node in the contract tests. The sidecar itself is always spawned
// under Node (the bundled runtime), never under Bun.
export type Handshake = {
  protocol: number
  channel: string
  pid: number
}

export type Sidecar = {
  endpoint: string
  protocol: number
  pid: number
  exited: boolean
  exitCode: number | null
  handshake: () => Promise<Handshake>
  platformSupport: () => Promise<Record<string, unknown>>
  run: (command: RunCommand) => Promise<RunResult>
  shutdown: () => Promise<void>
  stop: () => void
  orphan: () => void
}

export type StartOptions = {
  node?: string
  entry?: string
  env?: Record<string, string>
  id?: string
  token?: string
}

export async function startSidecar(options: StartOptions = {}): Promise<Sidecar> {
  const id = options.id ?? randomBytes(8).toString("hex")
  const token = options.token ?? generateToken()
  const node = options.node ?? process.execPath
  const entry = options.entry ?? fileURLToPath(new URL("./main.ts", import.meta.url))
  const child = spawn(node, [entry], {
    env: { ...process.env, KILO_MXC_CONTROL_ID: id, KILO_MXC_CONTROL_TOKEN: token, ...options.env },
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  })

  const state = { exited: false, code: null as number | null }
  child.once("close", (code) => {
    state.exited = true
    state.code = code
  })

  const ready = await new Promise<{ endpoint: string; protocol: number; pid: number }>((resolve, reject) => {
    let buffer = ""
    const fail = (cause: string) => {
      child.kill()
      reject(new Error(`sidecar did not become ready: ${cause}`))
    }
    child.once("error", (err) => fail(err.message))
    child.stdout.setEncoding("utf8")
    child.stdout.on("data", (chunk: string) => {
      buffer += chunk
      const index = buffer.indexOf("\n")
      if (index < 0) return
      const line = buffer.slice(0, index)
      child.stdout.removeAllListeners("data")
      child.stderr.removeAllListeners("data")
      try {
        const payload = JSON.parse(line)
        if (payload.ready !== true || typeof payload.endpoint !== "string") throw new Error("malformed ready line")
        resolve({ endpoint: payload.endpoint, protocol: payload.protocol, pid: payload.pid })
      } catch (cause) {
        fail(cause instanceof Error ? cause.message : String(cause))
      }
    })
    child.stderr.setEncoding("utf8")
    child.stderr.on("data", (chunk: string) => fail(`stderr: ${chunk.trim()}`))
  })

  const socket = await new Promise<net.Socket>((resolve, reject) => {
    const conn = net.connect(ready.endpoint)
    conn.once("connect", () => resolve(conn))
    conn.once("error", reject)
  })
  socket.setEncoding("utf8")

  let next = 0
  let buffer = ""
  const waiting = new Map<number, { resolve: (result: any) => void; reject: (err: Error) => void }>()
  socket.on("data", (chunk: string) => {
    buffer += chunk
    let index: number
    while ((index = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, index)
      buffer = buffer.slice(index + 1)
      if (!line.trim()) continue
      const response = JSON.parse(line)
      const waiter = waiting.get(response.id)
      if (!waiter) continue
      waiting.delete(response.id)
      if (response.ok) waiter.resolve(response.result)
      else waiter.reject(new ControlError(response.error.code, response.error.message))
    }
  })

  const call = <T>(method: string, extra: Record<string, unknown> = {}) =>
    new Promise<T>((resolve, reject) => {
      const requestId = ++next
      waiting.set(requestId, { resolve: resolve as (result: any) => void, reject })
      socket.write(JSON.stringify({ id: requestId, method, ...extra }) + "\n")
    })

  return {
    endpoint: ready.endpoint,
    protocol: ready.protocol,
    pid: ready.pid,
    get exited() {
      return state.exited
    },
    get exitCode() {
      return state.code
    },
    handshake: () => call<Handshake>("handshake", { token }),
    platformSupport: () => call<Record<string, unknown>>("platformSupport"),
    run: (command: RunCommand) => call<RunResult>("run", { run: command }),
    shutdown: async () => {
      await call("shutdown")
      await new Promise<void>((resolve) => {
        if (state.exited) return resolve()
        child.once("close", () => resolve())
      })
    },
    stop: () => child.kill(),
    orphan: () => child.stdin.end(),
  }
}

export class ControlError extends Error {
  code: string

  constructor(code: string, message: string) {
    super(message)
    this.code = code
  }
}
