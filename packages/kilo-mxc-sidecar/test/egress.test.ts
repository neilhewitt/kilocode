import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { connect } from "node:net"
import { readFileSync, rmSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { withEgressProxy } from "../src/egress.ts"
import type { RunCommand, RunHandle, RunResult } from "../src/run.ts"
import type { RunBindings, Runtime } from "../src/sdk.ts"
import { startSidecar } from "../src/client.ts"

// The egress wrapper owns the proxy half of Model 2: a proxied run must be
// pinned to a live loopback proxy for exactly the run's lifetime, and a cidr
// relaxation must be recorded in the result the caller sees.

const runtimeFixture = fileURLToPath(new URL("./fixtures/scripted-runtime.mjs", import.meta.url))

function command(egress: RunCommand["network"]["egress"]): RunCommand {
  return {
    command: "cmd /c echo hi",
    filesystem: { readwritePaths: ["C:\\w"], readonlyPaths: [], deniedPaths: [] },
    network: { egress },
    environment: {},
  }
}

function free(port: number) {
  return new Promise<boolean>((resolve) => {
    const socket = connect(port, "127.0.0.1")
    socket.once("error", (cause: NodeJS.ErrnoException) => resolve(cause.code === "ECONNREFUSED"))
    socket.once("connect", () => {
      socket.destroy()
      resolve(false)
    })
  })
}

async function freed(port: number, ms = 5000) {
  const deadline = Date.now() + ms
  while (Date.now() < deadline) {
    if (await free(port)) return true
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
  return false
}

function portOf(bindings: RunBindings) {
  const match = /^http:\/\/127\.0\.0\.1:(\d+)$/.exec(bindings.networkProxy ?? "")
  if (!match) throw new Error(`no loopback proxy endpoint in ${JSON.stringify(bindings)}`)
  return Number(match[1])
}

function recording(mode: "settle" | "hang" = "settle") {
  const calls: Array<{ command: RunCommand; bindings: RunBindings }> = []
  const runtime: Runtime = {
    getPlatformSupport: async () => ({ isSupported: true, source: "scripted" }),
    run: async (command, bindings = {}) => {
      calls.push({ command, bindings })
      const handle: RunHandle = {
        wait: () =>
          mode === "hang"
            ? new Promise<RunResult>(() => {})
            : Promise.resolve({ exitCode: 0, stdout: "", stderr: "", timedOut: false, warnings: [] }),
        kill: () => {},
      }
      return handle
    },
  }
  return { runtime, calls }
}

describe("egress wrapper", () => {
  test("pins a proxied run to a live loopback proxy and closes it when the run settles", async () => {
    const { runtime, calls } = recording()
    const wrapped = withEgressProxy(runtime)
    const handle = await wrapped.run(command({ default: "proxy", allowedHosts: ["registry.npmjs.org:443"] }))
    assert.equal(calls.length, 1)
    const port = portOf(calls[0].bindings)
    assert.equal(await free(port), false, "the proxy must be listening while the run is live")
    const result = await handle.wait()
    assert.equal(result.exitCode, 0)
    assert.ok(await freed(port), "the proxy must be gone once the run settles")
  })

  test("closes the proxy when the run is killed", async () => {
    const { runtime, calls } = recording("hang")
    const wrapped = withEgressProxy(runtime)
    const handle = await wrapped.run(command({ default: "proxy", allowedHosts: ["example.com:443"] }))
    const port = portOf(calls[0].bindings)
    assert.equal(await free(port), false)
    handle.kill()
    assert.ok(await freed(port), "the proxy must be gone once the run is killed")
  })

  test("records a cidr relaxation in the run's warnings", async () => {
    const { runtime } = recording()
    const wrapped = withEgressProxy(runtime)
    const handle = await wrapped.run(
      command({
        default: "cidr",
        allow: [
          { to: ["140.82.112.0/20"], ports: [{ protocol: "tcp", port: 22 }] },
          { to: ["10.0.0.0/8"] },
        ],
      }),
    )
    const result = await handle.wait()
    assert.equal(result.warnings.length, 2)
    assert.match(result.warnings[0], /egress relaxation: 140\.82\.112\.0\/20 \[tcp:22\]/)
    assert.match(result.warnings[1], /egress relaxation: 10\.0\.0\.0\/8 \[any\]/)
  })

  test("starts no proxy for deny, allow, and cidr runs", async () => {
    const { runtime, calls } = recording()
    const wrapped = withEgressProxy(runtime)
    for (const egress of [
      { default: "deny" },
      { default: "allow" },
      { default: "cidr", allow: [{ to: ["10.0.0.0/8"] }] },
    ] as const) {
      const handle = await wrapped.run(command(egress))
      await handle.wait()
    }
    assert.equal(calls.length, 3)
    for (const entry of calls) assert.equal(entry.bindings.networkProxy, undefined)
  })

  test("closeProxies releases proxies of still-running proxied runs", async () => {
    const { runtime, calls } = recording("hang")
    const wrapped = withEgressProxy(runtime)
    const handle = await wrapped.run(command({ default: "proxy", allowedHosts: ["example.com:443"] }))
    const port = portOf(calls[0].bindings)
    assert.equal(await free(port), false)
    await wrapped.closeProxies()
    assert.ok(await free(port), "shutdown must leave no orphaned proxy listener")
    handle.kill()
  })

  test("a spawned sidecar shuts down without orphaning its run proxy", async (t) => {
    const log = path.join(import.meta.dirname, "egress-events.tmp.jsonl")
    rmSync(log, { force: true })
    const sidecar = await startSidecar({
      env: {
        KILO_MXC_RUNTIME_MODULE: runtimeFixture,
        KILO_MXC_SCRIPT_HANG: "1",
        KILO_MXC_SCRIPT_EVENTS: log,
      },
    })
    try {
      await sidecar.handshake()
      // The run hangs on purpose; it settles with a rejection when the
      // sidecar exits, so the catch is attached immediately.
      sidecar.run(command({ default: "proxy", allowedHosts: ["example.com:443"] })).catch(() => {})
      const deadline = Date.now() + 5000
      let port = 0
      while (Date.now() < deadline) {
        try {
          const events = readFileSync(log, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line))
          const binding = events.find((entry) => entry.type === "run" && entry.bindings?.networkProxy)
          if (binding) {
            port = portOf({ networkProxy: binding.bindings.networkProxy })
            break
          }
        } catch {
          // the events file appears once the sidecar records the run
        }
        await new Promise((resolve) => setTimeout(resolve, 25))
      }
      assert.ok(port > 0, "the sidecar must record the proxy endpoint it pinned the run to")
      assert.equal(await free(port), false, "the sidecar proxy must be live during the run")
      await sidecar.shutdown()
      assert.ok(await freed(port), "the proxy listener must die with the sidecar")
      t.after(() => rmSync(log, { force: true }))
    } finally {
      rmSync(log, { force: true })
      await sidecar.shutdown().catch(() => sidecar.stop())
    }
  })
})
