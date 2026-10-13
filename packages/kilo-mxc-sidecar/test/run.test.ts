import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { createControlServer } from "../src/control.ts"
import { isRunCommand } from "../src/run.ts"
import type { RunCommand, RunHandle, RunResult } from "../src/run.ts"
import type { Runtime } from "../src/sdk.ts"
import { generateToken } from "../src/auth.ts"
import { controlEndpoint } from "../src/endpoint.ts"
import { connect, until } from "./wire.ts"
import { startSidecar } from "../src/client.ts"
import { fileURLToPath } from "node:url"

const runtimeFixture = fileURLToPath(new URL("./fixtures/scripted-runtime.mjs", import.meta.url))

function runCommand(partial: Partial<RunCommand> = {}): RunCommand {
  return {
    command: 'cmd /c "echo confined"',
    workingDirectory: "C:\\workspace",
    filesystem: {
      readwritePaths: ["C:\\workspace"],
      readonlyPaths: ["C:\\Windows"],
      deniedPaths: ["C:\\workspace\\.env"],
    },
    network: { egress: { default: "deny" } },
    environment: { PATH: "C:\\Windows\\System32" },
    ...partial,
  }
}

function scripted(result: Partial<RunResult> = {}): { runtime: Runtime; seen: RunCommand[] } {
  const seen: RunCommand[] = []
  const runtime: Runtime = {
    getPlatformSupport: async () => ({ isSupported: true, source: "scripted" }),
    run: async (command) => {
      seen.push(command)
      const handle: RunHandle = {
        wait: () => Promise.resolve({ exitCode: 0, stdout: "", stderr: "", timedOut: false, warnings: [], ...result }),
        kill: () => {},
      }
      return handle
    },
  }
  return { runtime, seen }
}

function hanging(started: () => void): { runtime: Runtime; killed: () => boolean } {
  let killCount = 0
  const runtime: Runtime = {
    getPlatformSupport: async () => ({ isSupported: true, source: "scripted" }),
    run: async () => {
      started()
      const handle: RunHandle = {
        wait: () => new Promise<RunResult>(() => {}),
        kill: () => {
          killCount += 1
        },
      }
      return handle
    },
  }
  return { runtime, killed: () => killCount > 0 }
}

function id() {
  return Math.random().toString(16).slice(2, 10)
}

describe("run payload egress validation", () => {
  test("accepts the four egress postures", () => {
    const base = runCommand()
    assert.equal(isRunCommand({ ...base, network: { egress: { default: "deny" } } }), true)
    assert.equal(isRunCommand({ ...base, network: { egress: { default: "allow" } } }), true)
    assert.equal(
      isRunCommand({ ...base, network: { egress: { default: "proxy", allowedHosts: ["registry.npmjs.org:443"] } } }),
      true,
    )
    assert.equal(
      isRunCommand({
        ...base,
        network: {
          egress: {
            default: "cidr",
            allow: [{ to: ["140.82.112.0/20"], ports: [{ protocol: "tcp", port: 443 }] }],
          },
        },
      }),
      true,
    )
  })

  test("accepts a cidr rule without ports (every port) and with a range", () => {
    const base = runCommand()
    assert.equal(isRunCommand({ ...base, network: { egress: { default: "cidr", allow: [{ to: ["0.0.0.0/0"] }] } } }), true)
    assert.equal(
      isRunCommand({
        ...base,
        network: {
          egress: { default: "cidr", allow: [{ to: ["10.0.0.0/8"], ports: [{ protocol: "udp", port: 53, endPort: 55 }] }] },
        },
      }),
      true,
    )
  })

  test("rejects a proxy egress without a string-array allowlist", () => {
    const base = runCommand()
    assert.equal(isRunCommand({ ...base, network: { egress: { default: "proxy" } } }), false)
    assert.equal(isRunCommand({ ...base, network: { egress: { default: "proxy", allowedHosts: "registry.npmjs.org" } } }), false)
    assert.equal(isRunCommand({ ...base, network: { egress: { default: "proxy", allowedHosts: [443] } } }), false)
  })

  test("rejects a cidr egress without a non-empty rule array", () => {
    const base = runCommand()
    assert.equal(isRunCommand({ ...base, network: { egress: { default: "cidr" } } }), false)
    assert.equal(isRunCommand({ ...base, network: { egress: { default: "cidr", allow: [] } } }), false)
    assert.equal(isRunCommand({ ...base, network: { egress: { default: "cidr", allow: [{ to: "10.0.0.0/8" }] } } }), false)
    assert.equal(
      isRunCommand({ ...base, network: { egress: { default: "cidr", allow: [{ to: [7], ports: [] }] } } }),
      false,
    )
  })

  test("rejects an unknown egress default", () => {
    const base = runCommand()
    assert.equal(isRunCommand({ ...base, network: { egress: { default: "open" } } }), false)
  })
})

describe("control channel run", () => {
  test("runs a command and returns its captured stdout, stderr, and exit code", async () => {
    const token = generateToken()
    const { runtime, seen } = scripted({ exitCode: 42, stdout: "confined out\n", stderr: "confined err\n" })
    const server = createControlServer({ runtime, endpoint: controlEndpoint(id()), token })
    await server.listen()
    try {
      const wire = await connect(server.endpoint)
      wire.send({ id: 1, method: "handshake", token })
      await wire.next()
      wire.send({ id: 2, method: "run", run: runCommand() })
      const response = JSON.parse(await wire.next())
      assert.equal(response.ok, true)
      assert.equal(response.id, 2)
      assert.deepEqual(response.result, {
        exitCode: 42,
        stdout: "confined out\n",
        stderr: "confined err\n",
        timedOut: false,
        warnings: [],
      })
      assert.deepEqual(seen, [runCommand()])
      wire.socket.destroy()
    } finally {
      await server.stop()
    }
  })

  test("rejects a run request without a valid payload", async () => {
    const token = generateToken()
    const server = createControlServer({ runtime: scripted().runtime, endpoint: controlEndpoint(id()), token })
    await server.listen()
    try {
      const wire = await connect(server.endpoint)
      wire.send({ id: 1, method: "handshake", token })
      await wire.next()
      wire.send({ id: 2, method: "run" })
      const response = JSON.parse(await wire.next())
      assert.equal(response.ok, false)
      assert.equal(response.error.code, "invalid_request")
      wire.socket.destroy()
    } finally {
      await server.stop()
    }
  })

  test("kills the active run when the client disconnects mid-run", async () => {
    const token = generateToken()
    let starts = 0
    const { runtime, killed } = hanging(() => {
      starts += 1
    })
    const server = createControlServer({ runtime, endpoint: controlEndpoint(id()), token })
    await server.listen()
    try {
      const wire = await connect(server.endpoint)
      wire.send({ id: 1, method: "handshake", token })
      await wire.next()
      wire.send({ id: 2, method: "run", run: runCommand() })
      await until(() => starts === 1)
      wire.socket.destroy()
      await until(() => killed())
      assert.ok(killed(), "the sidecar must kill the confined command when its caller goes away")
    } finally {
      await server.stop()
    }
  })

  test("runs a command through a spawned sidecar and the driver client", async () => {
    const canned: RunResult = { exitCode: 7, stdout: "out via client\n", stderr: "err via client\n", timedOut: false, warnings: ["scripted warning"] }
    const sidecar = await startSidecar({
      env: {
        KILO_MXC_RUNTIME_MODULE: runtimeFixture,
        KILO_MXC_SCRIPT_RESULT: JSON.stringify(canned),
      },
    })
    try {
      await sidecar.handshake()
      const result = await sidecar.run(runCommand())
      assert.deepEqual(result, canned)
    } finally {
      await sidecar.shutdown().catch(() => sidecar.stop())
    }
  })
})

