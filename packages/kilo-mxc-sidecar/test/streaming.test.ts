import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { createControlServer } from "../src/control.ts"
import type { RunCommand, RunHandle, RunResult } from "../src/run.ts"
import type { Runtime, RunOptions } from "../src/sdk.ts"
import { generateToken } from "../src/auth.ts"
import { controlEndpoint } from "../src/endpoint.ts"
import { connect } from "./wire.ts"
import { startSidecar } from "../src/client.ts"

const runtimeFixture = fileURLToPath(new URL("./fixtures/scripted-runtime.mjs", import.meta.url))

function id() {
  return Math.random().toString(16).slice(2, 10)
}

function runCommand(partial: Partial<RunCommand> = {}): RunCommand {
  return {
    command: 'cmd /c "echo confined"',
    workingDirectory: "C:\\workspace",
    filesystem: {
      readwritePaths: ["C:\\workspace"],
      readonlyPaths: [],
      deniedPaths: [],
    },
    network: { egress: { default: "deny" } },
    ui: { disable: false },
    environment: { PATH: "C:\\Windows\\System32" },
    ...partial,
  }
}

function streaming(forwardOf: (options: RunOptions) => void): Runtime {
  const run = async (_command: RunCommand, _bindings: unknown, options: RunOptions): Promise<RunHandle> => {
    forwardOf(options)
    return {
      wait: () =>
        Promise.resolve({
          exitCode: 5,
          stdout: "buffered out\n",
          stderr: "buffered err\n",
          timedOut: false,
          warnings: ["shim warning"],
        }),
      kill: () => {},
    }
  }
  return {
    getPlatformSupport: async () => ({ isSupported: true, source: "scripted" }),
    run: run as unknown as Runtime["run"],
  }
}

describe("control channel streamed runs", () => {
  test("a streamed run emits stdout event frames before the settled response", async () => {
    const token = generateToken()
    const runtime = streaming((options) => {
      options.forward?.("stdout", new TextEncoder().encode("live out; "))
      options.forward?.("stderr", new TextEncoder().encode("live err"))
    })
    const server = createControlServer({ runtime, endpoint: controlEndpoint(id()), token })
    await server.listen()
    try {
      const wire = await connect(server.endpoint)
      wire.send({ id: 1, method: "handshake", token })
      await wire.next()
      wire.send({ id: 2, method: "run", run: runCommand({ stream: true }) })
      const first = JSON.parse(await wire.next())
      assert.equal(first.id, 2)
      assert.equal(first.event, "stdout", "output arrives as framed events, not as the run's result")
      assert.equal(new TextDecoder().decode(Buffer.from(first.data, "base64")), "live out; ")
      const second = JSON.parse(await wire.next())
      assert.equal(second.event, "stderr")
      assert.equal(new TextDecoder().decode(Buffer.from(second.data, "base64")), "live err")
      const settled = JSON.parse(await wire.next())
      assert.equal(settled.ok, true)
      assert.deepEqual(settled.result, {
        exitCode: 5,
        stdout: "buffered out\n",
        stderr: "buffered err\n",
        timedOut: false,
        warnings: ["shim warning"],
      })
      wire.socket.destroy()
    } finally {
      await server.stop()
    }
  })

  test("a captured run never emits event frames even when the runtime could forward", async () => {
    const token = generateToken()
    const runtime = streaming((options) => {
      options?.forward?.("stdout", new TextEncoder().encode("must not be forwarded"))
    })
    const server = createControlServer({ runtime, endpoint: controlEndpoint(id()), token })
    await server.listen()
    try {
      const wire = await connect(server.endpoint)
      wire.send({ id: 1, method: "handshake", token })
      await wire.next()
      wire.send({ id: 2, method: "run", run: runCommand() })
      const response = JSON.parse(await wire.next())
      assert.equal(response.ok, true)
      assert.equal(response.event, undefined, "captured runs keep their single settled response")
      assert.deepEqual(response.result.warnings, ["shim warning"])
      wire.socket.destroy()
    } finally {
      await server.stop()
    }
  })

  test("the driver client surfaces stream events to onOutput and the settled result is unchanged", async (t) => {
    const canned: RunResult = {
      exitCode: 3,
      stdout: "streamed out via client\n",
      stderr: "",
      timedOut: false,
      warnings: ["streamed warning"],
    }
    const sidecar = await startSidecar({
      env: {
        KILO_MXC_RUNTIME_MODULE: runtimeFixture,
        KILO_MXC_SCRIPT_RESULT: JSON.stringify(canned),
        KILO_MXC_SCRIPT_STREAM_OUT: "streamed out via client",
      },
    })
    t.after(async () => {
      await sidecar.shutdown().catch(() => sidecar.stop())
    })
    await sidecar.handshake()
    const live: Array<{ stream: string; text: string }> = []
    const command = runCommand({ stream: true })
    const result = await sidecar.run(command, {
      onOutput: (stream, data) => live.push({ stream, text: new TextDecoder().decode(data) }),
    })
    assert.deepEqual(live, [{ stream: "stdout", text: "streamed out via client" }])
    assert.deepEqual(result, canned, "the settled result is identical to capture-mode")
  })
})

describe("run-shim streamed forwarding", () => {
  const shim = fileURLToPath(new URL("../src/run-shim.ts", import.meta.url))

  /** Runs the shim with the scripted runtime and returns everything the agent-side pipes see. */
  function shimRun(streamed: boolean) {
    const payload = runCommand({ ...(streamed ? { stream: true } : {}) })
    let output = ""
    let problem = ""
    let code: number
    try {
      output = execFileSync(process.execPath, [shim, JSON.stringify(payload)], {
        encoding: "utf8",
        env: {
          ...process.env,
          KILO_MXC_RUNTIME_MODULE: runtimeFixture,
          KILO_MXC_SCRIPT_RESULT: JSON.stringify({
            exitCode: 5,
            stdout: "buffered out\n",
            stderr: "buffered err\n",
            timedOut: false,
            warnings: ["shim warning"],
          }),
          KILO_MXC_SCRIPT_STREAM_OUT: "live out; ",
          KILO_MXC_SCRIPT_STREAM_ERR: "live err; ",
        },
        stdio: ["pipe", "pipe", "pipe"],
      })
      code = 0
    } catch (error) {
      const failure = error as { stdout?: string; stderr?: string; status?: number }
      output = failure.stdout ?? ""
      problem = failure.stderr ?? ""
      code = failure.status ?? -1
    }
    return { output, problem, code }
  }

  test("a streamed run forwards chunks live, without replaying them at completion", () => {
    const { output, problem, code } = shimRun(true)
    assert.equal(output, "live out; ", "the shim's stdout carries exactly the streamed chunks")
    assert.equal(problem, "live err; [kilo-mxc] shim warning\n", "stderr carries the streamed chunks plus the warnings — nothing replayed")
    assert.equal(code, 5, "completion semantics are identical")
  })

  test("a captured run keeps today's buffered replay semantics", () => {
    const { output, problem, code } = shimRun(false)
    assert.equal(output, "buffered out\n")
    assert.equal(problem, "buffered err\n[kilo-mxc] shim warning\n")
    assert.equal(code, 5)
  })
})
