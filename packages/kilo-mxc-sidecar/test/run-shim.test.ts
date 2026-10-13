import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { until } from "./wire.ts"
import { startSidecar } from "../src/client.ts"
import type { RunCommand } from "../src/run.ts"

const shim = fileURLToPath(new URL("../src/run-shim.ts", import.meta.url))
const runtimeFixture = fileURLToPath(new URL("./fixtures/scripted-runtime.mjs", import.meta.url))

function runShim(payload: unknown, env: Record<string, string>) {
  const child = spawn(process.execPath, [shim, JSON.stringify(payload)], {
    env: { ...process.env, ...env },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  })
  let stdout = ""
  let stderr = ""
  child.stdout.setEncoding("utf8")
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk
  })
  child.stderr.setEncoding("utf8")
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk
  })
  const done = new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
    child.on("close", (code) => resolve({ code, stdout, stderr }))
  })
  return { child, done, read: () => ({ stdout, stderr }) }
}

const payload = {
  command: 'cmd /c "echo confined"',
  workingDirectory: "C:\\workspace",
  filesystem: {
    readwritePaths: ["C:\\workspace"],
    readonlyPaths: ["C:\\Windows"],
    deniedPaths: [],
  },
  network: { egress: { default: "deny" } },
  ui: { disable: false },
  environment: { PATH: "C:\\Windows\\System32" },
}

function events(file: string) {
  if (!existsSync(file)) return []
  return readFileSync(file, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line))
}

describe("run shim", () => {
  test("round-trips stdout, stderr, warnings, and the exit code", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-shim-"))
    const log = path.join(dir, "events.jsonl")
    try {
      const canned = {
        exitCode: 42,
        stdout: "confined stdout\n",
        stderr: "confined stderr\n",
        timedOut: false,
        warnings: ["scripted warning"],
      }
      const { done } = runShim(payload, {
        KILO_MXC_RUNTIME_MODULE: runtimeFixture,
        KILO_MXC_SCRIPT_RESULT: JSON.stringify(canned),
        KILO_MXC_SCRIPT_EVENTS: log,
      })
      const result = await done
      assert.equal(result.code, 42)
      assert.equal(result.stdout, "confined stdout\n")
      assert.ok(result.stderr.includes("confined stderr\n"))
      assert.ok(result.stderr.includes("[kilo-mxc] scripted warning"), "warnings must surface on stderr")
      assert.deepEqual(events(log), [{ type: "run", command: payload, bindings: {} }])
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test("names the failure and exits non-zero when the sidecar cannot host a runtime", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-shim-fail-"))
    const log = path.join(dir, "events.jsonl")
    try {
      const { done } = runShim(payload, {
        // No scripted runtime and no SDK the sidecar can load: startup must fail
        // closed with a named error rather than running anything.
        KILO_MXC_RUNTIME_MODULE: "",
        KILO_MXC_SDK_ENTRY: path.join(dir, "no-such-sdk.mjs"),
        KILO_MXC_SCRIPT_EVENTS: log,
      })
      const result = await done
      assert.notEqual(result.code, 0)
      assert.ok(result.stderr.includes("kilo-mxc-shim:"), `stderr must name the shim failure, got: ${result.stderr}`)
      assert.ok(result.stderr.length > "kilo-mxc-shim:".length, "stderr must carry the underlying reason")
      assert.deepEqual(events(log), [])
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test("kills the confined command and exits when the parent link breaks mid-run", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-shim-kill-"))
    const log = path.join(dir, "events.jsonl")
    try {
      // Drive the sidecar the way the shim does, hang a run, then break the
      // parent link (stdin) the way a departing shim does. The sidecar must
      // tree-kill the confined command and exit rather than linger.
      // Hard-terminate without a tree kill (plain TerminateProcess) breaks the
      // stdio pipes without delivering EOF on Windows; production callers kill
      // the whole tree (taskkill /T), which the MXC job object also honours.
      const sidecar = await startSidecar({
        env: {
          KILO_MXC_RUNTIME_MODULE: runtimeFixture,
          KILO_MXC_SCRIPT_HANG: "1",
          KILO_MXC_SCRIPT_EVENTS: log,
        },
      })
      try {
        await sidecar.handshake()
        const settled = sidecar.run(payload as RunCommand)
        settled.catch(() => {})
        await until(() => events(log).some((entry) => entry.type === "run"))
        sidecar.orphan()
        await until(() => sidecar.exited)
        await until(() => events(log).some((entry) => entry.type === "kill"))
        assert.ok(events(log).some((entry) => entry.type === "kill"), "the sidecar must kill the run when the parent link breaks")
      } finally {
        await Promise.race([
          sidecar.shutdown().catch(() => {}),
          new Promise<void>((resolve) => setTimeout(resolve, 2_000)),
        ])
        sidecar.stop()
      }
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
