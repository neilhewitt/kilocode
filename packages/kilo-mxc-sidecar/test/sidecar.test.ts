import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { existsSync, readFileSync } from "node:fs"
import { mkdtempSync, rmSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { startSidecar } from "../src/client.ts"
import { connect, until } from "./wire.ts"

const runtimeFixture = fileURLToPath(new URL("./fixtures/scripted-runtime.mjs", import.meta.url))

describe("sidecar process lifecycle", () => {
  test("starts on demand, handshakes, answers platform support, and shuts down cleanly", async () => {
    const sidecar = await startSidecar({ env: { KILO_MXC_RUNTIME_MODULE: runtimeFixture } })
    const handshake = await sidecar.handshake()
    assert.equal(handshake.protocol, 1)
    assert.equal(handshake.channel, "control")
    const support = await sidecar.platformSupport()
    assert.equal(support.isSupported, true)
    assert.equal(support.isolationTier, "base-container")
    assert.equal(support.source, "scripted")
    await sidecar.shutdown()
    assert.equal(sidecar.exitCode, 0)
  })

  test("announces an endpoint on stdout that is the control channel, never a proxy port", async () => {
    const sidecar = await startSidecar({ env: { KILO_MXC_RUNTIME_MODULE: runtimeFixture } })
    try {
      assert.ok(sidecar.endpoint.includes("kilo-mxc-control-"), `endpoint ${sidecar.endpoint} must carry the control prefix`)
      assert.ok(!/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(sidecar.endpoint), "endpoint must not be a TCP host:port")
    } finally {
      await sidecar.shutdown().catch(() => sidecar.stop())
    }
  })

  test("refuses an unauthenticated connection to the control channel", async () => {
    const sidecar = await startSidecar({ env: { KILO_MXC_RUNTIME_MODULE: runtimeFixture } })
    try {
      const wire = await connect(sidecar.endpoint)
      wire.send({ id: 1, method: "handshake", token: "forged" })
      const response = JSON.parse(await wire.next())
      assert.equal(response.ok, false)
      assert.equal(response.error.code, "unauthorized")
      await until(() => wire.closed)
    } finally {
      await sidecar.shutdown().catch(() => sidecar.stop())
    }
  })

  test("exits when its parent goes away (stdin closed)", async () => {
    const sidecar = await startSidecar({ env: { KILO_MXC_RUNTIME_MODULE: runtimeFixture } })
    sidecar.orphan()
    await until(() => sidecar.exited)
    assert.ok(true)
  })

  test("rejects a pending call when the sidecar dies mid-request", async () => {
    const sidecar = await startSidecar({ env: { KILO_MXC_RUNTIME_MODULE: runtimeFixture, KILO_MXC_SCRIPT_HANG: "1" } })
    try {
      await sidecar.handshake()
      const run = sidecar.run({
        command: "cmd /c echo hi",
        filesystem: { readwritePaths: ["C:\\w"], readonlyPaths: [], deniedPaths: [] },
        network: { egress: { default: "deny" } },
        ui: { disable: false },
        environment: {},
      })
      sidecar.stop()
      const outcome = await Promise.race([
        run.then(
          () => "settled",
          () => "rejected",
        ),
        new Promise<"hung">((resolve) => {
          setTimeout(() => resolve("hung"), 2_000).unref()
        }),
      ])
      assert.equal(outcome, "rejected", "a caller must learn that its run died with the sidecar")
      const late = await Promise.race([
        sidecar.platformSupport().then(
          () => "settled",
          () => "rejected",
        ),
        new Promise<"hung">((resolve) => {
          setTimeout(() => resolve("hung"), 2_000).unref()
        }),
      ])
      assert.equal(late, "rejected", "calls made after the sidecar is gone must reject, not hang")
    } finally {
      sidecar.stop()
    }
  })
})

describe("sidecar platform support probing", () => {
  test("answers a scripted non-enforcing tier with its warnings verbatim and never runs a command", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-probe-"))
    const log = path.join(root, "events.jsonl")
    const scripted = {
      isSupported: true,
      isolationTier: "appcontainer-dacl",
      warnings: [
        "HostPrepSystemDriveMissing: run wxc-host-prep prepare-system-drive once from an elevated context",
        "HostPrepNullDeviceMissing: run wxc-host-prep prepare-null-device once per boot",
      ],
      source: "scripted",
    }
    try {
      const sidecar = await startSidecar({
        env: {
          KILO_MXC_RUNTIME_MODULE: runtimeFixture,
          KILO_MXC_SCRIPT_SUPPORT: JSON.stringify(scripted),
          KILO_MXC_SCRIPT_EVENTS: log,
        },
      })
      try {
        await sidecar.handshake()
        const support = await sidecar.platformSupport()
        assert.deepEqual(support, scripted)
      } finally {
        await sidecar.shutdown().catch(() => sidecar.stop())
      }
      assert.equal(sidecar.exitCode, 0)
      const recorded = existsSync(log)
        ? (readFileSync(log, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line)) as Array<{
            type: string
          }>)
        : []
      assert.deepEqual(
        recorded.map((entry) => entry.type),
        ["platformSupport"],
        "a probe consults platform support only — it must never launch a run",
      )
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})
