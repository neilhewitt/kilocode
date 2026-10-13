import { describe, test } from "node:test"
import assert from "node:assert/strict"
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
})
