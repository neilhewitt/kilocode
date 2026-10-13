import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { CONTROL_CHANNEL_PREFIX, controlEndpoint, isTcpStyleEndpoint } from "../src/endpoint.ts"

describe("control channel endpoint", () => {
  test("is a named pipe on Windows carrying the control prefix", () => {
    const endpoint = controlEndpoint("a1b2c3d4", { platform: "win32" })
    assert.ok(endpoint.startsWith(`\\\\.\\pipe\\${CONTROL_CHANNEL_PREFIX}-`), `endpoint ${endpoint} must live under the control pipe namespace`)
  })

  test("is a user-scoped unix domain socket path elsewhere", () => {
    const endpoint = controlEndpoint("a1b2c3d4", { platform: "linux", tmp: "/tmp" })
    assert.ok(endpoint.startsWith(`/tmp/${CONTROL_CHANNEL_PREFIX}-`), `endpoint ${endpoint} must live under the control socket namespace`)
  })

  test("embeds the caller-provided id", () => {
    const endpoint = controlEndpoint("deadbeef", { platform: "win32" })
    assert.ok(endpoint.includes("deadbeef"))
  })

  test("is never a TCP host:port endpoint, keeping it distinct from the loopback proxy port", () => {
    for (const platform of ["win32", "linux", "darwin"]) {
      const endpoint = controlEndpoint("a1b2c3d4", { platform, tmp: "/tmp" })
      assert.ok(!isTcpStyleEndpoint(endpoint), `${platform} endpoint must not be a TCP endpoint`)
    }
  })
})
