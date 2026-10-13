import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { sdkEnv } from "../src/sdk.ts"

describe("MXC telemetry settings are never touched", () => {
  test("ambient telemetry keys pass through byte-identical", () => {
    const ambient = {
      MXC_TELEMETRY_CONSENT: "off",
      PATH: "C:\\Windows\\System32",
    }
    assert.deepEqual(sdkEnv(ambient), ambient)
  })

  test("the sidecar cannot introduce a telemetry key into the SDK environment", () => {
    assert.throws(() => sdkEnv({}, { MXC_TELEMETRY_CONSENT: "on" }), /refusing to add telemetry key/)
  })

  test("non-telemetry additions compose over the ambient environment", () => {
    const composed = sdkEnv({ PATH: "old" }, { MXC_BIN_DIR: "C:\\bundle\\bin" })
    assert.deepEqual(composed, { PATH: "old", MXC_BIN_DIR: "C:\\bundle\\bin" })
  })
})
