import { describe, test } from "node:test"
import assert from "node:assert/strict"
import os from "node:os"
import { runThrough, sdkEnv, toSdkRequest, type SdkModule } from "../src/sdk.ts"
import type { RunCommand } from "../src/run.ts"

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

function command(audit: RunCommand["audit"]): RunCommand {
  return {
    command: "cmd /c echo confined",
    workingDirectory: os.tmpdir(),
    filesystem: { readwritePaths: ["C:\\workspace"], readonlyPaths: [], deniedPaths: [] },
    network: { egress: { default: "deny" } },
    ui: { disable: false },
    environment: {},
    ...(audit === undefined ? {} : { audit }),
  }
}

describe("audit request composition", () => {
  test("maps an audit request onto captureDenials allow-mode on the containment config", () => {
    const request = toSdkRequest(command({ denialsPath: "C:\\logs\\denials.json" }))
    assert.deepEqual(request.containment, {
      type: "processcontainer",
      config: { captureDenials: { mode: "allow", outputPath: "C:\\logs\\denials.json" } },
    })
  })

  test("without an audit request the containment config stays bare", () => {
    const request = toSdkRequest(command(undefined))
    assert.deepEqual(request.containment, { type: "processcontainer" })
    assert.equal(request.containment.config, undefined)
  })

  test("an audit request without denialsPath asks for allow-capture at the SDK default destination", () => {
    const request = toSdkRequest(command({}))
    assert.deepEqual(request.containment, { type: "processcontainer", config: { captureDenials: { mode: "allow" } } })
  })
})

describe("engine capture results reach the run result", () => {
  function child(metadata: Record<string, unknown> | undefined) {
    return {
      standardOutput: null,
      standardError: null,
      wait: () => Promise.resolve({ exitCode: 0, timedOut: false }),
      warnings: [] as unknown[],
      outputMetadata: () => metadata,
      kill: () => {},
    }
  }

  test("a captureDenials report surfaces as the run result's audit summary", async () => {
    const sdk: Pick<SdkModule, "spawn"> = { spawn: async () => child({ captureDenials: { outputPath: "C:\\logs\\denials.json", exitCode: 0, totalDenials: 2, deniedResourcesTruncated: false } }) }
    const result = await (await runThrough(sdk, command(undefined))).wait()
    assert.deepEqual(result.audit, { totalDenials: 2, reportPath: "C:\\logs\\denials.json" })
  })

  test("a run without engine metadata settles without an audit summary", async () => {
    const sdk: Pick<SdkModule, "spawn"> = { spawn: async () => child(undefined) }
    const result = await (await runThrough(sdk, command(undefined))).wait()
    assert.equal(result.audit, undefined)
  })

  test("a malformed capture report is never surfaced as an audit summary", async () => {
    const sdk: Pick<SdkModule, "spawn"> = { spawn: async () => child({ captureDenials: { totalDenials: "two" } }) }
    const result = await (await runThrough(sdk, command(undefined))).wait()
    assert.equal(result.audit, undefined)
  })

  test("a captureDenials failure surfaces as a warning, never as an audit summary", async () => {
    const error = { message: "capture finalisation failed", etlPath: "C:\\logs\\trace.etl" }
    const sdk: Pick<SdkModule, "spawn"> = {
      spawn: async () => ({ ...child({ captureDenialsError: error }), warnings: ["captureDenialsError: capture finalisation failed"] }),
    }
    const result = await (await runThrough(sdk, command(undefined))).wait()
    assert.equal(result.audit, undefined)
    assert.ok(result.warnings.some((entry) => entry.includes("capture finalisation failed")), "the failure stays observable as a warning")
  })
})
