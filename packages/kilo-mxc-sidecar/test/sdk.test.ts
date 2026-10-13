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

function auditCommand(audit: RunCommand["audit"]): RunCommand {
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
    const request = toSdkRequest(auditCommand({ denialsPath: "C:\\logs\\denials.json" }))
    assert.deepEqual(request.containment, {
      type: "processcontainer",
      config: { captureDenials: { mode: "allow", outputPath: "C:\\logs\\denials.json" } },
    })
  })

  test("without an audit request the containment config stays bare", () => {
    const request = toSdkRequest(auditCommand(undefined))
    assert.deepEqual(request.containment, { type: "processcontainer" })
    assert.equal((request.containment as { config?: unknown }).config, undefined)
  })

  test("an audit request without denialsPath asks for allow-capture at the SDK default destination", () => {
    const request = toSdkRequest(auditCommand({}))
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
    const result = await (await runThrough(sdk, auditCommand(undefined))).wait()
    assert.deepEqual(result.audit, { totalDenials: 2, reportPath: "C:\\logs\\denials.json" })
  })

  test("a run without engine metadata settles without an audit summary", async () => {
    const sdk: Pick<SdkModule, "spawn"> = { spawn: async () => child(undefined) }
    const result = await (await runThrough(sdk, auditCommand(undefined))).wait()
    assert.equal(result.audit, undefined)
  })

  test("a malformed capture report is never surfaced as an audit summary", async () => {
    const sdk: Pick<SdkModule, "spawn"> = { spawn: async () => child({ captureDenials: { totalDenials: "two" } }) }
    const result = await (await runThrough(sdk, auditCommand(undefined))).wait()
    assert.equal(result.audit, undefined)
  })

  test("a captureDenials failure surfaces as a warning, never as an audit summary", async () => {
    const error = { message: "capture finalisation failed", etlPath: "C:\\logs\\trace.etl" }
    const sdk: Pick<SdkModule, "spawn"> = {
      spawn: async () => ({ ...child({ captureDenialsError: error }), warnings: ["captureDenialsError: capture finalisation failed"] }),
    }
    const result = await (await runThrough(sdk, auditCommand(undefined))).wait()
    assert.equal(result.audit, undefined)
    assert.ok(result.warnings.some((entry) => entry.includes("capture finalisation failed")), "the failure stays observable as a warning")
  })
})

function command(egress: RunCommand["network"]["egress"]): RunCommand {
  return {
    command: "cmd /c echo hi",
    filesystem: { readwritePaths: ["C:\\w"], readonlyPaths: [], deniedPaths: [] },
    network: { egress },
    ui: { disable: false },
    environment: {},
  }
}

describe("SDK request network composition", () => {
  test("deny composes the explicit blocked posture with ingress denied", () => {
    const request = toSdkRequest(command({ default: "deny" }))
    assert.deepEqual(request.network, {
      egress: { default: "deny" },
      ingress: { default: "deny", hostLoopback: "deny" },
    })
  })

  test("allow keeps the unrestricted posture", () => {
    const request = toSdkRequest(command({ default: "allow" }))
    assert.deepEqual(request.network, { egress: { default: "allow" } })
  })

  test("proxy composes MXC Model 2 pinned to the sidecar proxy endpoint", () => {
    const request = toSdkRequest(command({ default: "proxy", allowedHosts: ["registry.npmjs.org:443"] }), {
      networkProxy: "http://127.0.0.1:3128",
    })
    assert.deepEqual(request.network, {
      egress: { default: "deny" },
      ingress: { default: "allow", hostLoopback: "allow" },
      runtimeConfig: { networkProxy: "http://127.0.0.1:3128" },
    })
  })

  test("a proxy posture without a live proxy endpoint fails closed", () => {
    assert.throws(() => toSdkRequest(command({ default: "proxy", allowedHosts: ["registry.npmjs.org:443"] })), /proxy/)
  })

  test("cidr composes MXC Model 1 with the recorded raw rules", () => {
    const request = toSdkRequest(
      command({
        default: "cidr",
        allow: [{ to: ["140.82.112.0/20"], ports: [{ protocol: "tcp", port: 22 }] }],
      }),
    )
    assert.deepEqual(request.network, {
      egress: {
        default: "deny",
        allow: [{ to: [{ cidr: "140.82.112.0/20" }], ports: [{ protocol: "tcp", port: 22 }] }],
      },
      ingress: { default: "deny", hostLoopback: "deny" },
    })
  })

  test("cidr rules map every destination to its wire peer and pass ports through", () => {
    const request = toSdkRequest(
      command({
        default: "cidr",
        allow: [
          { to: ["10.0.0.0/8"] },
          { to: ["::/0", "2001:db8::/32"], ports: [{ protocol: "udp", port: 53, endPort: 54 }] },
        ],
      }),
    )
    const network = request.network as { egress: { allow: unknown } }
    assert.deepEqual(network.egress.allow, [
      { to: [{ cidr: "10.0.0.0/8" }] },
      {
        to: [{ cidr: "::/0" }, { cidr: "2001:db8::/32" }],
        ports: [{ protocol: "udp", port: 53, endPort: 54 }],
      },
    ])
  })

  test("runThrough forwards the proxy binding to the SDK spawn", async () => {
    const spawned: Array<Record<string, unknown>> = []
    const handle = await runThrough(
      {
        spawn: async (request) => {
          spawned.push(request)
          return {
            standardOutput: null,
            standardError: null,
            wait: async () => ({ exitCode: 0, timedOut: false }),
            kill: () => {},
          }
        },
      },
      command({ default: "proxy", allowedHosts: ["example.com:443"] }),
      { networkProxy: "http://127.0.0.1:9999" },
    )
    const result = await handle.wait()
    assert.equal(result.exitCode, 0)
    assert.equal(spawned.length, 1)
    assert.deepEqual(spawned[0].network, {
      egress: { default: "deny" },
      ingress: { default: "allow", hostLoopback: "allow" },
      runtimeConfig: { networkProxy: "http://127.0.0.1:9999" },
    })
  })
})
