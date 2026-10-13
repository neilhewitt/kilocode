import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import type { Profile } from "../src/profile.ts"
import {
  ENFORCEMENT_FLOOR_DOC,
  assessPlatformSupport,
  deniedByProfile,
  probeMxcSupport,
} from "../src/probe.ts"

// Ticket 14 — host gating. The capability probe gates sandbox mode: only the
// base-container (PSEC) enforcement tier may confine; anything else is a hard
// refuse with the OS build, the returned tier, and the doc link in the message,
// plus probe-emitted host-prep warnings carried verbatim as diagnostics.

const BUILD = "10.0.26100"

describe("probe assessment (pure)", () => {
  test("accepts the base-container tier", () => {
    const gate = assessPlatformSupport({ isSupported: true, isolationTier: "base-container" }, BUILD)
    assert.equal(gate.verdict, "enforce")
    assert.equal(gate.tier, "base-container")
    assert.equal(gate.reason, undefined)
    assert.deepEqual(gate.diagnostics, [])
  })

  test("refuses an AppContainer tier host — the base-container-only floor", () => {
    for (const tier of ["appcontainer-bfs", "appcontainer-dacl"]) {
      const gate = assessPlatformSupport({ isSupported: true, isolationTier: tier }, BUILD)
      assert.equal(gate.verdict, "refuse", tier)
      assert.match(gate.reason ?? "", new RegExp(tier))
    }
  })

  test("refusal states the OS build, the returned tier, and the doc link", () => {
    const gate = assessPlatformSupport({ isSupported: true, isolationTier: "appcontainer-dacl" }, BUILD)
    assert.equal(gate.verdict, "refuse")
    assert.match(gate.reason ?? "", /10\.0\.26100/)
    assert.match(gate.reason ?? "", /appcontainer-dacl/)
    assert.match(gate.reason ?? "", new RegExp(ENFORCEMENT_FLOOR_DOC))
  })

  test("refuses a host the SDK reports unsupported, even without a tier", () => {
    const gate = assessPlatformSupport({ isSupported: false }, BUILD)
    assert.equal(gate.verdict, "refuse")
    assert.match(gate.reason ?? "", /10\.0\.26100/)
    assert.match(gate.reason ?? "", /unsupported/i)
  })

  test("refuses fail-closed when the tier is missing or malformed", () => {
    assert.equal(assessPlatformSupport({}, BUILD).verdict, "refuse")
    assert.equal(assessPlatformSupport({ isSupported: true, isolationTier: 7 }, BUILD).verdict, "refuse")
    assert.equal(assessPlatformSupport("nonsense", BUILD).verdict, "refuse")
  })

  test("carries host-prep warnings verbatim as diagnostics", () => {
    const warnings = [
      "HostPrepSystemDriveMissing: run wxc-host-prep prepare-system-drive",
      "HostPrepNullDeviceMissing: run wxc-host-prep prepare-null-device per boot",
    ]
    const gate = assessPlatformSupport({ isSupported: true, isolationTier: "base-container", warnings }, BUILD)
    assert.equal(gate.verdict, "enforce", "warnings alone never fail an enforcing host")
    assert.deepEqual(gate.diagnostics, warnings)
    const refused = assessPlatformSupport({ isSupported: true, isolationTier: "appcontainer-dacl", warnings }, BUILD)
    assert.deepEqual(refused.diagnostics, warnings)
  })
})

function fixtureProfile(root: string): Profile {
  return {
    filesystem: {
      allowWrite: [
        { path: root, kind: "subtree" },
        { path: path.join(root, "tmp"), kind: "subtree" },
      ],
      denyWrite: [{ path: path.join(root, "store"), kind: "subtree" }],
      denyNames: [".git", ".env"],
      temporaryDirectory: path.join(root, "tmp"),
    },
    network: { mode: "proxy", allowedHosts: ["registry.npmjs.org"] },
    environment: { deny: ["KILO_SERVER_PASSWORD"], set: {} },
  }
}

describe("what would have been denied (audit composition)", () => {
  test("records the denial surface a sandboxed session would have had", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-gate-audit-"))
    try {
      const denied = deniedByProfile(fixtureProfile(root))
      assert.deepEqual(denied.writesDeniedOutside, [root, path.join(root, "tmp")])
      assert.deepEqual(denied.writesDenied, [path.join(root, "store")])
      assert.deepEqual(denied.namesDenied, [".git", ".env"])
      assert.deepEqual(denied.environmentDenied, ["KILO_SERVER_PASSWORD"])
      assert.deepEqual(denied.network, { mode: "proxy", allowedHosts: ["registry.npmjs.org"] })
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})

describe("probe driver (scripted sidecar)", () => {
  const runtimeFixture = path.resolve(
    fileURLToPath(new URL(".", import.meta.url)),
    "../../kilo-mxc-sidecar/test/fixtures/scripted-runtime.mjs",
  )

  function sidecarEnv(scriptSupport: object, events: string) {
    return {
      KILO_MXC_RUNTIME_MODULE: runtimeFixture,
      KILO_MXC_SCRIPT_SUPPORT: JSON.stringify(scriptSupport),
      KILO_MXC_SCRIPT_EVENTS: events,
    }
  }

  test("probes an enforcing host through the sidecar and shuts it down cleanly", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-gate-enforce-"))
    const log = path.join(root, "events.jsonl")
    try {
      const gate = await probeMxcSupport({
        node: process.execPath,
        env: sidecarEnv({ isSupported: true, isolationTier: "base-container", source: "scripted" }, log),
      })
      assert.equal(gate.verdict, "enforce")
      assert.equal(gate.tier, "base-container")
      const recorded = readFileSync(log, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line))
      assert.deepEqual(
        recorded.map((entry) => entry.type),
        ["platformSupport"],
        "the probe is read-only: it consults platform support and never runs a command",
      )
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("refuses a scripted AppContainer host with warnings verbatim", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-gate-refuse-"))
    const log = path.join(root, "events.jsonl")
    try {
      const warnings = ["HostPrepSystemDriveMissing: run wxc-host-prep prepare-system-drive"]
      const gate = await probeMxcSupport({
        node: process.execPath,
        env: sidecarEnv({ isSupported: true, isolationTier: "appcontainer-dacl", warnings }, log),
      })
      assert.equal(gate.verdict, "refuse")
      assert.equal(gate.tier, "appcontainer-dacl")
      assert.match(gate.reason ?? "", /appcontainer-dacl/)
      assert.match(gate.reason ?? "", /base-container/)
      assert.deepEqual(gate.diagnostics, warnings)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("refuses fail-closed when the sidecar cannot be probed", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-gate-unprobeable-"))
    try {
      const broken = path.join(root, "broken-runtime.mjs")
      writeFileSync(broken, "export function createRuntime() { throw new Error('boom') }\n")
      const gate = await probeMxcSupport({
        node: process.execPath,
        env: { KILO_MXC_RUNTIME_MODULE: broken },
      })
      assert.equal(gate.verdict, "refuse")
      assert.equal(gate.source, "unprobeable")
      assert.match(gate.reason ?? "", /could not run/i)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})

// Live gating, probe-gated like the enforcement seam: only on win32 hosts with
// the real MXC SDK present. This host is base-container, so the real probe must
// accept it; everywhere else the scripted cases above carry the behaviour.
describe("probe driver (live, probe-gated)", () => {
  test("assesses the real host through the real SDK", async (t) => {
    if (process.platform !== "win32") return t.skip(`live probe requires Windows; this host is ${process.platform}`)
    const entry = process.env.KILO_MXC_SDK_ENTRY ?? `${os.tmpdir()}/kilo/mxc-smoke/node_modules/@microsoft/mxc-sdk/dist/v1/index.js`
    if (!existsSync(entry)) return t.skip(`MXC SDK not installed at ${entry}`)
    const versions = process.versions as Record<string, string | undefined>
    if (versions.bun) return t.skip("the MXC SDK cannot run under Bun")
    const gate = await probeMxcSupport({ node: process.execPath, env: { KILO_MXC_SDK_ENTRY: entry } })
    assert.equal(gate.source, "probe")
    if (gate.verdict === "enforce") {
      assert.equal(gate.tier, "base-container")
      return
    }
    assert.match(gate.reason ?? "", new RegExp(ENFORCEMENT_FLOOR_DOC))
  })
})
