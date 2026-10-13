import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"

// KNOWN-RISK repro (ticket 15), now pinned as the engine-path canary. Ticket
// 13's implementer reported that MXC SDK 1.0.0 captureDenials crashed the SDK
// host process (0xC0000005); this repro confirmed it in an isolated child on a
// probe-gated live base-container host (identical request without the
// captureDenials config enforces cleanly — see operator history). ADR 0002
// wires audit mode to captureDenials allow-mode, so the engine path ships
// wired but disabled: audit mode logs would-be denials on the unsandboxed
// dry-run path, and KILO_MXC_AUDIT_ENGINE=1 opts a host into the engine path.
// This test fails when the pinned crash disappears (flip the default then) or
// when the engine, once enabled, stops reporting captures.

const ACCESS_VIOLATION = 0xc0000005

const fixture = path.resolve(fileURLToPath(new URL(".", import.meta.url)), "fixtures/audit-repro.mjs")

function sdkEntry() {
  return (
    process.env.KILO_MXC_SDK_ENTRY ??
    `${os.tmpdir()}/kilo/mxc-smoke/node_modules/@microsoft/mxc-sdk/dist/v1/index.js`
  )
}

describe("audit mode engine path (live, probe-gated)", () => {
  test("captures would-be denials under the engine switch, or documents the upstream blocker without it", { timeout: 180_000 }, (t) => {
    if (process.platform !== "win32") return t.skip(`live audit repro requires Windows; this host is ${process.platform}`)
    const entry = sdkEntry()
    if (!existsSync(entry)) return t.skip(`MXC SDK not installed at ${entry}`)
    const versions = process.versions as Record<string, string | undefined>
    if (versions.bun) return t.skip("the MXC SDK cannot run under Bun")
    const engine = process.env.KILO_MXC_AUDIT_ENGINE === "1"
    const run = spawnSync(process.execPath, [fixture], {
      encoding: "utf8",
      timeout: 180_000,
      env: { ...process.env, KILO_MXC_SDK_ENTRY: entry },
    })
    const verdict = (() => {
      try {
        return JSON.parse((run.stdout ?? "").trim().split("\n").at(-1) ?? "")
      } catch {
        return undefined
      }
    })()
    if (verdict?.outcome === "skip")
      return t.skip(`host enforcement tier is ${verdict.tier === "" ? "unknown" : verdict.tier}, not base-container`)
    if (!engine) {
      assert.equal(
        run.status,
        ACCESS_VIOLATION,
        "upstream blocker confirmed: MXC SDK 1.0.0 captureDenials allow-mode crashed the SDK host process (0xC0000005)",
      )
      assert.equal(verdict, undefined, "a crash leaves no verdict line")
      return
    }
    assert.notEqual(run.status, ACCESS_VIOLATION, "the engine path crashed while KILO_MXC_AUDIT_ENGINE=1 — upstream regressed")
    assert.equal(run.status, 0, `the audit repro child failed: ${run.stderr}`)
    assert.ok(verdict, "the engine path must complete rather than die")
    assert.equal(verdict.outcome, "captured", `unexpected verdict: ${JSON.stringify(verdict)}`)
    assert.equal(verdict.exitCode, 0, `the audited workload itself failed: ${verdict.stderr}`)
    assert.equal(verdict.rewritten, "answer", "allow-mode must suspend the denial so the would-be-denied write succeeds")
    assert.ok(verdict.captured === true, "the engine must attach a captureDenials report to the run")
    assert.ok(verdict.totalDenials >= 1, "the report must count the suspended denial")
  })
})
