import { describe, test } from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { resolveUnit } from "../../src/unit/resolve.ts"
import { writeManifest, type UnitManifest } from "../../src/unit/manifest.ts"
import { startSidecar } from "../../src/client.ts"

// End-to-end at the script level: a resolved unit's launch spec (node
// executable, sidecar entry, composed environment) must actually start a
// working sidecar through the same client the agent core uses. The fixture
// unit points its Node at this host's node.exe and its sidecar entry at the
// real server sources; the runtime is scripted exactly as the contract tests
// script it, so no MXC SDK or download is needed.
const runtimeFixture = fileURLToPath(new URL("../fixtures/scripted-runtime.mjs", import.meta.url))

function manifest(): UnitManifest {
  return {
    unitFormat: 1,
    platform: { os: "win32", arch: "x64" },
    node: {
      version: "24.21.0",
      archive: "node-v24.21.0-win-x64.zip",
      sha256: "158f7685b44de51f6c0df1d153526cbcd3e1bc739a8dfc607721cef75de9e541",
      source: "https://nodejs.org/dist/v24.21.0/node-v24.21.0-win-x64.zip",
    },
    sdk: { name: "@microsoft/mxc-sdk", version: "1.0.0" },
    sidecar: { package: "@kilocode/mxc-sidecar", version: "7.8.9", protocol: 1, entry: "sidecar/src/main.ts" },
    created: "2026-10-13T00:00:00.000Z",
  }
}

describe("resolved unit launches a working sidecar", () => {
  test("startSidecar runs the resolved node and entry with the resolved environment", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "kilo-mxc-launch-"))
    try {
      const source = path.join(dir, "src")
      await fs.cp(fileURLToPath(new URL("../../src", import.meta.url)), source, { recursive: true })
      const unitDir = path.join(dir, "dist", "bin", "mxc-sidecar-unit")
      await fs.mkdir(path.join(unitDir, "node"), { recursive: true })
      await fs.cp(source, path.join(unitDir, "sidecar", "src"), { recursive: true })
      // The unit's "Node runtime" is this host's node.exe: the launch path is
      // what is under test, not the binary's provenance (covered elsewhere).
      await fs.copyFile(process.execPath, path.join(unitDir, "node", "node.exe"))
      const pkgDir = path.join(unitDir, "sdk", "node_modules", "@microsoft", "mxc-sdk")
      await fs.mkdir(path.join(pkgDir, "dist", "v1"), { recursive: true })
      await fs.writeFile(path.join(pkgDir, "package.json"), JSON.stringify({ name: "@microsoft/mxc-sdk", version: "1.0.0", exports: { "./v1": "./dist/v1/index.js" } }))
      await fs.writeFile(path.join(pkgDir, "dist", "v1", "index.js"), "export const getPlatformSupport = async () => ({})\n")
      await writeManifest(unitDir, manifest())

      const resolved = await resolveUnit({ execPath: path.join(dir, "dist", "bin", "kilo.exe") })
      assert.ok(resolved.ok, resolved.ok ? "" : resolved.reasons.join("; "))

      const sidecar = await startSidecar({
        node: resolved.node,
        entry: resolved.entry,
        env: { ...resolved.env, KILO_MXC_RUNTIME_MODULE: runtimeFixture },
      })
      try {
        const handshake = await sidecar.handshake()
        assert.equal(handshake.protocol, 1)
        const support = await sidecar.platformSupport()
        assert.equal(support.source, "scripted")
      } finally {
        await sidecar.shutdown().catch(() => sidecar.stop())
      }
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  // Fresh-install smoke, gated like live.test.ts: point KILO_MXC_UNIT_LIVE at
  // a unit assembled by script/build-unit.ts and this starts the sidecar with
  // the unit's own bundled Node and the real MXC SDK — the clean-machine path
  // minus the machine. Skips everywhere else.
  test("a freshly assembled unit starts with its own Node and the real SDK", async (t) => {
    const unit = process.env.KILO_MXC_UNIT_LIVE
    if (!unit) return t.skip("set KILO_MXC_UNIT_LIVE to an assembled unit directory to run this")
    const resolved = await resolveUnit({ env: { KILO_MXC_UNIT: unit } })
    assert.ok(resolved.ok, resolved.ok ? "" : resolved.reasons.join("; "))
    const sidecar = await startSidecar({ node: resolved.node, entry: resolved.entry, env: resolved.env })
    try {
      const handshake = await sidecar.handshake()
      assert.equal(handshake.protocol, resolved.manifest.sidecar.protocol)
      const support = await sidecar.platformSupport()
      assert.equal(support.isSupported, true)
      assert.equal(support.isolationTier, "base-container")
    } finally {
      await sidecar.shutdown().catch(() => sidecar.stop())
    }
  })
})
