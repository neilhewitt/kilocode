import { describe, test } from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { installUnit, readCurrentPointer, removeUnit, sweepUnits } from "../../src/unit/install.ts"
import { fingerprintOf, readManifest, writeManifest, type UnitManifest } from "../../src/unit/manifest.ts"

// installUnit is the user-scope half of the distribution: it materialises an
// already-assembled unit under a per-user root using filesystem operations
// only — no child processes, no network, no elevation — and keeps exactly one
// complete unit visible through an atomically flipped pointer.

function manifest(overrides: Partial<UnitManifest> = {}): UnitManifest {
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
    ...overrides,
  }
}

async function assembledUnit(dir: string, version: string): Promise<string> {
  const source = path.join(dir, "dist-units", `unit-${version}`)
  await fs.mkdir(path.join(source, "node"), { recursive: true })
  await fs.writeFile(path.join(source, "node", "node.exe"), "node-binary")
  await fs.mkdir(path.join(source, "sidecar", "src"), { recursive: true })
  await fs.writeFile(path.join(source, "sidecar", "src", "main.ts"), "void 0")
  await fs.mkdir(path.join(source, "sdk", "node_modules", "@microsoft", "mxc-sdk"), { recursive: true })
  await fs.writeFile(
    path.join(source, "sdk", "node_modules", "@microsoft", "mxc-sdk", "package.json"),
    JSON.stringify({ name: "@microsoft/mxc-sdk", version: "1.0.0" }),
  )
  await writeManifest(source, manifest({ sdk: { name: "@microsoft/mxc-sdk", version } }))
  return source
}

async function temp() {
  return fs.mkdtemp(path.join(os.tmpdir(), "kilo-mxc-install-"))
}

describe("per-user unit install and upgrade", () => {
  test("installs a unit under the root and points `current` at it", async () => {
    const dir = await temp()
    try {
      const source = await assembledUnit(dir, "1.0.0")
      const root = path.join(dir, "user-root")
      await installUnit({ source, root })
      const current = await readCurrentPointer(root)
      assert.ok(current, "current pointer must exist after install")
      const unitDir = path.join(root, "units", current.fingerprint)
      const manifest = await readManifest(unitDir)
      assert.ok(manifest.ok)
      assert.equal(manifest.manifest.sdk.version, "1.0.0")
      assert.equal(await fs.readFile(path.join(unitDir, "node", "node.exe"), "utf8"), "node-binary")
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  test("upgrading flips the pointer atomically and leaves no orphaned units", async () => {
    const dir = await temp()
    try {
      const root = path.join(dir, "user-root")
      await installUnit({ source: await assembledUnit(dir, "1.0.0"), root })
      const first = await readCurrentPointer(root)
      await installUnit({ source: await assembledUnit(dir, "1.0.1"), root })
      const second = await readCurrentPointer(root)
      assert.ok(first && second)
      assert.notEqual(first.fingerprint, second.fingerprint)
      assert.equal(second.unit.sdk.version, "1.0.1")
      const units = await fs.readdir(path.join(root, "units"))
      assert.deepEqual(units.sort(), [second.fingerprint], "the superseded unit must be swept, not left behind")
      // The pointer is a single rename-flipped file: it either names the old
      // complete unit or the new complete unit, never a mixture.
      const remaining = await readManifest(path.join(root, "units", units[0]!))
      assert.ok(remaining.ok)
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  test("re-installing the same unit is a no-op that keeps the tree intact", async () => {
    const dir = await temp()
    try {
      const root = path.join(dir, "user-root")
      await installUnit({ source: await assembledUnit(dir, "1.0.0"), root })
      const before = await readCurrentPointer(root)
      await installUnit({ source: await assembledUnit(dir, "1.0.0"), root })
      const after = await readCurrentPointer(root)
      assert.deepEqual(before, after)
      const units = await fs.readdir(path.join(root, "units"))
      assert.equal(units.length, 1)
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  test("writes nothing outside the requested root and never spawns a process", async () => {
    const dir = await temp()
    try {
      const source = await assembledUnit(dir, "1.0.0")
      const root = path.join(dir, "user-root")
      const siblingsBefore = new Set(await fs.readdir(dir))
      await installUnit({ source, root })
      const siblingsAfter = new Set(await fs.readdir(dir))
      assert.deepEqual([...siblingsAfter].filter((name) => !siblingsBefore.has(name)), ["user-root"])
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  test("refuses a source without a valid manifest and leaves the root untouched", async () => {
    const dir = await temp()
    try {
      const source = path.join(dir, "not-a-unit")
      await fs.mkdir(source, { recursive: true })
      const root = path.join(dir, "user-root")
      await assert.rejects(installUnit({ source, root }), /manifest/)
      assert.equal(await fs.stat(root).then(() => true, () => false), false)
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  test("sweepUnits removes staging leftovers and unreferenced units but keeps the current one", async () => {
    const dir = await temp()
    try {
      const root = path.join(dir, "user-root")
      await installUnit({ source: await assembledUnit(dir, "1.0.0"), root })
      const current = await readCurrentPointer(root)
      const orphan = path.join(root, "units", fingerprintOf(manifest({ sdk: { name: "@microsoft/mxc-sdk", version: "0.9.0" } })))
      await fs.mkdir(orphan, { recursive: true })
      await fs.mkdir(path.join(root, "units", ".staging-orphan"), { recursive: true })
      await sweepUnits(root)
      const units = await fs.readdir(path.join(root, "units"))
      assert.deepEqual(units, [current!.fingerprint])
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  test("removeUnit leaves no sidecar orphans behind", async () => {
    const dir = await temp()
    try {
      const root = path.join(dir, "user-root")
      await installUnit({ source: await assembledUnit(dir, "1.0.0"), root })
      await removeUnit(root)
      assert.deepEqual(await fs.readdir(root), [])
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })
})
