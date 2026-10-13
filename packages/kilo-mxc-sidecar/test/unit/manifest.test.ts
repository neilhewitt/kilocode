import { describe, test } from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { fingerprintOf, readManifest, validateManifest, writeManifest, type UnitManifest } from "../../src/unit/manifest.ts"

async function temp() {
  return fs.mkdtemp(path.join(os.tmpdir(), "kilo-mxc-manifest-"))
}

function example(): UnitManifest {
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

describe("unit manifest", () => {
  test("round-trips through a unit directory", async () => {
    const dir = await temp()
    try {
      await writeManifest(dir, example())
      const read = await readManifest(dir)
      assert.ok(read.ok, `expected a valid manifest: ${read.ok ? "" : read.error}`)
      assert.deepEqual(read.manifest, example())
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  test("fingerprint is stable across creation time but tracks every pin", () => {
    const a = example()
    const b = { ...example(), created: "1999-01-01T00:00:00.000Z" }
    assert.equal(fingerprintOf(a), fingerprintOf(b))
    const sdkBump = { ...example(), sdk: { ...example().sdk, version: "1.1.0" } }
    assert.notEqual(fingerprintOf(a), fingerprintOf(sdkBump))
    const nodeBump = { ...example(), node: { ...example().node, version: "24.22.0" } }
    assert.notEqual(fingerprintOf(a), fingerprintOf(nodeBump))
    const protocolBump = { ...example(), sidecar: { ...example().sidecar, protocol: 2 } }
    assert.notEqual(fingerprintOf(a), fingerprintOf(protocolBump))
  })

  test("fingerprint is hex and independent of key order", () => {
    const a = example()
    const reordered: UnitManifest = {
      created: a.created,
      sidecar: a.sidecar,
      sdk: a.sdk,
      node: a.node,
      platform: a.platform,
      unitFormat: a.unitFormat,
    }
    assert.equal(fingerprintOf(a), fingerprintOf(reordered))
    assert.match(fingerprintOf(a), /^[0-9a-f]{16,}$/)
  })

  test("validateManifest rejects malformed manifests with the field named", () => {
    const good = example()
    assert.ok(validateManifest(good).ok)
    assert.ok(!validateManifest({ ...good, unitFormat: 2 }).ok)
    assert.ok(!validateManifest({ ...good, node: { ...good.node, sha256: "zz" } }).ok)
    assert.ok(!validateManifest({ ...good, node: { ...good.node, source: "https://evil.example/node.zip" } }).ok)
    assert.ok(!validateManifest({ ...good, sdk: { ...good.sdk, version: "^1.0.0" } }).ok)
    assert.ok(!validateManifest({ ...good, platform: { ...good.platform, os: "aix" } }).ok)
    assert.ok(!validateManifest(null).ok)
    assert.ok(!validateManifest("nope").ok)
  })

  test("readManifest reports a missing file instead of throwing", async () => {
    const dir = await temp()
    try {
      const result = await readManifest(dir)
      assert.equal(result.ok, false)
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })
})

