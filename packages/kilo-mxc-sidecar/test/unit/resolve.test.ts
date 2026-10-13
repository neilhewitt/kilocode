import { describe, test } from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { resolveUnit } from "../../src/unit/resolve.ts"
import { writeManifest, type UnitManifest } from "../../src/unit/manifest.ts"
import { installUnit } from "../../src/unit/install.ts"

function manifest(sdkVersion = "1.0.0", protocol = 1): UnitManifest {
  return {
    unitFormat: 1,
    platform: { os: "win32", arch: "x64" },
    node: {
      version: "24.21.0",
      archive: "node-v24.21.0-win-x64.zip",
      sha256: "158f7685b44de51f6c0df1d153526cbcd3e1bc739a8dfc607721cef75de9e541",
      source: "https://nodejs.org/dist/v24.21.0/node-v24.21.0-win-x64.zip",
    },
    sdk: { name: "@microsoft/mxc-sdk", version: sdkVersion },
    sidecar: { package: "@kilocode/mxc-sidecar", version: "7.8.9", protocol, entry: "sidecar/src/main.ts" },
    created: "2026-10-13T00:00:00.000Z",
  }
}

async function unitAt(dir: string, sdkVersion = "1.0.0", protocol = 1): Promise<string> {
  await fs.mkdir(path.join(dir, "node"), { recursive: true })
  await fs.writeFile(path.join(dir, "node", "node.exe"), "node-binary")
  await fs.mkdir(path.join(dir, "sidecar", "src"), { recursive: true })
  await fs.writeFile(path.join(dir, "sidecar", "src", "main.ts"), "void 0")
  const pkgDir = path.join(dir, "sdk", "node_modules", "@microsoft", "mxc-sdk")
  await fs.mkdir(path.join(pkgDir, "dist", "v1"), { recursive: true })
  await fs.mkdir(path.join(pkgDir, "bin", "x64"), { recursive: true })
  await fs.writeFile(path.join(pkgDir, "bin", "x64", "wxc-exec.exe"), "fake")
  await fs.writeFile(path.join(pkgDir, "dist", "v1", "index.js"), "export const getPlatformSupport = async () => ({})\n")
  await fs.writeFile(
    path.join(pkgDir, "package.json"),
    JSON.stringify({ name: "@microsoft/mxc-sdk", version: sdkVersion, exports: { "./v1": "./dist/v1/index.js" } }),
  )
  await writeManifest(dir, manifest(sdkVersion, protocol))
  return dir
}

async function temp() {
  return fs.mkdtemp(path.join(os.tmpdir(), "kilo-mxc-resolve-"))
}

const EXPECTED = { sdk: { version: "1.0.0" }, node: { version: "24.21.0" }, protocol: 1 }

describe("sidecar unit resolution", () => {
  test("finds the unit bundled beside the binary and returns a complete launch spec", async () => {
    const dir = await temp()
    try {
      const unit = await unitAt(path.join(dir, "bin", "mxc-sidecar-unit"))
      const resolved = await resolveUnit({
        execPath: path.join(dir, "bin", "kilo.exe"),
        expected: EXPECTED,
      })
      assert.ok(resolved.ok, resolved.ok ? "" : resolved.reasons.join("; "))
      assert.equal(resolved.dir, unit)
      assert.equal(resolved.node, path.join(unit, "node", "node.exe"))
      assert.equal(resolved.entry, path.join(unit, "sidecar", "src", "main.ts"))
      assert.equal(
        resolved.env.KILO_MXC_SDK_ENTRY,
        path.join(unit, "sdk", "node_modules", "@microsoft", "mxc-sdk", "dist", "v1", "index.js"),
      )
      assert.equal(resolved.env.MXC_BIN_DIR, path.join(unit, "sdk", "node_modules", "@microsoft", "mxc-sdk", "bin", "x64"))
      assert.equal(resolved.env.MXC_FFI_DIR, resolved.env.MXC_BIN_DIR)
      assert.equal(resolved.env.KILO_MXC_UNIT, unit)
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  test("CLI and extension binaries beside identical unit copies resolve identically", async () => {
    const dir = await temp()
    try {
      const cliUnit = await unitAt(path.join(dir, "cli-dist", "bin", "mxc-sidecar-unit"))
      const extUnit = await unitAt(path.join(dir, "extension-dist", "bin", "mxc-sidecar-unit"))
      const cli = await resolveUnit({ execPath: path.join(dir, "cli-dist", "bin", "kilo.exe"), expected: EXPECTED })
      const ext = await resolveUnit({ execPath: path.join(dir, "extension-dist", "bin", "kilo.exe"), expected: EXPECTED })
      assert.ok(cli.ok && ext.ok)
      // Same pins, same manifest, same relative layout: the launch specs are
      // byte-identical apart from the absolute location of the unit.
      const strip = (spec: typeof cli) =>
        JSON.stringify(spec, (_key, value: unknown) =>
          typeof value === "string" ? value.replaceAll(cliUnit, "<unit>").replaceAll(extUnit, "<unit>") : value,
        )
      assert.equal(strip(cli), strip(ext))
      assert.equal(cli.manifest.sdk.version, ext.manifest.sdk.version)
      assert.equal(cli.manifest.node.sha256, ext.manifest.node.sha256)
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  test("KILO_MXC_UNIT overrides every search path", async () => {
    const dir = await temp()
    try {
      const override = await unitAt(path.join(dir, "custom-unit"))
      const resolved = await resolveUnit({
        env: { KILO_MXC_UNIT: override },
        execPath: path.join(dir, "nowhere", "kilo.exe"),
        expected: EXPECTED,
      })
      assert.ok(resolved.ok)
      assert.equal(resolved.dir, override)
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  test("falls back to the per-user install when nothing is bundled beside the binary", async () => {
    const dir = await temp()
    try {
      const source = await unitAt(path.join(dir, "bundled"))
      const root = path.join(dir, "user-root")
      await installUnit({ source, root })
      const resolved = await resolveUnit({
        execPath: path.join(dir, "elsewhere", "kilo.exe"),
        userRoot: root,
        expected: EXPECTED,
      })
      assert.ok(resolved.ok, resolved.ok ? "" : resolved.reasons.join("; "))
      assert.ok(resolved.dir.startsWith(path.join(root, "units")))
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  test("refuses a unit whose pins do not match the expected release pins", async () => {
    const dir = await temp()
    try {
      await unitAt(path.join(dir, "bin", "mxc-sidecar-unit"), "9.9.9")
      const resolved = await resolveUnit({ execPath: path.join(dir, "bin", "kilo.exe"), expected: EXPECTED })
      assert.ok(!resolved.ok)
      assert.ok(resolved.reasons.join("; ").includes("sdk"), "the refusal must name the pin that mismatched")
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  test("reports why nothing was found instead of throwing", async () => {
    const dir = await temp()
    try {
      const resolved = await resolveUnit({ execPath: path.join(dir, "bin", "kilo.exe"), expected: EXPECTED })
      assert.ok(!resolved.ok)
      assert.ok(resolved.reasons.length >= 1)
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })
})

