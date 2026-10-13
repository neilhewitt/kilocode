import { describe, test } from "node:test"
import assert from "node:assert/strict"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { assembleUnit } from "../../src/unit/assemble.ts"
import { readManifest } from "../../src/unit/manifest.ts"

// Everything remote or tool-dependent is injected: the Node runtime comes from
// a fake verified download, the SDK from a fake installer that plants a
// package.json like npm's. These tests pin the assembly contract: layout,
// manifest, SDK version enforcement, staging cleanup, and replace semantics.
const NODE_BYTES = Buffer.from("official-node-archive-bytes")

function nodePins() {
  return {
    version: "24.21.0",
    archives: {
      "win32-x64": {
        archive: "node-v24.21.0-win-x64.zip",
        sha256: "3f0b3d0e14de13e2d5b7f76c9df0e21bd77ee72ea9a6a0a53df8ac0d1c6f62ea",
      },
    },
  }
}

function shasums(digest: string) {
  return `${digest}  node-v24.21.0-win-x64.zip\n`
}

async function sha256(buffer: Buffer) {
  const { createHash } = await import("node:crypto")
  return createHash("sha256").update(buffer).digest("hex")
}

function fakeFetch(digest: string) {
  return async (url: string) => {
    if (url.endsWith("SHASUMS256.txt")) return new Response(shasums(digest), { status: 200 })
    if (url.endsWith(".zip")) return new Response(NODE_BYTES, { status: 200 })
    return new Response("not found", { status: 404 })
  }
}

async function fakeExtract(archive: string, dest: string) {
  const dir = path.join(dest, "node-v24.21.0-win-x64")
  await fs.mkdir(dir, { recursive: true })
  await fs.writeFile(path.join(dir, "node.exe"), "fake-node-binary")
}

async function fakeInstallSdk(sdkDir: string, version = "1.0.0") {
  const pkgDir = path.join(sdkDir, "node_modules", "@microsoft", "mxc-sdk")
  await fs.mkdir(pkgDir, { recursive: true })
  await fs.writeFile(
    path.join(pkgDir, "package.json"),
    JSON.stringify({
      name: "@microsoft/mxc-sdk",
      version,
      exports: { "./v1": "./dist/v1/index.js" },
    }),
  )
  await fs.mkdir(path.join(pkgDir, "dist", "v1"), { recursive: true })
  await fs.writeFile(path.join(pkgDir, "dist", "v1", "index.js"), "export const getPlatformSupport = async () => ({})\n")
  await fs.mkdir(path.join(pkgDir, "bin", "x64"), { recursive: true })
  await fs.writeFile(path.join(pkgDir, "bin", "x64", "wxc-exec.exe"), "fake")
}

function sidecarSource() {
  return fileURLToPath(new URL("../../src", import.meta.url))
}

async function temp() {
  return fs.mkdtemp(path.join(os.tmpdir(), "kilo-mxc-assemble-"))
}

async function buildOptions(dir: string, overrides: Record<string, unknown> = {}) {
  const digest = await sha256(NODE_BYTES)
  const pins = { ...nodePins(), archives: { "win32-x64": { archive: "node-v24.21.0-win-x64.zip", sha256: digest } } }
  return {
    output: path.join(dir, "bin", "mxc-sidecar-unit"),
    os: "win32" as const,
    arch: "x64" as const,
    cacheDir: path.join(dir, "cache"),
    sidecarDir: sidecarSource(),
    pins,
    fetchImpl: fakeFetch(digest),
    extract: fakeExtract,
    probeVersion: async () => "v24.21.0",
    sdkInstaller: (sdkDir: string) => fakeInstallSdk(sdkDir),
    log: () => {},
    ...overrides,
  }
}

describe("sidecar unit assembly", () => {
  test("lays out Node runtime, pinned SDK, sidecar server, and manifest as one unit", async () => {
    const dir = await temp()
    try {
      const unit = await assembleUnit(await buildOptions(dir))
      const nodeStat = await fs.stat(path.join(unit, "node", "node.exe"))
      assert.ok(nodeStat.isFile())
      const sdkPkg = JSON.parse(
        await fs.readFile(path.join(unit, "sdk", "node_modules", "@microsoft", "mxc-sdk", "package.json"), "utf8"),
      )
      assert.equal(sdkPkg.version, "1.0.0")
      const manifest = await readManifest(unit)
      assert.ok(manifest.ok, manifest.ok ? "" : manifest.error)
      assert.equal(manifest.manifest.node.version, "24.21.0")
      assert.equal(manifest.manifest.node.sha256, await sha256(NODE_BYTES))
      assert.equal(manifest.manifest.sdk.version, "1.0.0")
      assert.ok(manifest.manifest.sidecar.entry.startsWith("sidecar/"))
      assert.equal(await fs.stat(path.join(unit, manifest.manifest.sidecar.entry)).then(() => true), true)
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  test("refuses an SDK the installer planted at a version other than the pin", async () => {
    const dir = await temp()
    try {
      const options = await buildOptions(dir, { sdkInstaller: (sdkDir: string) => fakeInstallSdk(sdkDir, "1.2.3") })
      await assert.rejects(assembleUnit(options), /planted 1\.2\.3/)
      assert.equal(await fs.stat(options.output).then(() => true, () => false), false, "no unit may appear on refusal")
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  test("a failed assembly leaves the previous unit and no staging directories behind", async () => {
    const dir = await temp()
    try {
      const options = await buildOptions(dir)
      const unit = await assembleUnit(options)
      const before = await fs.readFile(path.join(unit, "manifest.json"), "utf8")
      const binDir = path.dirname(options.output)
      await assert.rejects(
        assembleUnit({
          ...options,
          sdkInstaller: () => {
            throw new Error("npm exploded")
          },
        }),
        /npm exploded/,
      )
      assert.equal(await fs.readFile(path.join(unit, "manifest.json"), "utf8"), before, "previous unit untouched")
      const leftovers = (await fs.readdir(binDir)).filter((name) => name.includes("staging") || name.includes(".old"))
      assert.deepEqual(leftovers, [])
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })

  test("re-assembling replaces the unit wholesale: new manifest, no leftovers", async () => {
    const dir = await temp()
    try {
      const options = await buildOptions(dir)
      await assembleUnit(options)
      const second = await assembleUnit({ ...options, sidecarVersion: "9.9.9" })
      const manifest = await readManifest(second)
      assert.ok(manifest.ok)
      assert.equal(manifest.manifest.sidecar.version, "9.9.9")
      const binDir = path.dirname(options.output)
      const leftovers = (await fs.readdir(binDir)).filter((name) => name.includes("staging") || name.includes(".old"))
      assert.deepEqual(leftovers, [])
      assert.deepEqual(await fs.readdir(binDir), ["mxc-sidecar-unit"])
    } finally {
      await fs.rm(dir, { recursive: true, force: true })
    }
  })
})
