// Assembles the versioned sidecar unit: the pinned Node runtime, the exactly
// pinned @microsoft/mxc-sdk, and the sidecar server, laid out together with a
// manifest recording every pin. Everything is built in a staging directory
// beside the output and only swapped in once complete, so a partial or failed
// assembly can never leave a mixed or broken unit behind.
//
// Build-time only: this module needs the network (nodejs.org, npm) and archive
// tooling. Install, upgrade, and resolution never download anything.

import { spawn } from "node:child_process"
import fs from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { expectedManifest, fingerprintOf, writeManifest, type UnitManifest } from "./manifest.ts"
import { fetchNodeRuntime, type NodePins, type UrlFetch } from "./node-runtime.ts"
import { UNIT_PINS, type UnitPlatform } from "./pins.ts"

export type AssembleOptions = {
  output: string
  os: UnitPlatform["os"]
  arch: UnitPlatform["arch"]
  cacheDir: string
  sidecarDir?: string
  sidecarVersion?: string
  pins?: NodePins
  fetchImpl?: UrlFetch
  extract?: (archive: string, dest: string) => Promise<void>
  probeVersion?: (nodeExecutable: string) => Promise<string>
  sdkInstaller?: (sdkDir: string) => Promise<void>
  log?: (message: string) => void
  now?: () => Date
}

export const SIDECAR_ENTRY = "sidecar/src/main.ts"

async function defaultSidecarDir(): Promise<string> {
  return fileURLToPath(new URL("../", import.meta.url))
}

async function defaultSidecarVersion(dir: string): Promise<string> {
  const pkg = JSON.parse(await fs.readFile(path.join(dir, "package.json"), "utf8")) as { version?: string }
  if (!pkg.version) throw new Error("sidecar package.json has no version")
  return pkg.version
}

async function defaultSdkInstaller(sdkDir: string): Promise<void> {
  const npm = process.platform === "win32" ? "npm.cmd" : "npm"
  const run = (args: string[]) =>
    new Promise<void>((resolve, reject) => {
      const child = spawn(npm, ["install", "--no-audit", "--no-fund", "--omit=dev", ...args], {
        cwd: sdkDir,
        stdio: "inherit",
        windowsHide: true,
        // npm is npm.cmd on Windows, which Node only spawns through a shell
        // (CVE-2024-27980); the arguments are repo-controlled pins.
        shell: process.platform === "win32",
      })
      child.once("error", reject)
      child.once("close", (code) => (code === 0 ? resolve() : reject(new Error(`npm install exited ${code}`))))
    })
  await fs.mkdir(sdkDir, { recursive: true })
  await run([`${UNIT_PINS.sdk.name}@${UNIT_PINS.sdk.version}`])
}

export async function assembleUnit(options: AssembleOptions): Promise<string> {
  const log = options.log ?? (() => {})
  const sidecarDir = options.sidecarDir ?? (await defaultSidecarDir())
  const sidecarVersion = options.sidecarVersion ?? (await defaultSidecarVersion(path.dirname(sidecarDir)))
  const { PROTOCOL_VERSION } = await import("../protocol.ts")

  const output = path.resolve(options.output)
  const parent = path.dirname(output)
  await fs.mkdir(parent, { recursive: true })
  const staging = path.join(parent, `.mxc-sidecar-unit.staging-${process.pid}-${Math.random().toString(36).slice(2, 10)}`)

  try {
    await fs.mkdir(staging, { recursive: true })

    log(`fetching pinned Node runtime for ${options.os}-${options.arch}`)
    const runtime = await fetchNodeRuntime({
      os: options.os,
      arch: options.arch,
      cacheDir: options.cacheDir,
      pins: options.pins,
      fetchImpl: options.fetchImpl,
      extract: options.extract,
      probeVersion: options.probeVersion,
      log,
    })

    // Node is a self-contained executable; the unit carries it alone, keeping
    // the distribution at one runtime binary rather than the full npm tree.
    await fs.mkdir(path.join(staging, "node"), { recursive: true })
    await fs.copyFile(runtime.nodeExecutable, path.join(staging, "node", path.basename(runtime.nodeExecutable)))

    log(`installing ${UNIT_PINS.sdk.name}@${UNIT_PINS.sdk.version}`)
    const sdkDir = path.join(staging, "sdk")
    await fs.mkdir(sdkDir, { recursive: true })
    const installSdk = options.sdkInstaller ?? defaultSdkInstaller
    await installSdk(sdkDir)
    const installed = await installedSdkVersion(sdkDir)
    if (installed !== UNIT_PINS.sdk.version) {
      throw new Error(`the sidecar unit pins ${UNIT_PINS.sdk.name}@${UNIT_PINS.sdk.version}, but the installer planted ${installed}`)
    }

    log("copying sidecar server")
    await fs.cp(sidecarDir, path.join(staging, "sidecar", "src"), { recursive: true })

    const manifest: UnitManifest = expectedManifest(
      { os: options.os, arch: options.arch },
      { version: sidecarVersion, protocol: PROTOCOL_VERSION, entry: SIDECAR_ENTRY },
      (options.now ?? (() => new Date()))().toISOString(),
    )
    manifest.node.sha256 = runtime.sha256
    manifest.node.archive = runtime.archive
    manifest.node.source = runtime.source
    await writeManifest(staging, manifest)

    await verifyUnitLayout(staging, manifest)
    await swapIntoPlace(staging, output, log)
    log(`sidecar unit assembled at ${output} (fingerprint ${fingerprintOf(manifest)})`)
    return output
  } finally {
    await fs.rm(staging, { recursive: true, force: true }).catch(() => {})
  }
}

async function installedSdkVersion(sdkDir: string): Promise<string> {
  try {
    const pkg = JSON.parse(
      await fs.readFile(path.join(sdkDir, "node_modules", UNIT_PINS.sdk.name, "package.json"), "utf8"),
    ) as { version?: string }
    return pkg.version ?? "unknown"
  } catch {
    return "missing"
  }
}

export async function verifyUnitLayout(dir: string, manifest: UnitManifest): Promise<void> {
  const nodeExecutable = path.join(dir, "node", manifest.platform.os === "win32" ? "node.exe" : path.join("bin", "node"))
  await fs.access(nodeExecutable).catch(() => {
    throw new Error(`unit is missing the Node runtime at ${path.relative(dir, nodeExecutable)}`)
  })
  await fs.access(path.join(dir, manifest.sidecar.entry)).catch(() => {
    throw new Error(`unit is missing the sidecar entry at ${manifest.sidecar.entry}`)
  })
  await fs
    .access(path.join(dir, "sdk", "node_modules", manifest.sdk.name, "package.json"))
    .catch(() => throwMissingSdk(manifest))
}

function throwMissingSdk(manifest: UnitManifest): never {
  throw new Error(`unit is missing ${manifest.sdk.name}@${manifest.sdk.version}`)
}

// Replace-by-rename: the existing unit (if any) is moved aside, the completed
// staging directory is renamed into place, and the old copy is deleted. At no
// instant do two versions share the unit directory.
async function swapIntoPlace(staging: string, output: string, log: (message: string) => void): Promise<void> {
  const previous = path.join(path.dirname(output), `.mxc-sidecar-unit.old-${process.pid}-${Math.random().toString(36).slice(2, 10)}`)
  let hadPrevious = false
  try {
    await fs.rename(output, previous)
    hadPrevious = true
  } catch (cause) {
    const code = (cause as NodeJS.ErrnoException).code
    if (code !== "ENOENT") throw cause
  }
  try {
    await fs.rename(staging, output)
  } catch (cause) {
    if (hadPrevious) await fs.rename(previous, output).catch(() => {})
    throw cause
  }
  if (hadPrevious) await fs.rm(previous, { recursive: true, force: true }).catch(() => log("could not remove the replaced unit"))
}
