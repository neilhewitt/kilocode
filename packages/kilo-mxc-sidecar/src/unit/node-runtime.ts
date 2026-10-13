// Acquires the pinned Node runtime for the sidecar unit. Downloads come only
// from official nodejs.org distributions and are verified twice: against the
// sha256 pinned in pins.ts (committed alongside the release) and against a
// freshly fetched SHASUMS256.txt from the same official directory. A rejected
// download is never extracted; an extracted runtime that does not report the
// pinned version is refused. The cache is content-addressed by archive digest.

import { spawn } from "node:child_process"
import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import { UNIT_PINS, NODE_DIST_BASE, nodeShasumsUrl, type UnitPlatform } from "./pins.ts"

export type NodePins = {
  version: string
  archives: Record<string, { archive: string; sha256: string }>
}

function pinFor(pins: NodePins, os: UnitPlatform["os"], arch: UnitPlatform["arch"]) {
  const pin = pins.archives[`${os}-${arch}`]
  if (!pin) throw new Error(`No pinned Node distribution for ${os}-${arch}`)
  return pin
}

export type UrlFetch = (url: string) => Promise<Response>

export type FetchNodeOptions = {
  os: UnitPlatform["os"]
  arch: UnitPlatform["arch"]
  cacheDir: string
  pins?: NodePins
  fetchImpl?: UrlFetch
  extract?: (archive: string, dest: string) => Promise<void>
  probeVersion?: (nodeExecutable: string) => Promise<string>
  log?: (message: string) => void
}

export type NodeRuntime = {
  nodeExecutable: string
  archive: string
  sha256: string
  source: string
  version: string
  fromCache: boolean
}

function sha256(buffer: Buffer): string {
  return createHash("sha256").update(buffer).digest("hex")
}

function digestFromShasums(text: string, archive: string): string | undefined {
  for (const line of text.split("\n")) {
    const match = /^([0-9a-f]{64})\s+\*?(.+)$/.exec(line.trim())
    if (match && match[2] === archive) return match[1]
  }
  return undefined
}

export async function fetchNodeRuntime(options: FetchNodeOptions): Promise<NodeRuntime> {
  const pins = options.pins ?? UNIT_PINS.node
  const fetchImpl = options.fetchImpl ?? fetch
  const log = options.log ?? (() => {})
  const pin = pinFor(pins, options.os, options.arch)
  const distUrl = `${NODE_DIST_BASE}/v${pins.version}/${pin.archive}`
  const archivePath = path.join(options.cacheDir, pin.archive)
  const extractRoot = path.join(options.cacheDir, "extracted", `${options.os}-${options.arch}`)
  const runtimeDir = path.join(extractRoot, pin.archive.replace(/\.(zip|tar\.gz)$/, ""))
  const nodeExecutable = path.join(runtimeDir, options.os === "win32" ? "node.exe" : path.join("bin", "node"))

  let fromCache = false
  let archiveBytes: Buffer
  try {
    archiveBytes = await fs.readFile(archivePath)
    if (sha256(archiveBytes) === pin.sha256) {
      fromCache = true
    } else {
      log(`cached archive ${pin.archive} failed the pin check; re-downloading`)
      archiveBytes = undefined as unknown as Buffer
    }
  } catch {
    archiveBytes = undefined as unknown as Buffer
  }

  if (!fromCache && archiveBytes === undefined) {
    const response = await fetchImpl(distUrl)
    if (!response.ok) throw new Error(`could not download ${distUrl}: ${response.status}`)
    archiveBytes = Buffer.from(await response.arrayBuffer())
    const digest = sha256(archiveBytes)
    if (digest !== pin.sha256) {
      throw new Error(`Node archive digest mismatch for ${pin.archive}: downloaded ${digest}, pinned ${pin.sha256}`)
    }
    const shasumsResponse = await fetchImpl(nodeShasumsUrl())
    if (!shasumsResponse.ok) {
      throw new Error(`could not fetch ${nodeShasumsUrl()} to verify the Node archive: ${shasumsResponse.status}`)
    }
    const published = digestFromShasums(await shasumsResponse.text(), pin.archive)
    if (published !== pin.sha256) {
      throw new Error(`nodejs.org SHASUMS256.txt lists ${published ?? "no entry"} for ${pin.archive}, pinned ${pin.sha256}`)
    }
    await fs.mkdir(options.cacheDir, { recursive: true })
    await fs.writeFile(archivePath, archiveBytes)
    await fs.rm(extractRoot, { recursive: true, force: true })
  }

  try {
    await fs.access(nodeExecutable)
  } catch {
    const extract = options.extract ?? defaultExtract
    await fs.mkdir(extractRoot, { recursive: true })
    await extract(archivePath, extractRoot)
  }

  const probe = options.probeVersion ?? probeNodeVersion
  const reported = await probe(nodeExecutable)
  if (reported !== `v${pins.version}`) {
    throw new Error(`bundled Node at ${nodeExecutable} reports ${reported}, expected v${pins.version}`)
  }

  return {
    nodeExecutable,
    archive: pin.archive,
    sha256: pin.sha256,
    source: distUrl,
    version: pins.version,
    fromCache,
  }
}

async function defaultExtract(archive: string, dest: string): Promise<void> {
  // bsdtar (Windows 10+, macOS) reads zip and tar archives alike; GNU tar on
  // Linux handles the .tar.gz distributions and falls back to unzip for zips.
  const attempts: string[][] = [[ "tar", "-xf", archive, "-C", dest ]]
  if (archive.endsWith(".zip")) attempts.push(["unzip", "-q", archive, "-d", dest])
  for (const command of attempts) {
    const code = await new Promise<number | null>((resolve, reject) => {
      const child = spawn(command[0]!, command.slice(1), { stdio: "ignore", windowsHide: true })
      child.once("error", reject)
      child.once("close", (status) => resolve(status))
    }).catch(() => null)
    if (code === 0) return
  }
  throw new Error(`could not extract ${archive} with tar or unzip`)
}

async function probeNodeVersion(nodeExecutable: string): Promise<string> {
  const code = await new Promise<number | null>((resolve, reject) => {
    const child = spawn(nodeExecutable, ["--version"], { stdio: ["ignore", "pipe", "ignore"], windowsHide: true })
    let out = ""
    child.stdout.setEncoding("utf8")
    child.stdout.on("data", (chunk: string) => (out += chunk))
    child.once("error", reject)
    child.once("close", () => resolve(out.trim() === "" ? null : 0))
  }).catch(() => null)
  if (code === null) throw new Error(`could not run ${nodeExecutable} --version`)
  const out = await new Promise<string>((resolve, reject) => {
    const child = spawn(nodeExecutable, ["--version"], { stdio: ["ignore", "pipe", "ignore"], windowsHide: true })
    let buffer = ""
    child.stdout.setEncoding("utf8")
    child.stdout.on("data", (chunk: string) => (buffer += chunk))
    child.once("error", reject)
    child.once("close", () => resolve(buffer.trim()))
  })
  return out
}

