// The unit manifest records every pin the versioned sidecar unit carries: the
// Node runtime (with its official nodejs.org source and digest), the exact
// @microsoft/mxc-sdk version, and the sidecar server with its control-channel
// protocol version. Install, upgrade, resolution, and release notes all read
// this file; nothing else gets to invent versions.

import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import { NODE_DIST_BASE, UNIT_PINS, nodeArchivePin } from "./pins.ts"

export const MANIFEST_FILENAME = "manifest.json"
export const UNIT_FORMAT_VERSION = 1

const SHA256 = /^[0-9a-f]{64}$/
const EXACT_SEMVER = /^\d+\.\d+\.\d+$/
const OS = new Set(["win32", "linux", "darwin"])
const ARCH = new Set(["x64", "arm64"])

export type UnitPlatform = {
  os: "win32" | "linux" | "darwin"
  arch: "x64" | "arm64"
}

export type UnitManifest = {
  unitFormat: number
  platform: UnitPlatform
  node: {
    version: string
    archive: string
    sha256: string
    source: string
  }
  sdk: {
    name: string
    version: string
  }
  sidecar: {
    package: string
    version: string
    protocol: number
    entry: string
  }
  created: string
}

export type ManifestCheck = { ok: true; manifest: UnitManifest } | { ok: false; error: string }

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function field(object: Record<string, unknown>, name: string): unknown {
  return object[name]
}

export function validateManifest(value: unknown): ManifestCheck {
  if (!isObject(value)) return { ok: false, error: "manifest must be a JSON object" }
  if (value.unitFormat !== UNIT_FORMAT_VERSION) {
    return { ok: false, error: `unitFormat must be ${UNIT_FORMAT_VERSION}` }
  }
  const platform = field(value, "platform")
  if (!isObject(platform) || !OS.has(String(field(platform, "os"))) || !ARCH.has(String(field(platform, "arch")))) {
    return { ok: false, error: "platform must be one of win32/linux/darwin x x64/arm64" }
  }
  const node = field(value, "node")
  if (!isObject(node)) return { ok: false, error: "node section is missing" }
  if (typeof field(node, "version") !== "string" || !EXACT_SEMVER.test(String(field(node, "version")))) {
    return { ok: false, error: "node.version must be an exact semver" }
  }
  if (typeof field(node, "sha256") !== "string" || !SHA256.test(String(field(node, "sha256")))) {
    return { ok: false, error: "node.sha256 must be a lowercase hex sha256" }
  }
  const source = field(node, "source")
  if (typeof source !== "string" || !source.startsWith(`${NODE_DIST_BASE}/`)) {
    return { ok: false, error: `node.source must come from ${NODE_DIST_BASE}` }
  }
  if (typeof field(node, "archive") !== "string") return { ok: false, error: "node.archive is missing" }
  const sdk = field(value, "sdk")
  if (!isObject(sdk)) return { ok: false, error: "sdk section is missing" }
  if (typeof field(sdk, "name") !== "string") return { ok: false, error: "sdk.name is missing" }
  if (typeof field(sdk, "version") !== "string" || !EXACT_SEMVER.test(String(field(sdk, "version")))) {
    return { ok: false, error: "sdk.version must be an exact pin, never a range" }
  }
  const sidecar = field(value, "sidecar")
  if (!isObject(sidecar)) return { ok: false, error: "sidecar section is missing" }
  if (typeof field(sidecar, "version") !== "string" || !EXACT_SEMVER.test(String(field(sidecar, "version")))) {
    return { ok: false, error: "sidecar.version must be an exact semver" }
  }
  if (typeof field(sidecar, "protocol") !== "number" || !Number.isInteger(field(sidecar, "protocol"))) {
    return { ok: false, error: "sidecar.protocol must be an integer" }
  }
  if (typeof field(sidecar, "entry") !== "string") return { ok: false, error: "sidecar.entry is missing" }
  if (typeof field(value, "created") !== "string") return { ok: false, error: "created is missing" }
  return { ok: true, manifest: value as UnitManifest }
}

// The fingerprint identifies the pin set: every field except `created`, hashed
// over canonically sorted JSON. Unit directories are named by it, so an update
// with different pins can never land inside the previous version's directory.
export function fingerprintOf(manifest: UnitManifest): string {
  const { created: _created, ...pins } = manifest
  const canonical = JSON.stringify(sortKeys(pins))
  return createHash("sha256").update(canonical).digest("hex").slice(0, 24)
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (isObject(value)) {
    const sorted: Record<string, unknown> = {}
    for (const key of Object.keys(value).sort()) sorted[key] = sortKeys(value[key])
    return sorted
  }
  return value
}

export async function writeManifest(dir: string, manifest: UnitManifest): Promise<void> {
  const check = validateManifest(manifest)
  if (!check.ok) throw new Error(`refusing to write invalid manifest: ${check.error}`)
  await fs.writeFile(path.join(dir, MANIFEST_FILENAME), JSON.stringify(manifest, null, 2) + "\n", "utf8")
}

export async function readManifest(dir: string): Promise<ManifestCheck> {
  let text: string
  try {
    text = await fs.readFile(path.join(dir, MANIFEST_FILENAME), "utf8")
  } catch {
    return { ok: false, error: `no ${MANIFEST_FILENAME} in ${dir}` }
  }
  try {
    return validateManifest(JSON.parse(text))
  } catch (cause) {
    return { ok: false, error: `manifest is not valid JSON: ${cause instanceof Error ? cause.message : String(cause)}` }
  }
}

// The manifest a fresh assembly of the current pins would produce, for checking
// an on-disk unit against the pins this build of Kilo expects.
export function expectedManifest(platform: UnitPlatform, sidecar: { version: string; protocol: number; entry: string }, created = new Date().toISOString()): UnitManifest {
  const pin = nodeArchivePin(platform.os, platform.arch)
  return {
    unitFormat: UNIT_FORMAT_VERSION,
    platform,
    node: {
      version: UNIT_PINS.node.version,
      archive: pin.archive,
      sha256: pin.sha256,
      source: `${NODE_DIST_BASE}/v${UNIT_PINS.node.version}/${pin.archive}`,
    },
    sdk: { ...UNIT_PINS.sdk },
    sidecar: {
      package: "@kilocode/mxc-sidecar",
      version: sidecar.version,
      protocol: sidecar.protocol,
      entry: sidecar.entry,
    },
    created,
  }
}
