// Resolution: how the CLI binary, the extension's bundled binary, and the
// contract tests all consume the same versioned sidecar unit. The search order
// is an explicit override, the unit directory bundled beside the executable
// (identical bytes in the CLI archive and the extension's VSIX), then the
// per-user install pointer. A candidate is only used when its manifest
// validates and matches the pins this build of Kilo expects — a unit from
// another release is refused with the pin that mismatched, never used.

import { createRequire } from "node:module"
import path from "node:path"
import { readCurrentPointer } from "./install.ts"
import { readManifest, type UnitManifest } from "./manifest.ts"
import { UNIT_PINS } from "./pins.ts"

export const UNIT_DIRNAME = "mxc-sidecar-unit"

export type ExpectedPins = {
  sdk?: { version: string }
  node?: { version: string }
  protocol?: number
}

export type ResolvedUnit = {
  dir: string
  manifest: UnitManifest
  node: string
  entry: string
  env: Record<string, string>
}

export type Resolution = { ok: true } & ResolvedUnit | { ok: false; reasons: string[] }

export type ResolveOptions = {
  env?: Record<string, string | undefined>
  execPath?: string
  userRoot?: string
  expected?: ExpectedPins
}

export async function resolveUnit(options: ResolveOptions = {}): Promise<Resolution> {
  const env = options.env ?? process.env
  const execPath = options.execPath ?? process.execPath
  const expected = options.expected ?? {
    sdk: { version: UNIT_PINS.sdk.version },
    node: { version: UNIT_PINS.node.version },
    protocol: undefined,
  }

  const candidates: Array<{ dir: string; origin: string }> = []
  const override = env.KILO_MXC_UNIT
  if (override) candidates.push({ dir: override, origin: "KILO_MXC_UNIT" })
  candidates.push({ dir: path.join(path.dirname(execPath), UNIT_DIRNAME), origin: "beside the executable" })
  if (options.userRoot) {
    const pointer = await readCurrentPointer(options.userRoot)
    if (pointer) candidates.push({ dir: pointer.dir, origin: "per-user install" })
  }

  const reasons: string[] = []
  for (const candidate of candidates) {
    const manifest = await readManifest(candidate.dir)
    if (!manifest.ok) {
      reasons.push(`${candidate.origin}: ${manifest.error}`)
      continue
    }
    const mismatch = pinMismatch(manifest.manifest, expected)
    if (mismatch) {
      reasons.push(`${candidate.origin}: ${mismatch}`)
      continue
    }
    return { ok: true, ...launchSpec(candidate.dir, manifest.manifest) }
  }
  if (reasons.length === 0) reasons.push("no sidecar unit candidates were available")
  return { ok: false, reasons }
}

function pinMismatch(manifest: UnitManifest, expected: ExpectedPins): string | undefined {
  if (expected.sdk && manifest.sdk.version !== expected.sdk.version) {
    return `sdk pin is ${manifest.sdk.version}, this build expects ${expected.sdk.version}`
  }
  if (expected.node && manifest.node.version !== expected.node.version) {
    return `Node pin is ${manifest.node.version}, this build expects ${expected.node.version}`
  }
  if (expected.protocol !== undefined && manifest.sidecar.protocol !== expected.protocol) {
    return `sidecar protocol is ${manifest.sidecar.protocol}, this build speaks ${expected.protocol}`
  }
  return undefined
}

export function launchSpec(dir: string, manifest: UnitManifest): ResolvedUnit {
  const node = path.join(dir, "node", manifest.platform.os === "win32" ? "node.exe" : path.join("bin", "node"))
  const entry = path.join(dir, manifest.sidecar.entry)
  const sdkRoot = path.join(dir, "sdk", "node_modules", manifest.sdk.name)
  const bins = path.join(sdkRoot, "bin", manifest.platform.arch)
  return {
    dir,
    manifest,
    node,
    entry,
    env: {
      KILO_MXC_UNIT: dir,
      // The sidecar's SDK loader (src/sdk.ts) loads the bundled SDK through
      // this explicit entry; MXC's own MXC_BIN_DIR/MXC_FFI_DIR point at the
      // architecture directory shipped inside the unit.
      KILO_MXC_SDK_ENTRY: resolveSdkEntry(dir, manifest),
      MXC_BIN_DIR: bins,
      MXC_FFI_DIR: bins,
    },
  }
}

function resolveSdkEntry(dir: string, manifest: UnitManifest): string {
  const marker = path.join(dir, "sdk", "node_modules", "entry-resolution.js")
  const require = createRequire(marker)
  try {
    return require.resolve(`${manifest.sdk.name}/v1`)
  } catch {
    return path.join(dir, "sdk", "node_modules", manifest.sdk.name, "dist", "v1", "index.js")
  }
}
