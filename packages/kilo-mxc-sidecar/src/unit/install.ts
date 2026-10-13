// User-scope install, upgrade, and removal for the sidecar unit. This half of
// the distribution never downloads anything and never spawns a process — it is
// filesystem operations only, entirely under a per-user root the caller owns,
// so no supported flow can require elevation (ADR 0005).
//
// Layout under the root:
//   units/<fingerprint>/   immutable unit directories, one per pin set
//   current                a one-line pointer file naming the live fingerprint
//
// An upgrade materialises the new unit directory in full, then flips `current`
// with a single rename. Consumers resolve `current` -> `units/<fingerprint>`,
// so a running sidecar can never observe a mixed unit: the pointer names
// either the complete old unit or the complete new one.

import { randomUUID } from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import { fingerprintOf, readManifest, type UnitManifest } from "./manifest.ts"

export const UNITS_DIRNAME = "units"
export const POINTER_FILENAME = "current"

export type CurrentPointer = {
  fingerprint: string
  unit: UnitManifest
  dir: string
}

export type InstallOptions = {
  source: string
  root: string
  log?: (message: string) => void
}

function token(): string {
  return randomUUID().slice(0, 8)
}

export async function readCurrentPointer(root: string): Promise<CurrentPointer | undefined> {
  let fingerprint: string
  try {
    fingerprint = (await fs.readFile(path.join(root, POINTER_FILENAME), "utf8")).trim()
  } catch {
    return undefined
  }
  const dir = path.join(root, UNITS_DIRNAME, fingerprint)
  const manifest = await readManifest(dir)
  if (!manifest.ok) return undefined
  return { fingerprint, unit: manifest.manifest, dir }
}

export async function installUnit(options: InstallOptions): Promise<CurrentPointer> {
  const log = options.log ?? (() => {})
  const source = path.resolve(options.source)
  const root = path.resolve(options.root)
  const manifest = await readManifest(source)
  if (!manifest.ok) throw new Error(`refusing to install a unit without a valid manifest: ${manifest.error}`)

  const fingerprint = fingerprintOf(manifest.manifest)
  const unitsDir = path.join(root, UNITS_DIRNAME)
  const target = path.join(unitsDir, fingerprint)

  await fs.mkdir(unitsDir, { recursive: true })
  const existing = await readManifest(target)
  if (existing.ok && fingerprintOf(existing.manifest) === fingerprint) {
    log(`unit ${fingerprint} already installed`)
  } else {
    const staging = path.join(unitsDir, `.staging-${token()}`)
    try {
      await fs.cp(source, staging, { recursive: true })
      const staged = await readManifest(staging)
      if (!staged.ok || fingerprintOf(staged.manifest) !== fingerprint) {
        throw new Error(`staged unit does not match its own manifest: ${staged.ok ? "fingerprint changed mid-copy" : staged.error}`)
      }
      await fs.rm(target, { recursive: true, force: true })
      await fs.rename(staging, target)
    } finally {
      await fs.rm(staging, { recursive: true, force: true }).catch(() => {})
    }
    log(`installed sidecar unit ${fingerprint}`)
  }

  // The pointer flip is the commit point: one temp file, one rename.
  const pointer = path.join(root, POINTER_FILENAME)
  const pointerStaging = path.join(root, `.${POINTER_FILENAME}.${token()}`)
  await fs.writeFile(pointerStaging, `${fingerprint}\n`, "utf8")
  await fs.rename(pointerStaging, pointer)

  await sweepUnits(root, log)

  const current = await readCurrentPointer(root)
  if (!current || current.fingerprint !== fingerprint) {
    throw new Error(`pointer does not name the installed unit after upgrade: ${current?.fingerprint ?? "none"}`)
  }
  return current
}

// Repair/removal hygiene: anything under `units/` that is not the current unit
// — superseded versions, interrupted staging directories — is deleted, so
// removing or repairing the install leaves no sidecar orphans.
export async function sweepUnits(root: string, log: (message: string) => void = () => {}): Promise<void> {
  const current = await readCurrentPointer(root)
  const keep = current?.fingerprint
  const unitsDir = path.join(root, UNITS_DIRNAME)
  let entries: string[]
  try {
    entries = await fs.readdir(unitsDir)
  } catch {
    return
  }
  for (const entry of entries) {
    if (entry === keep) continue
    log(`sweeping orphaned sidecar unit ${entry}`)
    await fs.rm(path.join(unitsDir, entry), { recursive: true, force: true }).catch(() => {})
  }
}

export async function removeUnit(root: string): Promise<void> {
  await fs.rm(path.join(root, UNITS_DIRNAME), { recursive: true, force: true }).catch(() => {})
  await fs.rm(path.join(root, POINTER_FILENAME), { force: true }).catch(() => {})
}
