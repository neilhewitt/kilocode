import type { PathRelaxation, Relaxation } from "./profile"

// The relaxation model (ADR 0002): every widening of the grant table is a
// deliberate, recorded relaxation — durable from config, ephemeral from the
// session prompt — and only relaxations ever widen a table. This module holds
// the pure halves: what a valid relaxation entry is, how durable and ephemeral
// entries merge for one command, and which entries compose into a filesystem
// posture. Recording happens at the session layer; composition happens in the
// backend's translation.

export function isRelaxation(value: unknown): value is Relaxation {
  if (typeof value !== "object" || value === null) return false
  const entry = value as Record<string, unknown>
  if (typeof entry.reason !== "undefined" && typeof entry.reason !== "string") return false
  if (entry.kind === "terminal")
    return Object.keys(entry).every((key) => key === "kind" || key === "reason")
  if (entry.kind !== "path") return false
  return (
    (entry.access === "read" || entry.access === "write") && typeof entry.path === "string" && entry.path !== ""
  )
}

// Only path relaxations change a filesystem table; terminal relaxations are
// recorded grants the PTY surface consumes without touching the table.
export function pathRelaxations(entries: ReadonlyArray<Relaxation> | undefined): ReadonlyArray<PathRelaxation> {
  if (entries === undefined) return []
  const composed: Array<PathRelaxation> = []
  for (const entry of entries) {
    if (isRelaxation(entry) && entry.kind === "path") composed.push(entry)
  }
  return composed
}

// One command's effective relaxations: durable config entries first, then the
// session's prompt-granted ones, in grant order. An identical grant composes
// once. Malformed entries never reach the table — relaxation is the one
// deliberate widening surface, and it fails closed.
export function merged(config: ReadonlyArray<Relaxation>, session: ReadonlyArray<Relaxation>): Array<Relaxation> {
  const seen = new Set<string>()
  const applied: Array<Relaxation> = []
  for (const entry of [...config, ...session]) {
    if (!isRelaxation(entry)) continue
    const key =
      entry.kind === "path"
        ? `path:${entry.access}:${process.platform === "win32" ? entry.path.toLowerCase() : entry.path}`
        : "terminal"
    if (seen.has(key)) continue
    seen.add(key)
    applied.push(entry)
  }
  return applied
}
