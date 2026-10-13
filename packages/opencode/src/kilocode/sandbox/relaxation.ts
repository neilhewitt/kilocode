import { isRelaxation, merged, type Relaxation } from "@kilocode/sandbox"

// The relaxation seam (ADR 0002, ticket 15). Every widening of the grant table
// flows through here so the surfaces that grant relaxations — durable config
// and the ephemeral permission prompt, with the PTY relaxation (ticket 17)
// plugging into the same request/grant/record shape — stay generic:
//
//   request  → SandboxRelaxation.grantable(...)   (validate)
//   grant    → SandboxPolicy.relax(...)           (persist per-session + record)
//   record   → SandboxStore.appendAudit(...)      (session log, with source)
//
// Composition into a table is @kilocode/sandbox's merged(); validation and
// dedupe are shared with the backend so config, prompt, and store all agree on
// what a relaxation is.

export namespace SandboxRelaxation {
  export type Source = "config" | "prompt"

  /** A relaxation request: a path grant or the terminal kind, optionally with the reason a prompt showed. */
  export type Request = Relaxation & { readonly reason?: string | undefined }

  const logged = new Set<string>()

  /** True the first time a session asks with a given key; later asks return false. */
  export function once(scope: string) {
    if (logged.has(scope)) return false
    logged.add(scope)
    return true
  }

  export function grantable(request: unknown): request is Request {
    return isRelaxation(request)
  }

  /** The effective relaxations for one command's table: durable config first, then the session's prompt grants. */
  export function effective(config: ReadonlyArray<Relaxation>, session: ReadonlyArray<Relaxation> | undefined) {
    return merged(config, session ?? [])
  }

  /** Appends one prompt-granted relaxation, composing an identical grant once. */
  export function appended(existing: ReadonlyArray<Relaxation>, request: Request) {
    const entries = merged([...existing], [request])
    return { entries, added: entries.length > existing.length }
  }

  /** The session-log record for one relaxation grant, carrying its source. */
  export function record(entry: Relaxation, source: Source) {
    return { type: "sandbox.relaxation", source, ...entry }
  }
}
