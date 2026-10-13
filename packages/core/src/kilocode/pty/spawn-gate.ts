// kilocode_change - ticket 17: the sandbox-aware terminal spawn gate (ADR 0004).
//
// The PTY service spawns session terminals through the `#pty` driver — a real
// ConPTY process with full reach. Under sandbox mode every session terminal
// must instead run confined, and the MXC engine cannot give a confined command
// a PTY (`unsupported_containment` from spawnWithPty on the processcontainer
// backend; tracked upstream — see @kilocode/sandbox's PTY_REVISIT_TRIGGER), so
// the confined terminal is the pipes fallback. Which posture applies is
// session-scoped sandbox policy — the opencode layer's knowledge, not this
// package's — so the decision is injected here as a consultable gate: the
// host package (opencode) sets `setSpawnGate(...)` once; the PTY service
// consults the gate for every create and falls back to the plain PTY spawn
// whenever no gate is installed (the unsandboxed behaviour this default
// preserves for non-Kilo hosts).
import type { Effect } from "effect"
import type { Proc } from "../../pty/pty"

export type SpawnGateInput = {
  readonly command: string
  readonly args: ReadonlyArray<string>
  readonly cwd: string
  readonly env: Record<string, string>
  // The session the terminal is created in the context of, when the caller
  // knows one; null means the caller explicitly cleared the association. The
  // sandbox policy is session-scoped, so an absent session falls back to the
  // directory's sandbox default.
  readonly sessionID?: string | null | undefined
  // The owning directory of the terminal's location.
  readonly directory: string
}

export type SpawnDecision =
  | // The real ConPTY terminal as always (sandbox off, audit mode, or a
    // granted PTY relaxation).
    { readonly mode: "pty" }
  | // The pipes fallback: `proc` is a Proc-shaped driver over the confined
    // run-shim launch — output streams live, input and resize are degraded
    // no-ops, kill is the tree kill.
    { readonly mode: "pipes"; readonly proc: Proc }

// The gate resolves the sandbox policy. A gate failure FAILS the terminal
// create: the enforced posture must never regress to an unconsulted plain PTY.
export type SpawnGate = (input: SpawnGateInput) => Effect.Effect<SpawnDecision, unknown>

const state: { gate?: SpawnGate } = {}

/** Registers the sandbox-aware gate. Passing undefined restores the plain PTY default. */
export function setSpawnGate(gate: SpawnGate | undefined): void {
  state.gate = gate
}

/** The registered gate, when the host package installed one. */
export function current(): SpawnGate | undefined {
  return state.gate
}
