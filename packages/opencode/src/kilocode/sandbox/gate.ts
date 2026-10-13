import { Effect } from "effect"
import { OFF_PLATFORM_ASSESSMENT, probeMxcSupport, type GateAssessment } from "@kilocode/sandbox"

// Session-start host gating (ticket 14, ADRs 0001/0005): a read-only capability
// probe decides whether sandbox mode may run. The probe runs once per server
// process on Windows; every other platform is off-platform by construction and
// never probes, so existing darwin/linux behaviour is untouched. Nothing here
// elevates or writes — the sidecar is asked for platform support and torn down.

export const UNSANDBOXED_SIGNAL = "RUNNING UNSANDBOXED"

let probed: Promise<GateAssessment> | undefined

function probe() {
  probed ??= probeMxcSupport()
  return probed
}

export const assess = Effect.fn("SandboxGate.assess")(function* () {
  if (process.platform !== "win32") return OFF_PLATFORM_ASSESSMENT
  return yield* Effect.promise(probe)
})

export type GateStatus = {
  readonly available: boolean
  readonly reason?: string | undefined
  readonly diagnostics: ReadonlyArray<string>
}

// Folds a gate assessment into the backend support answer: a refused gate
// overrides availability with its precise reason and verbatim diagnostics.
export function fold(support: { available: boolean; reason?: string | undefined }, gate: GateAssessment): GateStatus {
  if (gate.verdict === "enforce") return { available: support.available, reason: support.reason, diagnostics: [] }
  return { available: false, reason: gate.reason ?? support.reason, diagnostics: gate.diagnostics }
}
