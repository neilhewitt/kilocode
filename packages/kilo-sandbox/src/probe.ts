import os from "node:os"
import { startSidecar } from "@kilocode/mxc-sidecar"
import { mxcRuntime } from "./mxc"
import type { Profile } from "./profile"

// Host gating (ticket 14, ADR 0001/0005): a read-only session-start capability
// probe decides whether sandbox mode may run. Only the base-container (PSEC)
// enforcement tier confines; every other tier — and any host the probe cannot
// assess — is a hard refuse carrying the OS build, the returned tier, and the
// doc link, plus probe-emitted host-prep warnings verbatim as diagnostics.
// The probe never writes, never runs a command, and never elevates: it starts
// the sidecar, handshakes, asks for platform support, and shuts it down.

export const ENFORCEMENT_FLOOR_DOC =
  "https://github.com/microsoft/mxc/blob/main/docs/backends/process-container/os-version-support.md"

export const ENFORCEMENT_FLOOR_TIER = "base-container"

export type GateVerdict = "enforce" | "refuse"

export type GateSource = "probe" | "unprobeable" | "non-windows"

export type GateAssessment = {
  readonly verdict: GateVerdict
  readonly tier: string
  readonly reason?: string | undefined
  readonly diagnostics: ReadonlyArray<string>
  readonly source: GateSource
}

// Platforms without the MXC backend never probe: their own backends govern
// support, and this gate must not change their behaviour.
export const OFF_PLATFORM_ASSESSMENT: GateAssessment = {
  verdict: "enforce",
  tier: "",
  diagnostics: [],
  source: "non-windows",
}

function warningsOf(record: Record<string, unknown>): Array<string> {
  if (!Array.isArray(record.warnings)) return []
  return record.warnings.filter((entry): entry is string => typeof entry === "string")
}

export function assessPlatformSupport(raw: unknown, osRelease: string): GateAssessment {
  const record = raw !== null && typeof raw === "object" ? (raw as Record<string, unknown>) : {}
  const supported = record.isSupported !== false
  const tier = typeof record.isolationTier === "string" ? record.isolationTier : ""
  const diagnostics = warningsOf(record)
  if (supported && tier === ENFORCEMENT_FLOOR_TIER) {
    return { verdict: "enforce", tier, diagnostics, source: "probe" }
  }
  const detail =
    tier !== ""
      ? `returned enforcement tier "${tier}"`
      : supported
        ? "returned no enforcement tier"
        : "reported this host as unsupported"
  const reason =
    `This host cannot enforce the Kilo sandbox: the MXC capability probe ${detail} on Windows build ${osRelease}. ` +
    `Kilo accepts only the ${ENFORCEMENT_FLOOR_TIER} (PSEC) enforcement tier and never falls back to a weaker one. ` +
    `See ${ENFORCEMENT_FLOOR_DOC}. No administrator rights are requested or required.`
  return { verdict: "refuse", tier, reason, diagnostics, source: "probe" }
}

export type GateDenials = {
  readonly writesDeniedOutside: ReadonlyArray<string>
  readonly writesDenied: ReadonlyArray<string>
  readonly namesDenied: ReadonlyArray<string>
  readonly environmentDenied: ReadonlyArray<string>
  readonly network: { readonly mode: Profile["network"]["mode"]; readonly allowedHosts: ReadonlyArray<string> }
}

// What a sandboxed session would have been denied, recorded in the audit log
// when a refusing host is continued unsandboxed so the record states exactly
// which protections are not in force.
export function deniedByProfile(profile: Profile): GateDenials {
  return {
    writesDeniedOutside: profile.filesystem.allowWrite.map((rule) => rule.path),
    writesDenied: profile.filesystem.denyWrite.map((rule) => rule.path),
    namesDenied: [...profile.filesystem.denyNames],
    environmentDenied: [...profile.environment.deny],
    network: { mode: profile.network.mode, allowedHosts: [...profile.network.allowedHosts] },
  }
}

export type ProbeOptions = {
  readonly node?: string | undefined
  readonly entry?: string | undefined
  readonly env?: Record<string, string> | undefined
}

function unprobeable(cause: unknown, osRelease: string): GateAssessment {
  const detail = cause instanceof Error ? cause.message : String(cause)
  return {
    verdict: "refuse",
    tier: "",
    reason:
      `The MXC capability probe could not run: ${detail}. Refusing to enable the sandbox rather than run it ` +
      `unenforced (Windows build ${osRelease}); see ${ENFORCEMENT_FLOOR_DOC}. ` +
      `No administrator rights are requested or required.`,
    diagnostics: [],
    source: "unprobeable",
  }
}

// Drives the sidecar through its only read-only discovery surface: handshake,
// platformSupport, shutdown. Nothing here launches a workload or touches host
// state, and the sidecar is always torn down before the assessment returns.
export async function probeMxcSupport(options: ProbeOptions = {}): Promise<GateAssessment> {
  const osRelease = os.release()
  try {
    const sidecar = await startSidecar({
      node: options.node ?? mxcRuntime(),
      ...(options.entry === undefined ? {} : { entry: options.entry }),
      env: options.env,
    })
    let raw: unknown
    try {
      await sidecar.handshake()
      raw = await sidecar.platformSupport()
    } finally {
      await sidecar.shutdown().catch(() => sidecar.stop())
    }
    return assessPlatformSupport(raw, osRelease)
  } catch (cause) {
    return unprobeable(cause, osRelease)
  }
}
