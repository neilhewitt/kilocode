import type { CidrPortRule } from "@kilocode/mxc-sidecar"

export type PathKind = "literal" | "subtree"

export interface PathRule {
  readonly path: string
  readonly kind: PathKind
}

export interface FilesystemProfile {
  readonly allowWrite: ReadonlyArray<PathRule>
  readonly denyWrite: ReadonlyArray<PathRule>
  readonly denyNames: ReadonlyArray<string>
  readonly temporaryDirectory?: string | undefined
}

export type RelaxationAccess = "read" | "write"

// A deliberate widening of the grant table (ADR 0002). Path relaxations widen
// the filesystem posture; the terminal kind is the recorded-but-uncomposed
// relaxation the PTY surface grants — it never changes a filesystem table.
export interface PathRelaxation {
  readonly kind: "path"
  readonly access: RelaxationAccess
  readonly path: string
}

export type Relaxation = PathRelaxation | { readonly kind: "terminal" }

// The audit posture of a profile: ask the MXC engine to allow-and-capture
// denials (captureDenials allow-mode) instead of enforcing them. The engine
// path is the authoring surface; `denialsPath` names the destination for the
// engine's denial report.
export interface AuditPosture {
  readonly denialsPath?: string | undefined
}

export interface NetworkProfile {
  readonly mode: "allow" | "deny" | "proxy"
  readonly allowedHosts: ReadonlyArray<string>
  // Explicit, recorded raw CIDR/port relaxations for non-HTTP egress (ADR
  // 0003). Present only when deliberately configured; MXC rejects direct
  // rules alongside a proxy, so a run with relaxations is governed by them
  // alone.
  readonly allowedCidrs?: ReadonlyArray<CidrPortRule> | undefined
}

export interface EnvironmentProfile {
  readonly deny: ReadonlyArray<string>
  readonly set: Readonly<Record<string, string>>
}

export interface Profile {
  readonly filesystem: FilesystemProfile
  readonly network: NetworkProfile
  readonly environment: EnvironmentProfile
  readonly relaxations?: ReadonlyArray<Relaxation> | undefined
  readonly audit?: AuditPosture | undefined
}
