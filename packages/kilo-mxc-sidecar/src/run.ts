// The per-command execution contract carried over the control channel. The
// backend translates a sandbox Profile into a RunCommand before launch; the
// sidecar executes it through the MXC runtime and answers with the captured
// RunResult. Everything a confined command may do is named here — there is no
// ambient fallback.
//
// Egress is one of four postures (ADR 0003):
// - `deny`: Model 3, nothing flows.
// - `allow`: no egress restriction requested by the profile.
// - `proxy`: Model 2 — the sidecar hosts a loopback HTTP/S proxy enforcing the
//   hostname allowlist, and MXC pins the container's egress to that proxy.
// - `cidr`: Model 1 — an explicit, recorded raw CIDR/port relaxation for
//   non-HTTP egress; MXC rejects direct rules alongside a proxy, so a cidr run
//   is governed solely by its recorded rules.

export type CidrPortRule = {
  readonly to: ReadonlyArray<string>
  readonly ports?: ReadonlyArray<CidrPortSelector> | undefined
}

export type CidrPortSelector = {
  readonly protocol: "tcp" | "udp" | "icmp" | "any"
  readonly port?: number | undefined
  readonly endPort?: number | undefined
}

export type RunEgress =
  | { readonly default: "allow" }
  | { readonly default: "deny" }
  | { readonly default: "proxy"; readonly allowedHosts: ReadonlyArray<string> }
  | { readonly default: "cidr"; readonly allow: ReadonlyArray<CidrPortRule> }

// The UI posture of the run. `disable` is the MXC kill switch for the GUI
// subsystem; it must stay false for ordinary development tooling (node, git,
// PowerShell all import USER32.dll, whose DLL initialisation dies with
// 0xC0000142 under DisallowWin32kSystemCalls). Everything else — clipboard,
// input injection, desktop control, system settings, IME — remains denied by
// the MXC UI policy's default-deny fields whenever the subsystem is enabled.
export type RunUi = {
  readonly disable: boolean
}

// The audit request on a run: ask the MXC engine to allow-and-capture denials
// (SDK captureDenials allow-mode) instead of enforcing them. `denialsPath`
// names the destination file for the engine's denial report. The engine path
// is the authoring surface behind a host switch; nothing sets it without the
// caller explicitly opting in (ADR 0002: audit mode is signalled, never a
// silent half-enforcement).
export type RunAudit = {
  readonly denialsPath?: string | undefined
}

// The degradation signal a streamed (pipes-fallback) run always carries: the
// sidecar cannot import the sandbox package's wording (dependency direction —
// the sandbox packages depends on this one), so the two agree on one message.
// The shim prints warnings as `[kilo-mxc] …` lines, so this is what the user
// of a pipes-fallback terminal sees.
export const PIPES_FALLBACK_WARNING =
  "pipes fallback: no TTY — the sandbox engine does not support PTY spawning (tracked upstream, ADR 0004); input and resize are unavailable — grant a terminal relaxation for a real terminal"

export type RunCommand = {
  readonly command: string
  readonly workingDirectory?: string | undefined
  readonly filesystem: {
    readonly readwritePaths: ReadonlyArray<string>
    readonly readonlyPaths: ReadonlyArray<string>
    readonly deniedPaths: ReadonlyArray<string>
  }
  readonly network: {
    readonly egress: RunEgress
  }
  readonly ui: RunUi
  readonly environment: Readonly<Record<string, string>>
  readonly audit?: RunAudit | undefined
  // The engine-side per-request deadline in whole milliseconds (ADR 0004:
  // "existing timeout semantics map onto `timeoutMs`"). Callers that know a
  // command's remaining timeout budget pass it so the MXC engine enforces the
  // same deadline; a hung confined command then settles with `timedOut: true`
  // instead of outliving every other kill path. Absent means no engine deadline.
  readonly timeoutMs?: number | undefined
  // The pipes fallback (ADR 0004): the MXC engine refuses PTY spawning for the
  // processcontainer backend (typed `unsupported_containment` from
  // spawnWithPty; revisit when upstream ships PTY spawning there), so every
  // confined command runs over pipes. `stream` asks the sidecar to forward
  // stdout/stderr chunks over the control channel as they arrive instead of
  // only settling the captured RunResult at the end — the streamed surface
  // needed by the pipes-backed session terminal. Input is not carried in
  // either mode: confined pipes are one-way.
  readonly stream?: boolean | undefined
}

// The engine's denial-capture summary for a completed run. Present only when
// the engine attached a captureDenials report.
export type RunAuditResult = {
  readonly totalDenials: number
  readonly reportPath?: string | undefined
}

export type RunResult = {
  readonly exitCode: number
  readonly stdout: string
  readonly stderr: string
  readonly timedOut: boolean
  readonly warnings: ReadonlyArray<string>
  readonly audit?: RunAuditResult | undefined
}

// A live execution inside the sidecar: `wait` settles with the captured result,
// `kill` asks the MXC engine for a job-object tree kill. The control server
// calls kill when the owning connection goes away mid-run.
export type RunHandle = {
  readonly wait: () => Promise<RunResult>
  readonly kill: () => void
}

function isStringArray(value: unknown): value is ReadonlyArray<string> {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string")
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null
}

const protocols = new Set(["tcp", "udp", "icmp", "any"])

function isPortSelector(value: unknown): value is CidrPortSelector {
  if (!isRecord(value)) return false
  if (typeof value["protocol"] !== "string" || !protocols.has(value["protocol"])) return false
  for (const key of ["port", "endPort"]) {
    const entry = value[key]
    if (entry !== undefined && (typeof entry !== "number" || !Number.isInteger(entry))) return false
  }
  return true
}

function isCidrRule(value: unknown): value is CidrPortRule {
  if (!isRecord(value)) return false
  if (!isStringArray(value["to"]) || value["to"].length === 0) return false
  const ports = value["ports"]
  if (ports === undefined) return true
  if (!Array.isArray(ports) || ports.length === 0) return false
  return ports.every(isPortSelector)
}

function isEgress(value: unknown): value is RunEgress {
  if (!isRecord(value)) return false
  switch (value["default"]) {
    case "allow":
    case "deny":
      return true
    case "proxy":
      return isStringArray(value["allowedHosts"])
    case "cidr":
      return Array.isArray(value["allow"]) && value["allow"].length > 0 && value["allow"].every(isCidrRule)
    default:
      return false
  }
}

function isAudit(value: unknown): value is RunAudit {
  if (!isRecord(value)) return false
  for (const key of Object.keys(value)) {
    if (key !== "denialsPath") return false
  }
  const denialsPath = value["denialsPath"]
  return denialsPath === undefined || typeof denialsPath === "string"
}

export function isRunCommand(value: unknown): value is RunCommand {
  if (!isRecord(value)) return false
  if (typeof value["command"] !== "string" || value["command"] === "") return false
  if (value["workingDirectory"] !== undefined && typeof value["workingDirectory"] !== "string") return false
  const filesystem = value["filesystem"]
  if (!isRecord(filesystem)) return false
  if (!isStringArray(filesystem["readwritePaths"])) return false
  if (!isStringArray(filesystem["readonlyPaths"])) return false
  if (!isStringArray(filesystem["deniedPaths"])) return false
  const network = value["network"]
  if (!isRecord(network)) return false
  if (!isEgress(network["egress"])) return false
  const ui = value["ui"]
  if (!isRecord(ui) || typeof ui["disable"] !== "boolean") return false
  const environment = value["environment"]
  if (!isRecord(environment) || Array.isArray(environment)) return false
  const audit = value["audit"]
  if (audit !== undefined && !isAudit(audit)) return false
  if (value["timeoutMs"] !== undefined) {
    const timeoutMs = value["timeoutMs"]
    if (typeof timeoutMs !== "number" || !Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) return false
  }
  if (value["stream"] !== undefined && typeof value["stream"] !== "boolean") return false
  return Object.values(environment).every((entry) => typeof entry === "string")
}
