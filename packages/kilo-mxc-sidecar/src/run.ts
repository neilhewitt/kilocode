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
}

export type RunResult = {
  readonly exitCode: number
  readonly stdout: string
  readonly stderr: string
  readonly timedOut: boolean
  readonly warnings: ReadonlyArray<string>
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
  return Object.values(environment).every((entry) => typeof entry === "string")
}
