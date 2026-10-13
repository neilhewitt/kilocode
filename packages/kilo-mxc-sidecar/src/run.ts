// The per-command execution contract carried over the control channel. The
// backend translates a sandbox Profile into a RunCommand before launch; the
// sidecar executes it through the MXC runtime and answers with the captured
// RunResult. Everything a confined command may do is named here — there is no
// ambient fallback.

export type RunEgress = {
  readonly default: "allow" | "deny"
}

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

function isEgress(value: unknown): value is RunEgress {
  if (!isRecord(value)) return false
  const egress = value["default"]
  return egress === "allow" || egress === "deny"
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
