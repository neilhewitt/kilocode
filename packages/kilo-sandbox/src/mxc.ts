import { existsSync, readdirSync, statSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { Effect, PlatformError } from "effect"
import type { CidrPortRule, RunCommand, RunEgress } from "@kilocode/mxc-sidecar"
import { normalizeDestinations } from "./destination.ts"
import type { Backend, Launch, Support } from "./backend"
import type { PathRule, Profile } from "./profile"
import { pathRelaxations } from "./relaxation"

// The Windows sandbox backend. Kilo's sandbox Profile is translated into an MXC
// run request carried by the sidecar's launcher shim: prepare() rewrites the
// launch into `<node> <run-shim> <request>`, so every command still flows
// through the existing per-command seam (prepareCommand → spawner) and the
// confined execution happens inside the sidecar's processcontainer sandbox.
// Execution is transient — one sandbox per command (ADR 0001) — and every
// command is composed with the full strictest-default grant table (ADR 0002):
// workspaces and temp read-write; the user profile, toolchains, OS directories,
// and workspace ancestors read-only; credential stores and secret-named files
// denied; toolchain caches redirected under the temp grant; the GUI subsystem
// kept available with clipboard/injection denied so ordinary tooling starts.
// Egress (ADR 0003, ticket 16) is deny-all by default, allowlisted through the
// sidecar's loopback proxy, or relaxed by recorded raw CIDR/port rules.

declare const KILO_MXC_SHIM_PATH: string | undefined

const caseInsensitive = process.platform === "win32"

// Windows command-line quoting: an argument is quoted when it contains
// whitespace or quotes, with backslashes doubled before each quote and at the
// closing quote. The MXC engine re-parses the command line, so this must match
// the conventions the target executable expects.
export function quoteWindows(argument: string) {
  if (argument === "") return '""'
  if (!/[\s"]/.test(argument)) return argument
  let quoted = '"'
  let backslashes = 0
  for (const character of argument) {
    if (character === "\\") {
      backslashes += 1
      continue
    }
    if (character === '"') {
      quoted += "\\".repeat(backslashes * 2 + 1) + '"'
      backslashes = 0
      continue
    }
    quoted += "\\".repeat(backslashes) + character
    backslashes = 0
  }
  return quoted + "\\".repeat(backslashes * 2) + '"'
}

// Shell launches are composed the way the other backends do it, with Windows
// quoting because this backend is win32-only.
function commandLine(launch: Launch) {
  if (!launch.shell) return [launch.command, ...launch.args].map(quoteWindows).join(" ")
  const shell = typeof launch.shell === "string" ? launch.shell : "cmd.exe"
  const body = [launch.command, ...launch.args.map(quoteWindows)].join(" ")
  return `${shell} -c ${quoteWindows(body)}`
}

// Windows environment lookups are case-insensitive; the merged launch
// environment may carry any casing.
function envValue(environment: Launch["environment"], name: string) {
  const source = environment ?? {}
  if (!caseInsensitive) return source[name]
  for (const [key, value] of Object.entries(source)) {
    if (key.toLowerCase() === name.toLowerCase()) return value
  }
  return undefined
}

// Ancestor directories of a granted root, up to and including the drive root:
// tools that walk parents looking for configuration (git, editors) must not
// fail just because the workspace sits nested (spec: workspace ancestors are
// generated read-only automatically).
function ancestors(of: string) {
  const found: Array<string> = []
  let current = path.resolve(of)
  while (true) {
    const parent = path.dirname(current)
    if (parent === current) return found
    found.push(parent)
    current = parent
  }
}

function sameOrUnder(candidate: string, root: string) {
  const left = path.resolve(candidate)
  const right = path.resolve(root)
  if (caseInsensitive) {
    return left.toLowerCase() === right.toLowerCase() || left.toLowerCase().startsWith(`${right.toLowerCase()}\\`)
  }
  return left === right || left.startsWith(`${right}\\`)
}

// The strictest-default readonly half of the grant table: the user profile,
// OS directories, the system drive root, and the toolchain directories named
// on PATH (mirroring the MXC SDK's host-discovery policy helpers, composed here
// so the translated request stays pure and testable at the backend seam).
// Entries at or under a read-write grant are dropped — a workspace is never
// carved read-only by its own PATH.
function readonlyDefaults(environment: Launch["environment"], readwrite: ReadonlyArray<string>) {
  if (process.platform !== "win32") return []
  const systemDrive = envValue(environment, "SystemDrive")
  const roots = [
    envValue(environment, "USERPROFILE"),
    envValue(environment, "SystemRoot"),
    envValue(environment, "ProgramFiles"),
    envValue(environment, "ProgramFiles(x86)"),
    envValue(environment, "ProgramData"),
    systemDrive === undefined ? undefined : `${systemDrive}\\`,
  ].filter((value): value is string => typeof value === "string")
  const pathValue = envValue(environment, "PATH") ?? ""
  const toolchains = pathValue
    .split(";")
    .filter((entry) => entry.trim() !== "" && existsSync(entry.trim()) && statSync(entry.trim()).isDirectory())
  return [...roots, ...toolchains].filter((entry) => !readwrite.some((grant) => sameOrUnder(entry, grant)))
}

function exists(rule: PathRule) {
  if (!existsSync(rule.path)) return false
  const entry = statSync(rule.path)
  if (rule.kind === "literal") return entry.isFile()
  return entry.isDirectory()
}

function distinct(paths: ReadonlyArray<string>) {
  const seen = new Set<string>()
  const keep: Array<string> = []
  for (const entry of paths) {
    if (entry === "" || seen.has(entry)) continue
    seen.add(entry)
    keep.push(entry)
  }
  return keep
}

function list(dir: string) {
  try {
    return readdirSync(dir, { withFileTypes: true })
  } catch {
    return []
  }
}

// Finds deny-named FILES under the writable roots so they can be denied
// outright (the spec maps denyNames onto denied paths for secret-named files).
// Directories are never blanket-denied by name: `.git` and friends stay under
// their parent grant so VCS metadata keeps working (git must operate under the
// default table); credential-store directories are denied explicitly instead.
// The scan is bounded by host readability: a directory the host-side scan
// cannot enumerate is skipped, so a deny-named file hidden inside it would not
// be denied — unlike the Bubblewrap backend, which fail-closes by re-binding
// such a directory read-only. Only reachable through ACL anomalies inside an
// already-writable workspace; recorded as a known caveat of the win32 mapping.
function scan(root: string, names: ReadonlySet<string>, found: Set<string>) {
  const pending = [root]
  while (pending.length > 0) {
    const dir = pending.pop()
    if (!dir) continue
    for (const entry of list(dir)) {
      const target = path.join(dir, entry.name)
      const name = caseInsensitive ? entry.name.toLowerCase() : entry.name
      const match = caseInsensitive ? [...names].some((n) => n.toLowerCase() === name) : names.has(entry.name)
      if (match && entry.isFile()) found.add(target)
      if (entry.isDirectory()) pending.push(target)
    }
  }
}

function deniedNames(profile: Profile, allow: ReadonlyArray<PathRule>) {
  if (profile.filesystem.denyNames.length === 0) return []
  const names = new Set(profile.filesystem.denyNames)
  const found = new Set<string>()
  for (const rule of allow) {
    if (rule.kind === "subtree") scan(rule.path, names, found)
  }
  return [...found].sort((a, b) => a.length - b.length)
}

// The proxy environment names are stripped from every confined environment:
// MXC sets the proxy variables itself when a run is pinned to the sidecar's
// loopback proxy, and a host-side proxy a container cannot reach would only
// turn allowed traffic into failures.
const proxyVariables = new Set([
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "all_proxy",
  "no_proxy",
])

// Credential stores are denied outright — read and write — even though the
// profile around them is merely read-only: sandboxed commands must not be able
// to read the user's keys (spec user story 11). Denied unconditionally, not
// only when the directory exists, so a store created after the table was
// composed is still covered on the next command.
const credentialStores = [".ssh", ".gnupg", ".aws", ".azure", ".kube"]

function deniedCredentials(environment: Launch["environment"]) {
  if (process.platform !== "win32") return []
  const home = envValue(environment, "USERPROFILE")
  if (home === undefined) return []
  return credentialStores.map((store) => path.join(home, store))
}

function safeEnvironment(environment: Launch["environment"]) {
  const source = environment ?? {}
  const safe: Record<string, string> = {}
  for (const [key, value] of Object.entries(source)) {
    if (value !== undefined && !key.startsWith("KILO_MXC_") && !proxyVariables.has(key)) safe[key] = value
  }
  return safe
}

// Egress posture (ADR 0003): relaxations are explicit and recorded, and MXC
// rejects direct rules alongside a proxy, so a profile carrying raw CIDR/port
// rules runs on those rules alone; otherwise proxy mode rides the sidecar's
// loopback proxy with the normalised hostname allowlist (an empty list is a
// deliberate deny-all), deny stays Model 3, and allow is unrestricted.
function egressOf(network: Profile["network"]): RunEgress {
  const relaxations: ReadonlyArray<CidrPortRule> = network.allowedCidrs ?? []
  if (relaxations.length > 0) return { default: "cidr", allow: relaxations }
  if (network.mode === "allow") return { default: "allow" }
  if (network.mode === "proxy") return { default: "proxy", allowedHosts: normalizeDestinations(network.allowedHosts) }
  return { default: "deny" }
}

// The shipped cache-redirection default list: toolchains that cache into the
// read-only user profile are pointed at a stable per-tool directory under the
// temp grant instead (ADR 0002 — stable across sessions, revoked by deleting
// the directory, user-extensible via the profile's environment set, which the
// backend merges in before translation and which therefore always wins over
// these defaults).
const cacheRedirections: ReadonlyArray<{ key: string; tool: string }> = [
  { key: "npm_config_cache", tool: "npm" },
  { key: "NUGET_PACKAGES", tool: "nuget" },
  { key: "PIP_CACHE_DIR", tool: "pip" },
  { key: "CARGO_HOME", tool: "cargo" },
]

function redirectCaches(environment: Record<string, string>, temporary: string | undefined) {
  if (temporary === undefined) return environment
  const redirected = { ...environment }
  for (const { key, tool } of cacheRedirections) {
    const existing = Object.keys(redirected).find((name) =>
      caseInsensitive ? name.toLowerCase() === key.toLowerCase() : name === key,
    )
    if (existing === undefined) redirected[key] = path.join(temporary, "kilo", "sandbox-cache", tool)
  }
  return redirected
}

// The strictest-default UI posture: the GUI subsystem must stay available
// because ordinary development tooling imports USER32.dll (node, git, both
// PowerShells, even where.exe), whose DLL initialisation dies with the
// 0xC0000142 STATUS_DLL_INIT_FAILED under DisallowWin32kSystemCalls — the
// motivating failure of the terminal spike. Everything the kill switch was
// protecting against — clipboard reads and writes, input injection, desktop
// switching, system setting changes, IME — remains denied by the MXC UI
// policy's default-deny fields whenever the subsystem is enabled.
function uiDefaults() {
  return { disable: false }
}

// Seam 1: the pure Profile → MXC request translation.
export function translate(profile: Profile, launch: Launch): RunCommand {
  const relaxations = pathRelaxations(profile.relaxations)
  const relaxedWrite = relaxations.filter((entry) => entry.access === "write").map((entry) => entry.path)
  const relaxedRead = relaxations.filter((entry) => entry.access === "read").map((entry) => entry.path)
  // A write relaxation is a read-write grant: it joins the allow list before
  // composition so ancestor generation and the readonly defaults treat it as
  // the workspace grant it is.
  const allow = distinct(
    [...profile.filesystem.allowWrite, ...relaxedWrite.map((path) => ({ path, kind: "subtree" as const }))]
      .filter(exists)
      .map((rule) => rule.path)
      .sort((a, b) => a.length - b.length),
  )
  const temporary = profile.filesystem.temporaryDirectory
  const readwrite = temporary && existsSync(temporary) && !allow.includes(temporary) ? [...allow, temporary] : allow
  const readonlyBase = distinct([
    ...profile.filesystem.denyWrite.filter(exists).map((rule) => rule.path),
    ...readwrite
      .flatMap((grant) => ancestors(grant))
      .filter((entry) => !readwrite.some((grant) => sameOrUnder(entry, grant))),
    ...readonlyDefaults(launch.environment, readwrite),
  ])
  const readonly = distinct([
    ...readonlyBase,
    // A read relaxation on a path no grant covers composes its own readonly
    // grant so the relaxed read actually reads.
    ...relaxedRead.filter(
      (entry) =>
        !readwrite.some((grant) => sameOrUnder(entry, grant)) &&
        !readonlyBase.some((rule) => sameOrUnder(entry, rule)),
    ),
  ])
  // A read relaxation un-denies exactly the denials it covers — a credential
  // store or a deny-named file the grant table had blocked — while every other
  // denial stands. Nothing else changes: a read relaxation grants read, never
  // write, and the profile around a relaxed store stays read-only.
  const denied = distinct([...deniedNames(profile, [...profile.filesystem.allowWrite, ...relaxedWrite.map((path) => ({ path, kind: "subtree" as const }))].filter(exists)), ...deniedCredentials(launch.environment)]).filter(
    (entry) => !relaxedRead.some((read) => sameOrUnder(entry, read)),
  )
  return {
    command: commandLine(launch),
    ...(launch.cwd === undefined ? { workingDirectory: readwrite[0] } : { workingDirectory: launch.cwd }),
    filesystem: {
      readwritePaths: readwrite,
      readonlyPaths: readonly,
      deniedPaths: denied,
    },
    network: { egress: egressOf(profile.network) },
    ui: uiDefaults(),
    environment: redirectCaches(safeEnvironment(launch.environment), temporary !== undefined && existsSync(temporary) ? temporary : undefined),
    ...(profile.audit === undefined
      ? {}
      : {
          audit:
            profile.audit.denialsPath === undefined || profile.audit.denialsPath === ""
              ? {}
              : { denialsPath: profile.audit.denialsPath },
        }),
  }
}

export function supportFor(platform: string, network?: Profile["network"]): Support {
  if (platform !== "win32") return { available: false, reason: "The MXC sandbox backend requires Windows" }
  return { available: true }
}

function support(network?: Profile["network"]): Support {
  return supportFor(process.platform, network)
}

function shim() {
  if (typeof KILO_MXC_SHIM_PATH !== "undefined") {
    return path.resolve(path.dirname(process.execPath), KILO_MXC_SHIM_PATH)
  }
  return fileURLToPath(import.meta.resolve("@kilocode/mxc-sidecar/run-shim"))
}

// The bundled Node runtime that hosts the sidecar (ADR 0005). Shared by the
// run shim and the read-only capability probe so both launch the same unit.
export function mxcRuntime() {
  return process.env.KILO_MXC_NODE ?? process.execPath
}

function runtime() {
  return mxcRuntime()
}

function setup(cause: unknown, launch: Launch) {
  return PlatformError.systemError({
    _tag: "PermissionDenied",
    module: "Sandbox",
    method: "prepareCommand",
    pathOrDescriptor: launch.command,
    description: cause instanceof Error ? cause.message : "Could not construct the Windows sandbox",
    cause,
  })
}

export const mxc: Backend = {
  support,
  prepare: (profile, launch) =>
    Effect.try({
      try: () => ({
        ...launch,
        command: runtime(),
        args: [shim(), JSON.stringify(translate(profile, launch))],
        shell: false,
      }),
      catch: (cause) => setup(cause, launch),
    }),
}
