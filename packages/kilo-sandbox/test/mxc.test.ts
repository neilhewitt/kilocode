import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { Effect } from "effect"
import type { Launch } from "../src/backend"
import { confine, select } from "../src/backend"
import { mxc, quoteWindows, supportFor, translate } from "../src/mxc"
import { bubblewrap } from "../src/bubblewrap"
import { seatbelt } from "../src/seatbelt"
import type { Profile } from "../src/profile"

// Seam 1 — sandbox backend policy translation: feed a Profile, assert the
// translated MXC request. Pure translation runs on any host; only the live
// enforcement tests at the bottom are probe-gated.

function profile(root: string, overrides: Partial<Profile> = {}): Profile {
  return {
    filesystem: {
      allowWrite: [{ path: root, kind: "subtree" }],
      denyWrite: [],
      denyNames: [".git"],
      temporaryDirectory: path.join(root, "tmp"),
      ...overrides.filesystem,
    },
    network: { mode: "deny", allowedHosts: [], ...overrides.network },
    environment: { deny: ["SECRET"], set: { KILO_SET: "1" } , ...overrides.environment },
  }
}

function launch(root: string, overrides: Partial<Launch> = {}): Launch {
  return {
    command: "cmd",
    args: ["/c", "echo hello"],
    cwd: root,
    environment: { PATH: "C:\\Windows\\System32", SECRET: "s", KILO_MXC_CONTROL_TOKEN: "t" },
    ...overrides,
  }
}

describe("mxc policy translation", () => {
  test("composes the grant table from the profile", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-translate-"))
    try {
      const denied = path.join(root, "deny-me")
      mkdirSync(denied)
      const input = profile(root, { filesystem: { allowWrite: [
        { path: root, kind: "subtree" },
        { path: path.join(root, "missing"), kind: "subtree" },
      ], denyWrite: [{ path: denied, kind: "subtree" }], denyNames: [".git"], temporaryDirectory: path.join(root, "tmp") } })
      mkdirSync(path.join(root, "tmp"))
      const request = translate(input, launch(root))
      assert.deepEqual(request.filesystem.readwritePaths, [root, path.join(root, "tmp")])
      assert.ok(request.filesystem.readonlyPaths.includes(denied), "denyWrite must map onto readonly grants")
      assert.ok(!request.filesystem.readwritePaths.includes(path.join(root, "missing")), "non-existent grants are dropped")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("maps denyNames onto denied paths found inside writable grants", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-deny-names-"))
    try {
      mkdirSync(path.join(root, ".git"))
      writeFileSync(path.join(root, ".env"), "SECRET=1")
      mkdirSync(path.join(root, "sub"))
      writeFileSync(path.join(root, "sub", ".gitconfig"), "x")
      const request = translate(profile(root, { filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [".git", ".env"], temporaryDirectory: undefined } }), launch(root))
      assert.ok(request.filesystem.deniedPaths.includes(path.join(root, ".git")), "deny-named directories are denied")
      assert.ok(request.filesystem.deniedPaths.includes(path.join(root, ".env")), "deny-named files are denied")
      assert.ok(!request.filesystem.deniedPaths.some((entry) => entry.endsWith(".gitconfig")), "non-matching names are not denied")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("denies egress by default and maps allow mode", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-egress-"))
    try {
      const denied = translate(profile(root), launch(root))
      assert.deepEqual(denied.network, { egress: { default: "deny" } })
      const allowed = translate(profile(root, { network: { mode: "allow", allowedHosts: [] } }), launch(root))
      assert.deepEqual(allowed.network, { egress: { default: "allow" } })
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("composes the command line with Windows quoting", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-command-"))
    try {
      const plain = translate(profile(root), launch(root, { command: "cmd", args: ["/c", "echo spaced arg"] }))
      assert.equal(plain.command, 'cmd /c "echo spaced arg"')
      const quoted = translate(profile(root), launch(root, { command: "node", args: ["-e", "console.log(\"hi\")"] }))
      assert.equal(quoted.command, 'node -e "console.log(\\"hi\\")"')
      const shelled = translate(profile(root), launch(root, { command: "echo hi", args: [], shell: "/bin/zsh" }))
      assert.equal(shelled.command, '/bin/zsh -c "echo hi"')
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("carries the working directory and a safe environment", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-env-"))
    try {
      const request = translate(profile(root), launch(root, { environment: { PATH: "p", SECRET: "s", KILO_MXC_SDK_ENTRY: "x", UNDEF: undefined } }))
      assert.equal(request.workingDirectory, root)
      assert.equal(request.environment.PATH, "p")
      assert.equal(request.environment.SECRET, "s")
      assert.equal(request.environment.KILO_MXC_SDK_ENTRY, undefined)
      assert.equal(request.environment.UNDEF, undefined)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("quotes Windows arguments per command-line conventions", () => {
    assert.equal(quoteWindows("plain"), "plain")
    assert.equal(quoteWindows("spaced arg"), '"spaced arg"')
    assert.equal(quoteWindows('say "hi"'), '"say \\"hi\\""')
    const backslash = String.fromCharCode(92)
    assert.equal(quoteWindows(`end${backslash}"`), `"end${backslash.repeat(3)}""`)
    assert.equal(quoteWindows(""), '""')
  })
})

describe("mxc backend support and selection", () => {
  test("is available on win32 except for proxy egress, which fails closed", () => {
    assert.deepEqual(supportFor("win32", { mode: "deny", allowedHosts: [] }), { available: true })
    assert.deepEqual(supportFor("win32", { mode: "allow", allowedHosts: [] }), { available: true })
    assert.deepEqual(supportFor("win32", undefined), { available: true })
    const proxy = supportFor("win32", { mode: "proxy", allowedHosts: ["example.com"] })
    assert.equal(proxy.available, false)
    assert.match(proxy.reason ?? "", /loopback proxy/)
  })

  test("requires Windows", () => {
    const support = supportFor("linux", { mode: "deny", allowedHosts: [] })
    assert.equal(support.available, false)
    assert.match(support.reason ?? "", /Windows/)
  })

  test("selects the mxc backend on win32 and leaves other platforms untouched", () => {
    assert.equal(select("win32"), mxc)
    assert.equal(select("darwin"), seatbelt)
    assert.equal(select("linux"), bubblewrap)
  })
})

describe("mxc backend through the per-command seam", () => {
  const runtimeFixture = path.resolve(
    fileURLToPath(new URL(".", import.meta.url)),
    "../../kilo-mxc-sidecar/test/fixtures/scripted-runtime.mjs",
  )

  test("rewrites the launch into the shim and round-trips through a scripted sidecar", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-e2e-"))
    const log = path.join(root, "events.jsonl")
    try {
      mkdirSync(path.join(root, "tmp"))
      const input: Profile = {
        filesystem: {
          allowWrite: [{ path: root, kind: "subtree" }],
          denyWrite: [],
          denyNames: [],
          temporaryDirectory: path.join(root, "tmp"),
        },
        network: { mode: "deny", allowedHosts: [] },
        environment: { deny: ["SECRET"], set: { KILO_SET: "1" } },
      }
      const original: Launch = {
        command: "node",
        args: ["-e", "console.log('confined')"],
        cwd: root,
        environment: { PATH: process.env.PATH ?? "", SECRET: "leak", HTTPS_PROXY: "http://127.0.0.1:9000", no_proxy: "*" },
      }
      const prepared = await Effect.runPromise(Effect.scoped(confine(input, original)))
      assert.equal(prepared.command, process.execPath)
      assert.equal(prepared.shell, false)

      const canned = { exitCode: 42, stdout: "scripted stdout\n", stderr: "", timedOut: false, warnings: [] }
      const child = spawn(prepared.command, prepared.args, {
        env: {
          ...process.env,
          KILO_MXC_RUNTIME_MODULE: runtimeFixture,
          KILO_MXC_SCRIPT_RESULT: JSON.stringify(canned),
          KILO_MXC_SCRIPT_EVENTS: log,
        },
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      })
      let stdout = ""
      let stderr = ""
      child.stdout.setEncoding("utf8")
      child.stdout.on("data", (chunk: string) => {
        stdout += chunk
      })
      child.stderr.setEncoding("utf8")
      child.stderr.on("data", (chunk: string) => {
        stderr += chunk
      })
      const done = new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
        child.on("close", (code) => resolve({ code, stdout, stderr }))
      })
      const result = await done
      assert.equal(result.code, 42)
      assert.equal(result.stdout, "scripted stdout\n")

      const recorded = existsSync(log)
        ? (readFileSync(log, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line)) as Array<Record<string, unknown>>)
        : []
      const runs = recorded.filter((entry) => entry.type === "run")
      assert.equal(runs.length, 1, "exactly one confined run must reach the sidecar")
      const request = runs[0].command as {
        command: string
        workingDirectory?: string
        filesystem: { readwritePaths: string[] }
        network: { egress: { default: string } }
        environment: Record<string, string>
      }
      assert.deepEqual(request.filesystem.readwritePaths, [root, path.join(root, "tmp")])
      assert.deepEqual(request.network, { egress: { default: "deny" } })
      assert.equal(request.workingDirectory, root)
      assert.equal(request.command, "node -e console.log('confined')")
      assert.equal(request.environment.KILO_SET, "1")
      assert.equal(request.environment.SECRET, undefined)
      assert.equal(request.environment.HTTPS_PROXY, undefined)
      assert.equal(request.environment.no_proxy, undefined)
      assert.equal(request.environment.KILO_MXC_RUNTIME_MODULE, undefined)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})

// Seam 3 — end-to-end enforcement, probe-gated: only on win32 hosts where the
// real MXC SDK is present and the probe returns the base-container tier.
// Everywhere else these skip with a reason; confinement behaviour itself is
// covered above through the scripted sidecar.
async function liveSdk(t: import("node:test").TestContext) {
  if (process.platform !== "win32") {
    return t.skip(`live enforcement requires Windows; this host is ${process.platform}`)
  }
  const entry = process.env.KILO_MXC_SDK_ENTRY ?? `${os.tmpdir()}/kilo/mxc-smoke/node_modules/@microsoft/mxc-sdk/dist/v1/index.js`
  if (!existsSync(entry)) return t.skip(`MXC SDK not installed at ${entry}`)
  const versions = process.versions as Record<string, string | undefined>
  if (versions.bun) return t.skip("the MXC SDK cannot run under Bun")
  const sdk = (await import(`file://${entry.replaceAll("\\", "/")}`)) as {
    getPlatformSupport: () => Promise<{ isSupported: boolean; isolationTier?: string }>
  }
  const support = await sdk.getPlatformSupport()
  if (!support.isSupported || support.isolationTier !== "base-container") {
    return t.skip(`host enforcement tier is ${String(support.isolationTier)}, not base-container`)
  }
  return entry
}

function liveProfile(root: string): Profile {
  return {
    filesystem: {
      allowWrite: [{ path: root, kind: "subtree" }],
      denyWrite: [],
      denyNames: [],
    },
    network: { mode: "deny", allowedHosts: [] },
    environment: { deny: [], set: {} },
  }
}

async function runConfined(profile: Profile, command: string, args: Array<string>, env: Record<string, string>) {
  const prepared = await Effect.runPromise(
    Effect.scoped(confine(profile, { command, args, environment: { ...process.env } })),
  )
  const child = spawn(prepared.command, prepared.args, { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"], windowsHide: true })
  let stdout = ""
  let stderr = ""
  child.stdout.setEncoding("utf8")
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk
  })
  child.stderr.setEncoding("utf8")
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk
  })
  const code = await new Promise<number | null>((resolve) => child.on("close", resolve))
  if (stderr.includes("kilo-mxc-shim:")) throw new Error(`confined launch failed: ${stderr}`)
  return { code, stdout, stderr }
}

describe("mxc live enforcement (probe-gated)", () => {
  test("round-trips stdout and the exit code from a confined command", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-live-rt-"))
    try {
      const result = await runConfined(liveProfile(root), "cmd", ["/c", "echo LIVE_OK & exit 42"], {
        KILO_MXC_SDK_ENTRY: entry,
      })
      assert.equal(result.code, 42)
      assert.match(result.stdout, /LIVE_OK/)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("allows writes inside the granted workspace", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-live-in-"))
    try {
      const inside = path.join(root, "inside.txt")
      const result = await runConfined(liveProfile(root), "cmd", ["/c", `echo INSIDE_OK > ${inside} & type ${inside}`], {
        KILO_MXC_SDK_ENTRY: entry,
      })
      assert.equal(result.code, 0)
      assert.match(result.stdout, /INSIDE_OK/)
      assert.ok(existsSync(inside), "the granted write must land on the host")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("denies writes outside granted paths with no host artefact", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-live-out-"))
    const outside = path.join(os.homedir(), "kilo-mxc-denied-probe.txt")
    try {
      const result = await runConfined(
        liveProfile(root),
        "cmd",
        ["/c", `(echo x) > ${outside} & if exist ${outside} (echo PROBE_WRITTEN) else (echo PROBE_DENIED)`],
        { KILO_MXC_SDK_ENTRY: entry },
      )
      assert.match(result.stderr, /Access is denied/, "the OS denial must surface on stderr")
      assert.match(result.stdout, /PROBE_DENIED/)
      assert.doesNotMatch(result.stdout, /PROBE_WRITTEN/)
      assert.equal(existsSync(outside), false, "no host artefact may remain")
    } finally {
      rmSync(outside, { force: true })
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("denies egress under the minimal policy", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-live-net-"))
    try {
      const result = await runConfined(liveProfile(root), "curl", ["--max-time", "15", "-s", "-S", "https://example.com/"], {
        KILO_MXC_SDK_ENTRY: entry,
      })
      assert.notEqual(result.code, 0, "egress must fail under the deny-all policy")
      assert.doesNotMatch(result.stdout, /Example Domain/, "no page content may come back")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})
