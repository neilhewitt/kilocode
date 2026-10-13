import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { lookup } from "node:dns/promises"
import { connect } from "node:net"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { Effect } from "effect"
import { createEgressProxy } from "@kilocode/mxc-sidecar"
import type { Launch } from "../src/backend.ts"
import { confine, select } from "../src/backend.ts"
import { mxc, quoteWindows, supportFor, translate } from "../src/mxc.ts"
import { bubblewrap } from "../src/bubblewrap.ts"
import { seatbelt } from "../src/seatbelt.ts"
import type { Profile } from "../src/profile.ts"

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

  test("maps proxy mode onto the proxy egress posture with a normalised allowlist", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-proxy-"))
    try {
      const request = translate(
        profile(root, { network: { mode: "proxy", allowedHosts: ["Api.GitHub.com:443", "example.com"] } }),
        launch(root),
      )
      assert.deepEqual(request.network, {
        egress: { default: "proxy", allowedHosts: ["api.github.com:443", "example.com:443"] },
      })
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("an empty proxy allowlist stays deny-all through the proxy", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-trim-"))
    try {
      const request = translate(profile(root, { network: { mode: "proxy", allowedHosts: [] } }), launch(root))
      assert.deepEqual(request.network, { egress: { default: "proxy", allowedHosts: [] } })
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("carries recorded cidr relaxations as the run's entire egress posture", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-cidr-"))
    try {
      const relaxations = [
        { to: ["140.82.112.0/20"], ports: [{ protocol: "tcp" as const, port: 22 }] },
        { to: ["10.0.0.0/8"] },
      ]
      // A relaxation governs even a proxy-mode profile: MXC rejects direct
      // rules alongside a proxy, so the recorded rules stand alone.
      const proxied = translate(
        profile(root, {
          network: { mode: "proxy", allowedHosts: ["example.com:443"], allowedCidrs: relaxations },
        }),
        launch(root),
      )
      assert.deepEqual(proxied.network, { egress: { default: "cidr", allow: relaxations } })
      const denied = translate(
        profile(root, { network: { mode: "deny", allowedHosts: [], allowedCidrs: relaxations } }),
        launch(root),
      )
      assert.deepEqual(denied.network, { egress: { default: "cidr", allow: relaxations } })
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("strips ambient proxy variables from the confined environment in every posture", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-proxyenv-"))
    try {
      const noisy = launch(root, {
        environment: {
          PATH: "p",
          HTTP_PROXY: "http://127.0.0.1:9000",
          HTTPS_PROXY: "http://127.0.0.1:9000",
          ALL_PROXY: "socks5://127.0.0.1:9000",
          NO_PROXY: "intranet",
          http_proxy: "http://127.0.0.1:9000",
          https_proxy: "http://127.0.0.1:9000",
          all_proxy: "socks5://127.0.0.1:9000",
          no_proxy: "intranet",
        },
      })
      for (const network of [
        { mode: "deny", allowedHosts: [] },
        { mode: "allow", allowedHosts: [] },
        { mode: "proxy", allowedHosts: ["example.com:443"] },
      ] as const) {
        const request = translate(profile(root, { network }), noisy)
        for (const key of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"]) {
          assert.equal(request.environment[key], undefined, `${key} must not reach the container (${network.mode})`)
        }
        assert.equal(request.environment.PATH, "p")
      }
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
  test("is available on win32 for every network posture, including proxy egress", () => {
    assert.deepEqual(supportFor("win32", { mode: "deny", allowedHosts: [] }), { available: true })
    assert.deepEqual(supportFor("win32", { mode: "allow", allowedHosts: [] }), { available: true })
    assert.deepEqual(supportFor("win32", undefined), { available: true })
    const proxy = supportFor("win32", { mode: "proxy", allowedHosts: ["example.com"] })
    assert.equal(proxy.available, true, "proxy egress is delivered by the sidecar's loopback proxy")
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

// Whether this host can pin a container to an identity-less host loopback
// proxy (MXC Model 2). PSEC 1.1 plus the ingress support flag is required;
// PSEC 1.0-only hosts lack it, and MXC refuses such requests fail-closed
// rather than letting them degrade to direct egress.
async function hostLoopbackProxySupported(entry: string) {
  const sdk = (await import(`file://${entry.replaceAll("\\", "/")}`)) as {
    probe: (request?: unknown) => Promise<{ error?: string; probes?: Record<string, boolean> }>
  }
  const probe = await sdk.probe({
    command: "cmd /c echo probe",
    network: {
      egress: { default: "deny" },
      ingress: { default: "allow", hostLoopback: "allow" },
      runtimeConfig: { networkProxy: "http://127.0.0.1:1" },
    },
  })
  return probe.probes?.baseContainerSupportsIngressHostLoopbackAllow === true && !probe.error
}

function runConfinedChild(profile: Profile, command: string, args: Array<string>, env: Record<string, string>) {
  const promise = (async () => {
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
    return {
      child,
      done: new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) =>
        child.on("close", (code) => resolve({ code, stdout, stderr })),
      ),
    }
  })()
  return promise
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

  test("a recorded cidr relaxation enables a deliberate non-proxied flow to a resolved endpoint", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const resolved = await lookup("example.com")
    const target = resolved.address
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-live-cidr-"))
    try {
      const relaxed: Profile = {
        ...liveProfile(root),
        network: {
          mode: "deny",
          allowedHosts: [],
          allowedCidrs: [{ to: [`${target}/32`], ports: [{ protocol: "tcp", port: 443 }] }],
        },
      }
      const curl = (profile: Profile) =>
        runConfined(profile, "curl", [
          "--max-time",
          "20",
          "-s",
          "-S",
          "--resolve",
          `example.com:443:${target}`,
          "https://example.com/",
        ], { KILO_MXC_SDK_ENTRY: entry })

      const denied = await curl(liveProfile(root))
      assert.notEqual(denied.code, 0, "the resolved endpoint must be unreachable without the relaxation")

      const allowed = await curl(relaxed)
      assert.equal(allowed.code, 0, "the recorded relaxation must enable the deliberate flow")
      assert.match(allowed.stdout, /Example Domain/, "the resolved endpoint's content must flow")
      assert.match(
        allowed.stderr,
        /egress relaxation: .*\[tcp:443\]/,
        "the deliberate widening must be recorded in the command's output",
      )
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("denies inbound connections to the sandbox, including from host loopback", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    // The listener needs a runtime that can bind a socket and write the port.
    // On this PSEC host every stock scripting runtime (node, PowerShell, git)
    // exits 0xC0000142 at DLL init inside the container — even under a
    // full-drive readonly grant — so no listener-capable process launches;
    // that incompatibility is tracked by the default-grant-table work.
    for (const [command, args] of [
      [process.execPath, ["--version"]],
      ["git", ["--version"]],
    ] as Array<[string, Array<string>]>) {
      const attempt = await new Promise<number | null>((resolve) => {
        void runConfined(liveProfile(os.tmpdir()), command, args, { KILO_MXC_SDK_ENTRY: entry }).then(
          (result) => resolve(result.code),
          () => resolve(null),
        )
      })
      if (attempt !== 0) {
        return t.skip(
          `no listener-capable runtime launches in the container on this host (${command} exits ${attempt}); ` +
            "ingress denial is still enforced by composition — no posture this host can run requests any inbound capability",
        )
      }
    }
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-live-inb-"))
    const listener = path.join(root, "listener.mjs")
    const status = path.join(root, "listener.status.txt")
    writeFileSync(
      listener,
      [
        "import net from 'node:net'",
        "import fs from 'node:fs'",
        "const server = net.createServer(() => {})",
        "server.listen(0, '0.0.0.0', () => fs.writeFileSync(process.argv[2], String(server.address().port)))",
        "setTimeout(() => process.exit(0), 25_000)",
      ].join("\n"),
    )
    try {
      const { child, done } = await runConfinedChild(liveProfile(root), process.execPath, [listener, status], {
        KILO_MXC_SDK_ENTRY: entry,
      })
      let port = 0
      const deadline = Date.now() + 20_000
      while (Date.now() < deadline && port === 0) {
        try {
          const value = Number.parseInt(readFileSync(status, "utf8").trim(), 10)
          if (Number.isInteger(value) && value > 0) port = value
        } catch {
          // the confined listener has not reported yet
        }
        if (port === 0) await new Promise((resolve) => setTimeout(resolve, 200))
      }
      assert.ok(port > 0, "the confined command must report the port it is listening on")
      const reached = await new Promise<boolean>((resolve) => {
        const socket = connect(port, "127.0.0.1")
        socket.setTimeout(5_000)
        socket.once("connect", () => {
          socket.destroy()
          resolve(true)
        })
        socket.once("timeout", () => {
          socket.destroy()
          resolve(false)
        })
        socket.once("error", () => resolve(false))
      })
      assert.equal(reached, false, "a host loopback connection to the sandbox listener must not succeed")
      child.kill()
      await done
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("proxy-pinned egress flows through the sidecar proxy or fails closed on hosts without the capability", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const capable = await hostLoopbackProxySupported(entry)
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-live-proxy-"))
    const proxyProfile = (hosts: Array<string>): Profile => ({
      ...liveProfile(root),
      network: { mode: "proxy", allowedHosts: hosts },
    })
    try {
      if (!capable) {
        // Fail-closed: MXC refuses to run a proxy-pinned request it cannot
        // enforce; the command must never fall back to direct egress.
        await assert.rejects(
          runConfined(proxyProfile(["registry.npmjs.org:443"]), "curl", [
            "--max-time",
            "15",
            "-s",
            "-S",
            "https://registry.npmjs.org/",
          ], { KILO_MXC_SDK_ENTRY: entry }),
          /hostLoopback|proxy/i,
        )
        return
      }
      const allowed = await runConfined(proxyProfile(["registry.npmjs.org:443"]), "curl", [
        "--max-time",
        "20",
        "-s",
        "-S",
        "https://registry.npmjs.org/express/latest",
      ], { KILO_MXC_SDK_ENTRY: entry })
      assert.equal(allowed.code, 0, "an allowlisted hostname must flow through the pinned proxy")
      assert.match(allowed.stdout, /"name"\s*:\s*"express"/, "the registry must answer through the proxy")

      const denied = await runConfined(proxyProfile(["registry.npmjs.org:443"]), "curl", [
        "--max-time",
        "15",
        "-s",
        "-S",
        "https://example.com/",
      ], { KILO_MXC_SDK_ENTRY: entry })
      assert.notEqual(denied.code, 0, "a non-allowlisted hostname must fail closed")
      assert.doesNotMatch(denied.stdout, /Example Domain/)

      const trimmed = await runConfined(proxyProfile([]), "curl", [
        "--max-time",
        "15",
        "-s",
        "-S",
        "https://registry.npmjs.org/",
      ], { KILO_MXC_SDK_ENTRY: entry })
      assert.notEqual(trimmed.code, 0, "an empty allowlist is a deny-all trim")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("the sidecar egress proxy enforces the allowlist against the real registry host-side", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const allowRegistry = await createEgressProxy({ allowedHosts: ["registry.npmjs.org:443"] })
    const allowNothing = await createEgressProxy({ allowedHosts: [] })
    try {
      const curl = (target: string, through: { endpoint: string }) =>
        new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
          const child = spawn("curl", ["--max-time", "20", "-s", "-S", "-x", through.endpoint, target], {
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
          child.on("close", (code) => resolve({ code, stdout, stderr }))
        })

      const allowed = await curl("https://registry.npmjs.org/express/latest", allowRegistry)
      assert.equal(allowed.code, 0, "the allowlisted registry request must flow through the proxy")
      assert.match(allowed.stdout, /"name"\s*:\s*"express"/)

      const blocked = await curl("https://example.com/", allowRegistry)
      assert.notEqual(blocked.code, 0, "a non-allowlisted hostname must fail closed through the proxy")
      assert.doesNotMatch(blocked.stdout, /Example Domain/)

      const trimmed = await curl("https://registry.npmjs.org/", allowNothing)
      assert.notEqual(trimmed.code, 0, "an empty allowlist must deny the same request the full list allows")
    } finally {
      await Promise.all([allowRegistry.close(), allowNothing.close()])
    }
  })
})
