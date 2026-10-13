import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { Effect } from "effect"
import { startSidecar } from "@kilocode/mxc-sidecar"
import { confine } from "../src/backend.ts"
import { translate } from "../src/mxc.ts"
import { assessPlatformSupport } from "../src/probe.ts"
import type { Profile, Relaxation } from "../src/profile.ts"

// Seam 3 — the enforcement suite (ticket 19). Where the per-package suites
// anchor their own seams (mxc.test.ts the sandbox backend, sidecar live.test.ts
// the control channel, opencode bun suites the session layer), this suite
// assembles the allow/deny matrix end to end: real commands through
// confine -> run-shim -> sidecar -> MXC SDK -> engine, with one assertion per
// matrix cell attributed to the containment promise it witnesses (ADR 0006):
//
//   Promise 1 — filesystem effects confined to the grant table  (FS-*)
//   Promise 3 — egress pinned to the proxy / deny, ingress denied (EG-*)
//   Promise 4 — UI, clipboard, input blocked by default         (UI-*)
//   Promise 5 — the control channel is unreachable in-container (TCB-*)
//
// Relaxations are the deliberate widening of promises 1/3 and are asserted to
// change live enforcement only when granted (RX-*), never silently; the
// session-log records of those grants are pinned at the session seam in
// packages/opencode/test/kilocode/sandbox/relaxation-logging.test.ts (bun
// runner — CI) because the session audit JSONL lives in the opencode layer.
// PERF-* asserts the ticket's per-command overhead budget from the spec's
// Testing Decisions (documented ~30 ms SDK-baseline ceiling, generous margin).
//
// Every live test is probe-gated: the capability matrix below classifies the
// host once and every cell either matches its assertions to what this host can
// honestly execute or skips with the precise missing capability. Cells that
// need a capability this host lacks say so by name in the skip.
//
// Known upstream gap carried from ticket 17: durable config terminal-kind
// relaxations are not yet honoured by the PTY gate, so this suite deliberately
// asserts NO durable-terminal behaviour and would need extending when upstream
// (and ticket 17's follow-up) lands that surface.

type RawSupport = {
  isSupported?: boolean
  isolationTier?: string
  warnings?: unknown
  uiCapabilities?: Record<string, unknown>
}

type Capabilities =
  | { qualify: false; reason: string }
  | {
      qualify: true
      entry: string
      tier: string
      support: RawSupport
      // Whether MXC's probe says this host can pin a container to an
      // identity-less host loopback proxy (Model 2). False on this host
      // (PSEC 1.0); the proxied cells then assert the typed fail-closed
      // refusal instead of the flow.
      model2Ingress: boolean
      credentialStore?: string
      uiCapabilities?: Record<string, unknown>
    }

let cached: Promise<Capabilities> | undefined

// One probe session per run: the matrix classifies the host once, cells select
// assertions from the result. Facts are measured, never guessed.
function capabilities(): Promise<Capabilities> {
  cached ??= (async () => {
    if (process.platform !== "win32")
      return { qualify: false, reason: `the MXC enforcement stack only exists on Windows; this host is ${process.platform}` }
    const entry =
      process.env.KILO_MXC_SDK_ENTRY ??
      path.join(os.tmpdir(), "kilo", "mxc-smoke", "node_modules", "@microsoft", "mxc-sdk", "dist", "v1", "index.js")
    if (!existsSync(entry)) return { qualify: false, reason: `no MXC SDK installed at ${entry}; install it to run the live cells` }
    const versions = process.versions as Record<string, string | undefined>
    if (versions.bun) return { qualify: false, reason: "the MXC SDK cannot run under Bun" }
    const sdk = (await import(`file://${entry.replaceAll("\\", "/")}`)) as {
      getPlatformSupport: () => Promise<RawSupport>
      probe?: (request?: unknown) => Promise<{ error?: string; probes?: Record<string, boolean> }>
    }
    const support = await sdk.getPlatformSupport()
    const assessment = assessPlatformSupport(support, os.release())
    if (assessment.verdict !== "enforce")
      return { qualify: false, reason: assessment.reason ?? `the probe refused this host (tier: ${assessment.tier})` }

    // Model 2 (identity-less host loopback proxy) capability probe — MXC's own
    // probe surface, the same request ticket 16's tests use.
    let model2Ingress = false
    if (sdk.probe) {
      try {
        const probe = await sdk.probe({
          command: "cmd /c echo probe",
          network: {
            egress: { default: "deny" },
            ingress: { default: "allow", hostLoopback: "allow" },
            runtimeConfig: { networkProxy: "http://127.0.0.1:1" },
          },
        })
        model2Ingress = probe.probes?.baseContainerSupportsIngressHostLoopbackAllow === true && !probe.error
      } catch {
        return { qualify: false, reason: "the MXC Model 2 capability probe failed on this host; refusing to assert either branch" }
      }
    }

    const credentialStore = [".ssh", ".gnupg", ".aws", ".azure", ".kube"]
      .map((name) => path.join(os.homedir(), name))
      .find((dir) => existsSync(dir) && readdirSync(dir).some((file) => statSync(path.join(dir, file)).isFile()))

    return {
      qualify: true,
      entry,
      tier: assessment.tier,
      support,
      model2Ingress,
      ...(credentialStore === undefined ? {} : { credentialStore }),
      ...(support.uiCapabilities === undefined ? {} : { uiCapabilities: support.uiCapabilities }),
    }
  })()
  return cached
}

async function gated(t: { skip: (message?: string) => void }): Promise<Extract<Capabilities, { qualify: true }>> {
  const caps = await capabilities()
  if (!caps.qualify) {
    t.skip(caps.reason) // node:test's skip aborts the test by throwing
    throw new Error("capability gate did not abort the test")
  }
  return caps
}

// The strictest default-ish assignment used across the matrix cells: workspace
// and temp granted read-write, secret-named files denied even inside the
// workspace, egress denied. The grant table's profile/credential/OS grants
// come from translate's default-table composition off the launch environment.
function matrixProfile(
  root: string,
  overrides: {
    denyNames?: ReadonlyArray<string>
    relaxations?: ReadonlyArray<Relaxation>
    network?: Profile["network"]
  } = {},
): Profile {
  return {
    filesystem: {
      allowWrite: [{ path: root, kind: "subtree" }],
      denyWrite: [],
      denyNames: overrides.denyNames ?? [".env"],
      temporaryDirectory: path.join(root, "tmp"),
    },
    network: overrides.network ?? { mode: "deny", allowedHosts: [] },
    environment: { deny: [], set: {} },
    ...(overrides.relaxations === undefined ? {} : { relaxations: overrides.relaxations }),
  }
}

async function runConfined(
  profile: Profile,
  command: string,
  args: Array<string>,
  env: Record<string, string>,
  options: { cwd?: string; environment?: Record<string, string> } = {},
) {
  const prepared = await Effect.runPromise(
    Effect.scoped(
      confine(profile, {
        command,
        args,
        cwd: options.cwd,
        environment: { ...process.env, ...options.environment },
      }),
    ),
  )
  const child = spawn(prepared.command, prepared.args, {
    env: { ...process.env, ...env },
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
  const code = await new Promise<number | null>((resolve) => child.on("close", resolve))
  if (stderr.includes("kilo-mxc-shim:")) throw new Error(`confined launch failed: ${stderr}`)
  return { code, stdout, stderr }
}

// A timed trivial confined run: spawn-to-completion wall time through the full
// stack (shim + transient sidecar + engine round trip).
async function timedConfined(profile: Profile, entry: string, options: { cwd?: string } = {}) {
  const started = performance.now()
  const result = await runConfined(profile, "cmd", ["/c", "echo PERF_OK"], { KILO_MXC_SDK_ENTRY: entry }, options)
  return { ...result, elapsed: performance.now() - started }
}

describe("seam 3 enforcement suite (probe-gated)", () => {
  test("FS-ALLOW-01: a write inside the granted workspace lands on the host (ADR 0006 promise 1)", async (t) => {
    const caps = await gated(t)
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-e2e-fs-allow-"))
    try {
      const probe = path.join(root, "workspace-artefact.txt")
      const result = await runConfined(matrixProfile(root), "cmd", ["/c", `(echo WORKSPACE_WRITE) > ${probe} & type ${probe}`], {
        KILO_MXC_SDK_ENTRY: caps.entry,
      })
      assert.equal(result.code, 0, `the in-workspace write must be allowed: ${result.stderr}`)
      assert.match(result.stdout, /WORKSPACE_WRITE/, "the confined command must read back what it wrote")
      assert.equal(readFileSync(probe, "utf8").trim(), "WORKSPACE_WRITE", "the write must land on the host")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("FS-DENY-01: a write under the user profile is denied and leaves no host artefact (ADR 0006 promise 1)", async (t) => {
    const caps = await gated(t)
    const writeProbe = path.join(os.homedir(), "kilo-e2e-profile-write-probe.txt")
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-e2e-fs-deny-"))
    try {
      const result = await runConfined(
        matrixProfile(root),
        "cmd",
        ["/c", `(echo x) > ${writeProbe} & if exist ${writeProbe} (echo PROBE_WRITTEN) else (echo PROBE_DENIED)`],
        { KILO_MXC_SDK_ENTRY: caps.entry },
      )
      assert.match(result.stderr, /Access is denied/, "the engine must deny the profile write with an access error")
      assert.match(result.stdout, /PROBE_DENIED/, "the confined command itself must see the write fail")
      assert.equal(existsSync(writeProbe), false, "no host artefact may remain")
    } finally {
      rmSync(writeProbe, { force: true })
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("FS-DENY-02: reading a credential store is denied (ADR 0006 promise 1)", async (t) => {
    const caps = await gated(t)
    const store = caps.credentialStore
    if (store === undefined)
      return t.skip("no credential store with a readable candidate file exists on this host (~/.ssh, ~/.gnupg, ~/.aws, ~/.azure, ~/.kube)")
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-e2e-fs-cred-"))
    try {
      const secret = path.join(store, readdirSync(store).find((file) => statSync(path.join(store, file)).isFile()) ?? "")
      const result = await runConfined(matrixProfile(root), "cmd", ["/c", `type ${secret}`], { KILO_MXC_SDK_ENTRY: caps.entry })
      assert.match(result.stderr, /Access is denied/, "the credential store contents must be unreadable in-container")
      assert.notEqual(result.code, 0, "the read attempt must not succeed")
      assert.equal(result.stdout, "", "no store content may leak to stdout")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("FS-DENY-03: a secret-named file inside the workspace stays denied (ADR 0006 promise 1)", async (t) => {
    const caps = await gated(t)
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-e2e-fs-secret-"))
    try {
      writeFileSync(path.join(root, ".env"), "SECRET=kilo-e2e\n")
      const result = await runConfined(matrixProfile(root), "cmd", ["/c", "type .env"], { KILO_MXC_SDK_ENTRY: caps.entry }, { cwd: root })
      assert.match(result.stderr, /Access is denied/, "the secret-named file must be unreadable even inside the workspace")
      assert.doesNotMatch(result.stdout, /SECRET/, "no secret content may leak to stdout")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  // The per-command overhead budget (spec, Testing Decisions): a trivial
  // confined command must complete within a documented ceiling. The measured
  // baseline is ~30 ms for a bare MXC SDK spawn (mxc-terminal-spike facts);
  // the full stack adds the shim's transient sidecar and the control round
  // trip, so the budget uses a generous margin for host variance around that
  // baseline — CONFINED_COMMAND_BUDGET_MS below is the documented figure, and
  // this cell fails loudly before a real slowdown could ship. Samples are
  // medians of repeated runs; every sample is emitted as a diagnostic so the
  // observed numbers stay attributable in the run output.
  const CONFINED_COMMAND_BUDGET_MS = 1_000
  const PERF_SAMPLES = 5
  test("PERF-BUDGET-01: a trivial confined command's spawn-to-completion stays within the documented budget", async (t) => {
    const caps = await gated(t)
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-e2e-perf-"))
    try {
      // Warm-up: first confined run pays one-off MXC infrastructure costs.
      const warmed = await timedConfined(matrixProfile(root), caps.entry, { cwd: root })
      assert.equal(warmed.code, 0, `the warm-up run must be a healthy trivial confined command: ${warmed.stderr}`)
      const samples: number[] = []
      for (let index = 0; index < PERF_SAMPLES; index += 1) {
        const sample = await timedConfined(matrixProfile(root), caps.entry, { cwd: root })
        assert.equal(sample.code, 0, `sample ${index + 1} must be a healthy trivial confined command: ${sample.stderr}`)
        assert.match(sample.stdout, /PERF_OK/, `sample ${index + 1} must round-trip its output`)
        samples.push(sample.elapsed)
        t.diagnostic(`PERF sample ${index + 1}/${PERF_SAMPLES}: ${sample.elapsed.toFixed(1)} ms spawn-to-completion`)
      }
      const median = [...samples].sort((a, b) => a - b)[Math.floor(samples.length / 2)]
      t.diagnostic(`PERF median: ${median.toFixed(1)} ms (budget: ${CONFINED_COMMAND_BUDGET_MS} ms)` + ` samples: ${samples.map((value) => value.toFixed(0)).join(", ")}`)
      assert.ok(
        median <= CONFINED_COMMAND_BUDGET_MS,
        `per-command overhead ${median.toFixed(1)} ms exceeds the documented budget ${CONFINED_COMMAND_BUDGET_MS} ms — regressions must be investigated before shipping`,
      )
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("TCB-01: a sandboxed process cannot reach the sidecar control channel (ADR 0006 promise 5)", async (t) => {
    const caps = await gated(t)
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-e2e-tcb-"))
    const sidecar = await startSidecar({ env: { KILO_MXC_SDK_ENTRY: caps.entry } })
    try {
      // The channel serves the host driver before the confined probe runs.
      await sidecar.handshake()
      const verdict = path.join(root, "tcb-verdict.txt")
      // Worst-case attacker knowledge: the endpoint name and a poisoned token
      // are handed to the confined probe (the launch environment must still
      // strip every KILO_MXC_* name), and container reach is asserted from
      // inside. node runs under the default table; net.connect fails fast to a
      // verdict line in the granted workspace either way.
      const script = [
        "const net=require('node:net'),fs=require('node:fs')",
        "const endpoint=process.argv[process.argv.length-2],out=process.argv[process.argv.length-1]",
        "const token=process.env.KILO_MXC_CONTROL_TOKEN===undefined?'TOKEN_ABSENT':'TOKEN_PRESENT'",
        "new Promise(r=>{const s=net.connect(endpoint)",
        "s.once('connect',()=>{s.destroy();r('TCB_REACHED')})",
        "s.once('error',e=>r('TCB_FAILED:'+e.code))",
        "s.setTimeout(30000,()=>{s.destroy();r('TCB_FAILED:timeout')})}).then(v=>{fs.writeFileSync(out,token+'\\n'+v);process.exit(0)})",
      ].join(";")
      await runConfined(
        matrixProfile(root),
        process.execPath,
        ["-e", script, sidecar.endpoint, verdict],
        { KILO_MXC_SDK_ENTRY: caps.entry },
        { cwd: root, environment: { KILO_MXC_CONTROL_TOKEN: "kilo-e2e-poison", KILO_MXC_CONTROL_ID: "kilo-e2e-poison" } },
      )
      const observed = existsSync(verdict) ? readFileSync(verdict, "utf8").trim() : "(no verdict)"
      assert.match(observed, /^TOKEN_ABSENT/m, "the launch environment must strip every KILO_MXC_* name from the container")
      assert.match(observed, /TCB_FAILED:/, `a sandboxed process must never reach the control channel: ${observed}`)
      assert.doesNotMatch(observed, /TCB_REACHED/, "reaching the pipe at all, even unauthenticated, is a TCB breach")
      // The channel must be intact afterwards: the confined probe poisoned
      // nothing.
      const after = await sidecar.handshake()
      assert.ok(after.pid > 0, "the sidecar must still serve the control channel after the confined probe")
    } finally {
      await sidecar.shutdown().catch(() => sidecar.stop())
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("UI-DENY-01: the probe reports the shipped posture's denied UI capabilities (ADR 0006 promise 4)", async (t) => {
    const caps = await gated(t)
    // Denied fields only: clipboard read/write, input injection, desktop
    // switching. Window creation stays intentionally available (ticket 13's
    // win32k evidence: the GUI subsystem must survive, or USER32-linked tools
    // die 0xC0000142) — and win32k enforcement itself is never asserted here.
    const caps_ui = caps.uiCapabilities
    if (caps_ui === undefined) return t.skip("the host platform support reports no UI capability facts; nothing to assert")
    t.diagnostic(`ui capabilities on this host: ${JSON.stringify(caps_ui)}`)
    assert.equal(caps_ui.canBlockClipboardRead, true, "clipboard reads must be blockable (MXC default-deny them whenever the UI subsystem is enabled)")
    assert.equal(caps_ui.canBlockClipboardWrite, true, "clipboard writes must be blockable (MXC default-deny them whenever the UI subsystem is enabled)")
    assert.equal(caps_ui.canBlockInputInjection, true, "input injection must be blockable (MXC default-deny it whenever the UI subsystem is enabled)")
    assert.equal(caps_ui.canBlockDesktopSwitching, true, "desktop switching must be blockable (MXC default-deny it whenever the UI subsystem is enabled)")
  })

  test("UI-POSTURE-01: the shipped UI posture keeps the GUI subsystem available (no win32k assertion)", async (t) => {
    const _caps = await gated(t) // the gate is the point: this cell asserts posture shapes, not host facts
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-e2e-ui-posture-"))
    try {
      const request = translate(matrixProfile(root), {
        command: "cmd",
        args: ["/c", "echo posture"],
        cwd: root,
        environment: { PATH: "C:\\Windows\\System32" },
      })
      assert.deepEqual(request.ui, { disable: false }, "the MXC UI kill switch must stay off so USER32-linked tools (node, git, PowerShell) start")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("RX-READ-01: a recorded read relaxation re-grants exactly the denied file through the full stack", async (t) => {
    const caps = await gated(t)
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-e2e-relax-"))
    try {
      writeFileSync(path.join(root, ".env"), "SECRET=kilo-e2e\n")
      const env = { KILO_MXC_SDK_ENTRY: caps.entry }
      // Baseline: the secret-named file is denied inside the workspace.
      const denied = await runConfined(matrixProfile(root), "cmd", ["/c", "type .env"], env, { cwd: root })
      assert.match(denied.stderr, /Access is denied/, "without the relaxation the secret-named file stays unreadable")
      assert.doesNotMatch(denied.stdout, /SECRET/, "no secret content may leak before the grant")
      // Granted: the identical read succeeds with exactly that one recorded
      // relaxation in the profile — the widening reaches the engine live.
      const granted = await runConfined(
        matrixProfile(root, { relaxations: [{ kind: "path", access: "read", path: path.join(root, ".env") }] }),
        "cmd",
        ["/c", "type .env"],
        env,
        { cwd: root },
      )
      assert.equal(granted.code, 0, `the relaxed read must succeed end to end: ${granted.stderr}`)
      assert.match(granted.stdout, /SECRET=kilo-e2e/, "the relaxed read must return the real content")
      // Scope: nothing else was widened — the temporary scratch file in the
      // workspace root stays writable (untouched by the read relaxation).
      const untouched = await runConfined(matrixProfile(root, { relaxations: [{ kind: "path", access: "read", path: path.join(root, ".env") }] }), "cmd", ["/c", `echo SAFE > ${path.join(root, "after-relax.txt")} & type ${path.join(root, "after-relax.txt")}`], env)
      assert.match(untouched.stdout, /SAFE/, "the write workspace grant must be unaffected by the read relaxation")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("EG-DENY-01: the default deny-all egress posture lets no HTTP page through (ADR 0006 promise 3)", async (t) => {
    const caps = await gated(t)
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-e2e-eg-deny-"))
    try {
      const result = await runConfined(matrixProfile(root), "curl", ["--max-time", "15", "-s", "-S", "https://example.com/"], {
        KILO_MXC_SDK_ENTRY: caps.entry,
      })
      assert.notEqual(result.code, 0, "no request page may be fetched under the deny-all posture")
      assert.doesNotMatch(result.stdout, /Example Domain/, "no external content may reach the command")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("EG-ALLOW-01: an allowlisted hostname flows through the pinned proxy (ADR 0006 promise 3)", async (t) => {
    const caps = await gated(t)
    if (!caps.model2Ingress)
      return t.skip(
        "this host cannot pin MXC Model 2 host-loopback proxies (probe reports baseContainerSupportsIngressHostLoopbackAllow=false); the proxied flow is asserted live on capable hosts and this host asserts the fail-closed refusal instead",
      )
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-e2e-eg-proxy-"))
    const proxied = (): Profile => ({
      ...matrixProfile(root),
      network: { mode: "proxy", allowedHosts: ["registry.npmjs.org:443"] },
    })
    try {
      const result = await runConfined(proxied(), "curl", [
        "--max-time",
        "20",
        "-s",
        "-S",
        "https://registry.npmjs.org/express/latest",
      ], { KILO_MXC_SDK_ENTRY: caps.entry })
      assert.equal(result.code, 0, `the allowlisted registry request must flow through the proxy: ${result.stderr}`)
      assert.match(result.stdout, /"name"\s*:\s*"express"/, "the registry must answer through the proxy")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("EG-DENY-02: a non-allowlisted hostname fails closed through the proxy (ADR 0006 promise 3)", async (t) => {
    const caps = await gated(t)
    if (!caps.model2Ingress)
      return t.skip(
        "this host cannot pin MXC Model 2 host-loopback proxies (probe reports baseContainerSupportsIngressHostLoopbackAllow=false); the proxied flow is asserted live on capable hosts and this host asserts the fail-closed refusal instead",
      )
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-e2e-eg-closed-"))
    const proxied = (): Profile => ({
      ...matrixProfile(root),
      network: { mode: "proxy", allowedHosts: ["registry.npmjs.org:443"] },
    })
    try {
      const result = await runConfined(proxied(), "curl", ["--max-time", "15", "-s", "-S", "https://example.com/"], {
        KILO_MXC_SDK_ENTRY: caps.entry,
      })
      assert.notEqual(result.code, 0, "a non-allowlisted hostname must fail closed")
      assert.doesNotMatch(result.stdout, /Example Domain/, "no external content may reach the command")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("EG-DENY-03: an empty allowlist is the deny-all trim (ADR 0006 promise 3)", async (t) => {
    const caps = await gated(t)
    if (!caps.model2Ingress)
      return t.skip(
        "this host cannot pin MXC Model 2 host-loopback proxies (probe reports baseContainerSupportsIngressHostLoopbackAllow=false); the proxied flow is asserted live on capable hosts and this host asserts the fail-closed refusal instead",
      )
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-e2e-eg-trim-"))
    const proxied = (): Profile => ({
      ...matrixProfile(root),
      network: { mode: "proxy", allowedHosts: [] },
    })
    try {
      const result = await runConfined(proxied(), "curl", ["--max-time", "15", "-s", "-S", "https://registry.npmjs.org/"], {
        KILO_MXC_SDK_ENTRY: caps.entry,
      })
      assert.notEqual(result.code, 0, "an empty allowlist must deny the same request the full list allows")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("EG-REFUSE-01: a proxy-pinned run is refused fail-closed where Model 2 cannot be enforced (ADR 0006 promise 3)", async (t) => {
    const caps = await gated(t)
    if (caps.model2Ingress)
      return t.skip("this host enforces Model 2 host-loopback proxies; the proxied flow cells assert that capability live")
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-e2e-eg-refuse-"))
    const proxied = (): Profile => ({
      ...matrixProfile(root),
      network: { mode: "proxy", allowedHosts: ["registry.npmjs.org:443"] },
    })
    try {
      // Fail-closed: MXC refuses a proxy-pinned request it cannot enforce; the
      // command must never fall back to direct egress.
      await assert.rejects(
        runConfined(proxied(), "curl", ["--max-time", "15", "-s", "-S", "https://registry.npmjs.org/"], {
          KILO_MXC_SDK_ENTRY: caps.entry,
        }),
        /hostLoopback|proxy/i,
        "the refusal must be MXC's typed hostLoopback/proxy error, never a degraded run",
      )
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})


