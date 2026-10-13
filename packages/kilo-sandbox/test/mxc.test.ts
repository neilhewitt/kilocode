import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { spawn, spawnSync } from "node:child_process"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs"
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
import { isRunCommand } from "@kilocode/mxc-sidecar"
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
    ...(overrides.relaxations === undefined ? {} : { relaxations: overrides.relaxations }),
    ...(overrides.audit === undefined ? {} : { audit: overrides.audit }),
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

function sameTree(left: string, right: string) {
  const a = process.platform === "win32" ? left.toLowerCase() : left
  const b = process.platform === "win32" ? right.toLowerCase() : right
  return a === b || a.startsWith(`${b}\\`)
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

  test("maps denyNames onto denied paths for secret-named files, never directories", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-deny-names-"))
    try {
      mkdirSync(path.join(root, ".git"))
      writeFileSync(path.join(root, ".env"), "SECRET=1")
      mkdirSync(path.join(root, "sub"))
      writeFileSync(path.join(root, "sub", ".gitconfig"), "x")
      const request = translate(profile(root, { filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [".git", ".env"], temporaryDirectory: undefined } }), launch(root))
      assert.ok(request.filesystem.deniedPaths.includes(path.join(root, ".env")), "deny-named files are denied")
      assert.ok(!request.filesystem.deniedPaths.includes(path.join(root, ".git")), "deny-named directories stay under their grant so VCS metadata keeps working")
      assert.ok(!request.filesystem.deniedPaths.some((entry) => entry.endsWith(".gitconfig")), "non-matching names are not denied")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("composes the strictest-default readonly table from the environment", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-table-"))
    const world = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-world-"))
    try {
      const home = path.join(world, "home")
      const tools = path.join(world, "tools")
      const under = path.join(root, "under")
      mkdirSync(home)
      mkdirSync(tools)
      mkdirSync(under)
      const request = translate(
        profile(root, { filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: undefined } }),
        launch(root, {
          environment: {
            PATH: `C:\\Windows\\System32;${tools};${under}`,
            USERPROFILE: home,
            SystemRoot: "C:\\Windows",
            ProgramFiles: "C:\\Program Files",
            "ProgramFiles(x86)": "C:\\Program Files (x86)",
            ProgramData: "C:\\ProgramData",
            SystemDrive: "C:",
          },
        }),
      )
      const readonly = request.filesystem.readonlyPaths
      assert.ok(readonly.includes(home), "the user profile is read-only")
      assert.ok(readonly.includes("C:\\Windows"), "the OS directory is read-only")
      assert.ok(readonly.includes("C:\\Program Files"), "program files are read-only")
      assert.ok(readonly.includes("C:\\Program Files (x86)"), "32-bit program files are read-only")
      assert.ok(readonly.includes("C:\\ProgramData"), "program data is read-only")
      assert.ok(readonly.includes("C:\\"), "the system drive root is readable (pwsh enumerates it on startup)")
      assert.ok(readonly.includes(tools), "PATH toolchain directories are read-only")
      assert.ok(!readonly.includes(under), "PATH entries under a read-write grant must not carve the workspace read-only")
      assert.ok(readonly.includes(path.dirname(root)), "workspace ancestors are generated read-only")
    } finally {
      rmSync(root, { recursive: true, force: true })
      rmSync(world, { recursive: true, force: true })
    }
  })

  test("denies the credential stores under the user profile", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-credentials-"))
    const world = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-credworld-"))
    try {
      const home = path.join(world, "home")
      mkdirSync(path.join(home, ".ssh"), { recursive: true })
      const request = translate(
        profile(root, { filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: undefined } }),
        launch(root, { environment: { PATH: "", USERPROFILE: home } }),
      )
      const denied = request.filesystem.deniedPaths
      assert.ok(denied.includes(path.join(home, ".ssh")), "existing credential stores are denied")
      assert.ok(denied.includes(path.join(home, ".gnupg")), "credential stores are denied even when not yet present")
      for (const store of [".aws", ".azure", ".kube"]) {
        assert.ok(denied.includes(path.join(home, store)), `${store} is denied`)
      }
    } finally {
      rmSync(root, { recursive: true, force: true })
      rmSync(world, { recursive: true, force: true })
    }
  })

  test("redirects toolchain caches to a stable per-tool directory under temp", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-cache-"))
    try {
      const temporary = path.join(root, "tmp")
      mkdirSync(temporary)
      const request = translate(
        profile(root, { filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: temporary } }),
        launch(root, { environment: { PATH: "" } }),
      )
      const expected = {
        npm_config_cache: path.join(temporary, "kilo", "sandbox-cache", "npm"),
        NUGET_PACKAGES: path.join(temporary, "kilo", "sandbox-cache", "nuget"),
        PIP_CACHE_DIR: path.join(temporary, "kilo", "sandbox-cache", "pip"),
        CARGO_HOME: path.join(temporary, "kilo", "sandbox-cache", "cargo"),
      }
      for (const [key, value] of Object.entries(expected)) {
        assert.equal(request.environment[key], value, `${key} is redirected under the temp grant`)
      }
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("keeps user-set cache locations over the shipped redirection defaults", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-cache-user-"))
    try {
      const temporary = path.join(root, "tmp")
      mkdirSync(temporary)
      const request = translate(
        profile(root, { filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: temporary } }),
        launch(root, { environment: { PATH: "", npm_config_cache: "D:\\warm", NPM_CONFIG_CACHE: "D:\\cased" } }),
      )
      assert.equal(request.environment.npm_config_cache, "D:\\warm", "an existing cache location is never clobbered")
      assert.equal(request.environment.NPM_CONFIG_CACHE, "D:\\cased", "case-insensitive duplicates also count as existing")
      assert.equal(request.environment.NUGET_PACKAGES, path.join(temporary, "kilo", "sandbox-cache", "nuget"), "unset tools still redirect")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("does not redirect caches when no temporary directory is granted", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-cache-none-"))
    try {
      const request = translate(
        profile(root, { filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: undefined } }),
        launch(root, { environment: { PATH: "" } }),
      )
      assert.equal(request.environment.npm_config_cache, undefined)
      assert.equal(request.environment.NUGET_PACKAGES, undefined)
      assert.equal(request.environment.PIP_CACHE_DIR, undefined)
      assert.equal(request.environment.CARGO_HOME, undefined)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("defaults the working directory to the first read-write grant", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-cwd-"))
    const second = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-cwd-second-"))
    try {
      const withCwd = translate(
        profile(root, { filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: undefined } }),
        launch(root, { cwd: second }),
      )
      assert.equal(withCwd.workingDirectory, second, "an explicit working directory is preserved")
      const defaulted = translate(
        profile(root, { filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: undefined } }),
        launch(root, { cwd: undefined }),
      )
      assert.equal(defaulted.workingDirectory, root, "without a working directory the first read-write grant is used")
      const none = translate(
        profile(root, { filesystem: { allowWrite: [{ path: path.join(root, "missing"), kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: undefined } }),
        launch(root, { cwd: undefined }),
      )
      assert.equal(none.workingDirectory, undefined, "no read-write grant means no working directory")
    } finally {
      rmSync(root, { recursive: true, force: true })
      rmSync(second, { recursive: true, force: true })
    }
  })

  test("composes the strictest-default UI posture with the GUI subsystem available", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-ui-"))
    try {
      const request = translate(
        profile(root, { filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: undefined } }),
        launch(root, { environment: { PATH: "" } }),
      )
      assert.deepEqual(request.ui, { disable: false }, "the kill switch must be off so USER32-linked tools (node, git, PowerShell) start; clipboard and injection stay denied by the MXC UI policy defaults")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("never carves a read-write path read-only through ancestor generation", () => {
    const outer = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-anc-outer-"))
    const temporary = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-anc-temp-"))
    try {
      const nested = path.join(outer, "nested", "ws")
      mkdirSync(nested, { recursive: true })
      const request = translate(
        profile(outer, {
          filesystem: {
            allowWrite: [
              { path: outer, kind: "subtree" },
              { path: nested, kind: "subtree" },
            ],
            denyWrite: [],
            denyNames: [],
            temporaryDirectory: temporary,
          },
        }),
        launch(outer, { environment: { PATH: "" } }),
      )
      const readonly = request.filesystem.readonlyPaths
      assert.ok(!readonly.includes(temporary), "the temp grant must not be re-granted read-only as a workspace ancestor")
      assert.ok(!readonly.includes(outer), "a workspace containing another workspace stays read-write")
      assert.ok(!readonly.some((entry) => sameTree(entry, temporary)), "no ancestor under the temp grant may be read-only")
      assert.ok(readonly.includes(os.tmpdir()), "genuine ancestors above the temp grant stay read-only")
    } finally {
      rmSync(outer, { recursive: true, force: true })
      rmSync(temporary, { recursive: true, force: true })
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

describe("terminal handling (ADR 0004)", () => {
  test("a pipes-fallback launch's stream ask lands on the run command", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-terminal-"))
    try {
      const streamed = translate(profile(root), { ...launch(root), stream: true } as Launch)
      assert.equal(streamed.stream, true, "the streamed ask rides the translated request the shim carries")
      const captured = translate(profile(root), launch(root))
      assert.equal(captured.stream, undefined, "capture-mode stays the default posture")
      assert.equal(isRunCommand(streamed), true, "the streamed request satisfies the sidecar's wire contract")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("a launch deadline maps onto the run's per-request timeout", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-terminal-"))
    try {
      const translated = translate(profile(root), { ...launch(root), timeoutMs: 30_000 } as unknown as Launch)
      assert.equal(translated.timeoutMs, 30_000)
      assert.equal(translate(profile(root), launch(root)).timeoutMs, undefined, "no deadline means no engine timeout")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("prepare rewrites the launch into the shim carrying the streamed pipes-fallback ask", async () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-terminal-"))
    try {
      const desktop = await Effect.runPromise(
        Effect.scoped(mxc.prepare(profile(root), { ...launch(root), stream: true } as unknown as Launch)),
      )
      const payload = JSON.parse(desktop.args[1] as string) as { stream?: boolean | undefined }
      assert.equal(payload.stream, true, "the shim is told the run streams")
      assert.match(desktop.command, /node(\.exe)?$/i)
      assert.match(desktop.args[0] as string, /run-shim/, "every confined launch goes through the run-shim seam")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})

describe("relaxation composition (ADR 0002)", () => {
  test("a read relaxation un-denies a credential store while the profile stays read-only", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-relax-cred-"))
    const world = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-relax-world-"))
    try {
      const home = path.join(world, "home")
      mkdirSync(path.join(home, ".ssh"), { recursive: true })
      const input = profile(root, {
        filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: undefined },
        relaxations: [{ kind: "path", access: "read", path: path.join(home, ".ssh") }],
      })
      const env = { PATH: "", USERPROFILE: home }
      const denied = translate(input, launch(root, { environment: env })).filesystem.deniedPaths
      assert.ok(!denied.includes(path.join(home, ".ssh")), "a relaxed credential store is no longer denied")
      for (const store of [".gnupg", ".aws", ".azure", ".kube"]) {
        assert.ok(denied.includes(path.join(home, store)), `${store} stays denied`)
      }
      const relaxed = translate(input, launch(root, { environment: env }))
      assert.ok(relaxed.filesystem.readonlyPaths.includes(home), "the user profile stays read-only — a read relaxation grants read, never write")
    } finally {
      rmSync(root, { recursive: true, force: true })
      rmSync(world, { recursive: true, force: true })
    }
  })

  test("a read relaxation un-denies exactly the relaxed deny-named file, and only when it covers the denial", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-relax-name-"))
    try {
      mkdirSync(path.join(root, "a"))
      mkdirSync(path.join(root, "b"))
      writeFileSync(path.join(root, "a", ".env"), "SECRET=1")
      writeFileSync(path.join(root, "b", ".env"), "SECRET=1")
      const input = profile(root, {
        filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [".env"], temporaryDirectory: undefined },
        relaxations: [{ kind: "path", access: "read", path: path.join(root, "a", ".env") }],
      })
      const denied = translate(input, launch(root, { environment: { PATH: "" } })).filesystem.deniedPaths
      assert.ok(!denied.includes(path.join(root, "a", ".env")), "the relaxed deny-named file is readable")
      assert.ok(denied.includes(path.join(root, "b", ".env")), "an unrelaxed deny-named file stays denied")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("a write relaxation grants the path read-write", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-relax-write-"))
    const extra = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-relax-write-extra-"))
    try {
      const request = translate(
        profile(root, {
          filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: undefined },
          relaxations: [{ kind: "path", access: "write", path: extra }],
        }),
        launch(root, { environment: { PATH: "" } }),
      )
      assert.ok(request.filesystem.readwritePaths.includes(extra), "the relaxed path is read-write")
      assert.ok(
        request.filesystem.readonlyPaths.includes(path.dirname(extra)),
        "ancestors of the relaxed write grant stay read-only",
      )
    } finally {
      rmSync(root, { recursive: true, force: true })
      rmSync(extra, { recursive: true, force: true })
    }
  })

  test("a read relaxation outside every grant composes its own readonly grant", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-relax-uncovered-"))
    try {
      const request = translate(
        profile(root, {
          filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: undefined },
          relaxations: [{ kind: "path", access: "read", path: "E:\\vault" }],
        }),
        launch(root, { environment: { PATH: "" } }),
      )
      assert.ok(
        request.filesystem.readonlyPaths.includes("E:\\vault"),
        "a read relaxation on a path no grant covers composes its own readonly grant",
      )
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("a terminal relaxation and garbage entries compose nothing into the table", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-relax-none-"))
    try {
      const bare = profile(root, { filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: undefined } })
      const request = translate(
        profile(root, {
          filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: undefined },
          relaxations: [{ kind: "terminal" }, { kind: "path" } as never, { kind: "path", access: "write" } as never],
        }),
        launch(root, { environment: { PATH: "" } }),
      )
      const expected = translate(bare, launch(root, { environment: { PATH: "" } }))
      assert.deepEqual(request.filesystem, expected.filesystem, "only well-formed path relaxations widen a table")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})

describe("audit request composition (ADR 0002)", () => {
  test("an audit posture maps onto the run's allow-capture request", () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-audit-req-"))
    try {
      const request = translate(
        profile(root, { filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: undefined }, audit: { denialsPath: path.join(root, "denials.json") } }),
        launch(root, { environment: { PATH: "" } }),
      )
      assert.deepEqual(request.audit, { denialsPath: path.join(root, "denials.json") })
      const bare = translate(
        profile(root, { filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: undefined }, audit: {} }),
        launch(root, { environment: { PATH: "" } }),
      )
      assert.deepEqual(bare.audit, {}, "an audit posture without a denials path still asks the engine to capture at its default destination")
      const off = translate(
        profile(root, { filesystem: { allowWrite: [{ path: root, kind: "subtree" }], denyWrite: [], denyNames: [], temporaryDirectory: undefined } }),
        launch(root, { environment: { PATH: "" } }),
      )
      assert.equal(off.audit, undefined, "without an audit posture the run stays a plain confined execution")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
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
        ui: { disable: boolean }
        environment: Record<string, string>
      }
      assert.deepEqual(request.filesystem.readwritePaths, [root, path.join(root, "tmp")])
      assert.deepEqual(request.network, { egress: { default: "deny" } })
      assert.deepEqual(request.ui, { disable: false })
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

function liveProfile(root: string | Array<string>, temporary: string | undefined = os.tmpdir()): Profile {
  const roots = Array.isArray(root) ? root : [root]
  return {
    filesystem: {
      allowWrite: roots.map((entry) => ({ path: entry, kind: "subtree" })),
      denyWrite: [],
      denyNames: [".env"],
      temporaryDirectory: temporary,
    },
    network: { mode: "deny", allowedHosts: [] },
    environment: { deny: [], set: {} },
  }
}

async function runConfined(
  profile: Profile,
  command: string,
  args: Array<string>,
  env: Record<string, string>,
  options: { cwd?: string } = {},
) {
  const prepared = await Effect.runPromise(
    Effect.scoped(confine(profile, { command, args, cwd: options.cwd, environment: { ...process.env } })),
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

  test("a streamed pipes-fallback run forwards output live exactly once and completes identically", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-live-stream-"))
    try {
      const prepared = await Effect.runPromise(
        Effect.scoped(
          confine(liveProfile(root), {
            command: "cmd",
            // Note: `timeout /t` cannot provide the delay — it needs a console
            // for the countdown and dies under the pipes fallback (itself a
            // demonstration of TTY-dependent behaviour). ping's second echo
            // request sleeps a headless second.
            args: ["/c", "(echo L1) & (ping -n 2 127.0.0.1 >nul) & (echo L2) & exit /b 7"],
            environment: { ...process.env },
            stream: true,
          }),
        ),
      )
      const child = spawn(prepared.command, prepared.args, {
        env: { ...process.env, KILO_MXC_SDK_ENTRY: entry },
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      })
      child.stdout.setEncoding("utf8")
      let stdout = ""
      const arrivals: Array<{ at: number; text: string }> = []
      const started = Date.now()
      child.stdout.on("data", (chunk: string) => {
        // Only the shim's LIVE forwards may appear: with a streamed ask the
        // captured result is never replayed, so each byte below arrived as
        // the confined command produced it.
        arrivals.push({ at: Date.now() - started, text: chunk })
        stdout += chunk
      })
      let stderr = ""
      child.stderr.setEncoding("utf8")
      child.stderr.on("data", (chunk: string) => {
        stderr += chunk
      })
      const code = await new Promise<number | null>((resolve) => child.on("close", resolve))
      const normalised = arrivals.map((entry) => entry.text.replace(/\r\n/g, "\n")).join("")
      assert.equal(normalised, "L1\nL2\n", "output arrives live exactly once — never replayed at completion")
      // Chunk coalescing across the process-pipe hop is scheduler-dependent
      // (the SDK itself emits L1/L2 as separate events they reach this
      // consumer read in ≥1 chunk), so only content and interleaving are
      // asserted here; per-chunk liveness is pinned at the scripted seams.
      assert.ok(arrivals.length >= 1)
      assert.equal(code, 7, "completion semantics are identical to capture-mode")
      assert.match(stderr, /\[kilo-mxc\] .*pip(e|es)/i, "the pipes-fallback degradation is signalled on the streamed run")
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

// Seam 3 — acceptance for the default grant table: the six ordinary tools must
// launch and operate under the strictest defaults, and every denial posture of
// the table must hold against real OS enforcement.
describe("mxc default grant table acceptance (probe-gated)", () => {
  function tool(t: import("node:test").TestContext, name: string, probe: () => boolean, reason: string) {
    if (!probe()) return t.skip(`${name} is not installed on this host: ${reason}`)
    return true
  }

  test("cmd launches and operates under the default table", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-acc-cmd-"))
    try {
      const probe = path.join(root, "cmd-ok.txt")
      const result = await runConfined(
        liveProfile(root),
        "cmd",
        ["/c", `(echo CMD_OK) > ${probe} & type ${probe}`],
        { KILO_MXC_SDK_ENTRY: entry },
        { cwd: root },
      )
      assert.equal(result.code, 0)
      assert.match(result.stdout, /CMD_OK/)
      assert.ok(existsSync(probe), "the confined cmd write must land on the host")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("Windows PowerShell launches and operates under the default table", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-acc-ps51-"))
    try {
      const result = await runConfined(
        liveProfile(root),
        "powershell",
        ["-NoProfile", "-Command", "Set-Content -Path ps51-ok.txt -Value PS51_OK; Get-Content ps51-ok.txt"],
        { KILO_MXC_SDK_ENTRY: entry },
        { cwd: root },
      )
      assert.equal(result.code, 0, `the 0xC0000142 naive-table failure must not recur: ${result.stderr}`)
      assert.match(result.stdout, /PS51_OK/)
      assert.ok(existsSync(path.join(root, "ps51-ok.txt")))
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("PowerShell 7 launches and operates under the default table", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    if (!tool(t, "pwsh", () => spawnSync("pwsh", ["-NoProfile", "-Command", "exit 0"]).status === 0, "pwsh probe failed")) return
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-acc-pwsh-"))
    try {
      const result = await runConfined(
        liveProfile(root),
        "pwsh",
        ["-NoProfile", "-Command", "Set-Content -Path pwsh-ok.txt -Value PWSH_OK; Get-Content pwsh-ok.txt"],
        { KILO_MXC_SDK_ENTRY: entry },
        { cwd: root },
      )
      assert.equal(result.code, 0, `pwsh must operate under the default table: ${result.stderr}`)
      assert.match(result.stdout, /PWSH_OK/)
      assert.ok(existsSync(path.join(root, "pwsh-ok.txt")))
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("node launches and operates under the default table", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-acc-node-"))
    try {
      const result = await runConfined(
        liveProfile(root),
        "node",
        ["-e", "require('fs').writeFileSync('node-ok.txt','ok'); console.log('NODE_OK', require('fs').readFileSync('node-ok.txt','utf8'))"],
        { KILO_MXC_SDK_ENTRY: entry },
        { cwd: root },
      )
      assert.equal(result.code, 0)
      assert.match(result.stdout, /NODE_OK ok/)
      assert.ok(existsSync(path.join(root, "node-ok.txt")))
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("npm launches, redirects its cache, and installs under the default table", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-acc-npm-"))
    const cache = path.join(os.tmpdir(), "kilo", "sandbox-cache", "npm")
    try {
      rmSync(path.join(os.tmpdir(), "kilo", "sandbox-cache"), { recursive: true, force: true })
      const version = await runConfined(liveProfile(root), "cmd", ["/c", "npm --version"], {
        KILO_MXC_SDK_ENTRY: entry,
      })
      assert.equal(version.code, 0, `npm must launch: ${version.stderr}`)
      assert.match(version.stdout, /\d+\.\d+\.\d+/)

      const located = await runConfined(liveProfile(root), "cmd", ["/c", "npm config get cache"], {
        KILO_MXC_SDK_ENTRY: entry,
      })
      assert.equal(located.code, 0)
      assert.equal(located.stdout.trim(), cache, "npm's cache must point at the redirected per-tool directory")

      const pkg = path.join(root, "fixture-pkg")
      mkdirSync(pkg)
      writeFileSync(path.join(pkg, "package.json"), JSON.stringify({ name: "kilo-mxc-fixture", version: "1.0.0" }))
      writeFileSync(path.join(pkg, "index.js"), "module.exports = 42\n")
      const packed = spawnSync("cmd", ["/c", "npm pack --json"], { cwd: pkg, encoding: "utf8" })
      assert.equal(packed.status, 0, `host-side npm pack must succeed: ${packed.stderr}`)
      const tarball = path.join(pkg, (JSON.parse(packed.stdout) as Array<{ filename: string }>)[0].filename)

      const workspace = path.join(root, "ws")
      mkdirSync(workspace)
      const install = await runConfined(
        liveProfile(workspace),
        "cmd",
        ["/c", `npm install --no-audit --no-fund --offline ${tarball}`],
        { KILO_MXC_SDK_ENTRY: entry },
        { cwd: workspace },
      )
      assert.equal(install.code, 0, `confined npm install must work: ${install.stderr}`)
      const required = await runConfined(
        liveProfile(workspace),
        "node",
        ["-e", "console.log('NPM_INSTALL_OK', require('kilo-mxc-fixture'))"],
        { KILO_MXC_SDK_ENTRY: entry },
        { cwd: workspace },
      )
      assert.match(required.stdout, /NPM_INSTALL_OK 42/)
      assert.ok(existsSync(path.join(cache, "_cacache")), "npm's cache must land under temp, not the profile")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("git launches and operates under the default table", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    if (!tool(t, "git", () => spawnSync("git", ["--version"]).status === 0, "git probe failed")) return
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-acc-git-"))
    try {
      writeFileSync(path.join(root, "tracked.txt"), "content\n")
      const identity = ["-c", "user.name=Sandbox Probe", "-c", "user.email=probe@example.com"]
      const init = await runConfined(liveProfile(root), "git", ["init", "."], { KILO_MXC_SDK_ENTRY: entry }, { cwd: root })
      assert.equal(init.code, 0, `git init must work: ${init.stderr}`)
      const add = await runConfined(liveProfile(root), "git", ["add", "."], { KILO_MXC_SDK_ENTRY: entry }, { cwd: root })
      assert.equal(add.code, 0, `git add must work: ${add.stderr}`)
      const commit = await runConfined(
        liveProfile(root),
        "git",
        [...identity, "commit", "-m", "sandbox probe"],
        { KILO_MXC_SDK_ENTRY: entry },
        { cwd: root },
      )
      assert.equal(commit.code, 0, `git commit must reach .git read-write: ${commit.stderr}`)
      const log = await runConfined(liveProfile(root), "git", ["log", "--oneline"], { KILO_MXC_SDK_ENTRY: entry }, { cwd: root })
      assert.match(log.stdout, /sandbox probe/)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("profile reads succeed and profile writes are denied", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const readProbe = path.join(os.homedir(), "kilo-mxc-read-probe.txt")
    const writeProbe = path.join(os.homedir(), "kilo-mxc-write-probe.txt")
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-acc-profile-"))
    try {
      writeFileSync(readProbe, "PROFILE_CONTENT\n")
      const read = await runConfined(liveProfile(root), "cmd", ["/c", `type ${readProbe}`], { KILO_MXC_SDK_ENTRY: entry })
      assert.equal(read.code, 0, `profile reads must succeed: ${read.stderr}`)
      assert.match(read.stdout, /PROFILE_CONTENT/)
      const write = await runConfined(
        liveProfile(root),
        "cmd",
        ["/c", `(echo x) > ${writeProbe} & if exist ${writeProbe} (echo PROBE_WRITTEN) else (echo PROBE_DENIED)`],
        { KILO_MXC_SDK_ENTRY: entry },
      )
      assert.match(write.stderr, /Access is denied/)
      assert.match(write.stdout, /PROBE_DENIED/)
      assert.equal(existsSync(writeProbe), false, "no host artefact may remain")
    } finally {
      rmSync(readProbe, { force: true })
      rmSync(writeProbe, { force: true })
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("reading a credential store is denied", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const store = [".ssh", ".gnupg", ".aws", ".azure", ".kube"]
      .map((name) => path.join(os.homedir(), name))
      .find((dir) => existsSync(dir) && readdirSync(dir).some((file) => statSync(path.join(dir, file)).isFile()))
    if (!store) return t.skip("no credential store with a readable candidate file exists on this host")
    const secret = path.join(store, readdirSync(store).find((file) => statSync(path.join(store, file)).isFile()) ?? "")
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-acc-cred-"))
    try {
      const result = await runConfined(liveProfile(root), "cmd", ["/c", `type ${secret}`], { KILO_MXC_SDK_ENTRY: entry })
      assert.match(result.stderr, /Access is denied/, "the credential store contents must be unreadable")
      assert.notEqual(result.code, 0)
      assert.equal(result.stdout, "", "no store content may leak to stdout")
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("reading a secret-named file inside the workspace is denied", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-acc-secret-"))
    try {
      writeFileSync(path.join(root, ".env"), "SECRET=1\n")
      const result = await runConfined(liveProfile(root), "cmd", ["/c", "type .env"], {
        KILO_MXC_SDK_ENTRY: entry,
      }, { cwd: root })
      assert.match(result.stderr, /Access is denied/, "the secret-named file must be unreadable")
      assert.doesNotMatch(result.stdout, /SECRET/)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("redirected caches are reused across commands and revoked by deletion", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const root = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-acc-cache-"))
    const cache = path.join(os.tmpdir(), "kilo", "sandbox-cache", "npm")
    const marker = path.join(cache, "marker")
    try {
      rmSync(path.join(os.tmpdir(), "kilo", "sandbox-cache"), { recursive: true, force: true })
      const before = await runConfined(liveProfile(root), "cmd", [`/c`, `if exist ${marker} (echo REUSED) else (echo MISSING)`], {
        KILO_MXC_SDK_ENTRY: entry,
      })
      assert.match(before.stdout, /MISSING/)
      mkdirSync(cache, { recursive: true })
      writeFileSync(marker, "warm\n")
      const reused = await runConfined(liveProfile(root), "cmd", [`/c`, `if exist ${marker} (echo REUSED) else (echo MISSING)`], {
        KILO_MXC_SDK_ENTRY: entry,
      })
      assert.match(reused.stdout, /REUSED/, "the same stable cache directory is visible across commands")
      rmSync(path.join(os.tmpdir(), "kilo", "sandbox-cache"), { recursive: true, force: true })
      const revoked = await runConfined(liveProfile(root), "cmd", [`/c`, `if exist ${marker} (echo REUSED) else (echo MISSING)`], {
        KILO_MXC_SDK_ENTRY: entry,
      })
      assert.match(revoked.stdout, /MISSING/, "deleting the directory revokes the cache")
    } finally {
      rmSync(path.join(os.tmpdir(), "kilo", "sandbox-cache"), { recursive: true, force: true })
      rmSync(root, { recursive: true, force: true })
    }
  })

  test("multiple workspaces are each granted read-write", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const first = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-acc-multi-a-"))
    const second = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-acc-multi-b-"))
    try {
      const left = path.join(first, "left.txt")
      const right = path.join(second, "right.txt")
      const result = await runConfined(
        liveProfile([first, second]),
        "cmd",
        ["/c", `(echo L) > ${left} & (echo R) > ${right} & if exist ${left} if exist ${right} (echo BOTH_OK) else (echo BOTH_MISSING)`],
        { KILO_MXC_SDK_ENTRY: entry },
      )
      assert.equal(result.code, 0)
      assert.match(result.stdout, /BOTH_OK/)
      assert.ok(existsSync(left) && existsSync(right))
    } finally {
      rmSync(first, { recursive: true, force: true })
      rmSync(second, { recursive: true, force: true })
    }
  })

  test("the working directory defaults to the first read-write grant", async (t) => {
    const entry = await liveSdk(t)
    if (!entry) return
    const first = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-acc-cwd-a-"))
    const second = mkdtempSync(path.join(os.tmpdir(), "kilo-mxc-acc-cwd-b-"))
    try {
      const result = await runConfined(liveProfile([first, second]), "cmd", ["/c", "cd"], { KILO_MXC_SDK_ENTRY: entry })
      assert.equal(result.stdout.trim(), first)
    } finally {
      rmSync(first, { recursive: true, force: true })
      rmSync(second, { recursive: true, force: true })
    }
  })
})
