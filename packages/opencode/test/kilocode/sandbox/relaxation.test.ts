import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { describe, expect, test } from "bun:test"
import type { SessionID } from "@/session/schema"
import { SandboxConfig } from "@/kilocode/sandbox/config"
import * as SandboxRelaxation from "@/kilocode/sandbox/relaxation"
import { SandboxStore } from "@/kilocode/sandbox/store"

// Ticket 15 — the relaxation and audit-mode session layer. The pure halves
// (validation, merge, records, config resolution) run here; the composition
// into an MXC table is covered by @kilocode/sandbox's node:test seam, and the
// Effect-stack wiring (policy audit branch, relax route) is pinned by the
// source contracts at the bottom the same way the TUI tests pin the plugin.

describe("sandbox config relaxations and audit", () => {
  test("resolves durable relaxations and the audit flag", () => {
    const resolved = SandboxConfig.resolve({
      sandbox: {
        enabled: true,
        audit: true,
        relaxations: [
          { kind: "path", access: "read", path: "~/.ssh", reason: "git push reads the credential store" },
          { kind: "terminal" },
        ],
      },
    })
    expect(resolved.audit).toBe(true)
    expect(resolved.relaxations).toEqual([
      { kind: "path", access: "read", path: "~/.ssh", reason: "git push reads the credential store" },
      { kind: "terminal" },
    ])
  })

  test("defaults audit off with no relaxations", () => {
    const resolved = SandboxConfig.resolve({ sandbox: { enabled: true } })
    expect(resolved.audit).toBe(false)
    expect(resolved.relaxations).toEqual([])
  })

  test("drops malformed config relaxations fail-closed", () => {
    const resolved = SandboxConfig.resolve({
      sandbox: {
        relaxations: [
          { kind: "path", access: "read", path: "~/.ssh" },
          { kind: "path", access: "exec", path: "C:\\x" },
          { kind: "path", access: "read" },
          { kind: "network" },
        ],
      },
    })
    expect(resolved.relaxations).toEqual([{ kind: "path", access: "read", path: "~/.ssh" }])
  })
})

describe("relaxation grant seam", () => {
  test("validates requests fail-closed", () => {
    expect(SandboxRelaxation.grantable({ kind: "path", access: "write", path: "C:\\out" })).toBe(true)
    expect(SandboxRelaxation.grantable({ kind: "terminal", reason: "pty" })).toBe(true)
    expect(SandboxRelaxation.grantable({ kind: "path", access: "write" })).toBe(false)
    expect(SandboxRelaxation.grantable({ kind: "terminal", path: "C:\\x" })).toBe(false)
    expect(SandboxRelaxation.grantable(undefined)).toBe(false)
  })

  test("an identical grant composes once; a new one appends in grant order", () => {
    const first = SandboxRelaxation.appended([], { kind: "path", access: "read", path: "C:\\a" })
    expect(first.added).toBe(true)
    const again = SandboxRelaxation.appended(first.entries, { kind: "path", access: "read", path: "C:\\a" })
    expect(again.added).toBe(false)
    expect(again.entries).toEqual(first.entries)
    const next = SandboxRelaxation.appended(first.entries, { kind: "path", access: "write", path: "C:\\b" })
    expect(next.added).toBe(true)
    expect(next.entries).toEqual([
      { kind: "path", access: "read", path: "C:\\a" },
      { kind: "path", access: "write", path: "C:\\b" },
    ])
  })

  test("records carry the grant's source for the session log", () => {
    expect(SandboxRelaxation.record({ kind: "path", access: "read", path: "C:\\a" }, "config")).toEqual({
      type: "sandbox.relaxation",
      source: "config",
      kind: "path",
      access: "read",
      path: "C:\\a",
    })
    expect(SandboxRelaxation.record({ kind: "terminal", reason: "pty for this session" }, "prompt")).toEqual({
      type: "sandbox.relaxation",
      source: "prompt",
      kind: "terminal",
      reason: "pty for this session",
    })
  })

  test("the config-grant logger asks once per session", () => {
    const scope = `config\0once-${Math.random()}`
    expect(SandboxRelaxation.once(scope)).toBe(true)
    expect(SandboxRelaxation.once(scope)).toBe(false)
  })
})

describe("session snapshot carries relaxations and audit", () => {
  test("round-trips prompt-granted relaxations and the audit flag through the store", async () => {
    const sessionID = `ses_relaxround_${Math.random().toString(16).slice(2)}` as SessionID
    const directory = path.join(os.tmpdir(), `kilo-relax-${Math.random().toString(16).slice(2)}`)
    try {
      await SandboxStore.write(directory, sessionID, {
        enabled: true,
        mode: "deny",
        allowedHosts: [],
        writablePaths: [],
        version: 0,
        relaxations: [{ kind: "path", access: "read", path: "C:\\ok" }],
        audit: true,
      })
      const stored = await SandboxStore.read(directory, sessionID)
      expect(stored?.audit).toBe(true)
      expect(stored?.relaxations).toEqual([{ kind: "path", access: "read", path: "C:\\ok" }])
    } finally {
      await SandboxStore.dispose(sessionID)
    }
  })
})

describe("audit mode and relax wiring contracts", () => {
  const read = (relative: string) => fs.readFileSync(path.resolve(import.meta.dir, relative), "utf8")

  test("audit sessions run unsandboxed with the would-be table logged per command", () => {
    const source = read("../../../src/kilocode/sandbox/policy.ts")
    expect(source).toContain("active.state.audit === true")
    expect(source).toContain("sandbox.audit.run")
    expect(source).toContain("UNSANDBOXED_SIGNAL} (audit mode)`")
    expect(source).toContain("wouldEnforce")
  })

  test("the engine path stays wired behind the host switch until upstream fixes the crash", () => {
    const source = read("../../../src/kilocode/sandbox/policy.ts")
    expect(source).toContain('KILO_MXC_AUDIT_ENGINE === "1"')
    expect(source).toContain("audit: { denialsPath: SandboxStore.denialsPath(sessionID) }")
    const store = read("../../../src/kilocode/sandbox/store.ts")
    expect(store).toContain("engine-denials.json")
  })

  test("relaxations compose into every enforced table and the relax route reaches the policy", () => {
    const source = read("../../../src/kilocode/sandbox/policy.ts")
    expect(source).toContain("relaxationsFor(active.state, config)")
    expect(source).toContain("SandboxRelaxation.record(entry, \"config\")")
    expect(source).toContain("SandboxRelaxation.record(request, \"prompt\")")
    const handler = read("../../../src/kilocode/server/httpapi/handlers/sandbox.ts")
    expect(handler).toContain("SandboxPolicy.relax(ctx.params.sessionID, ctx.payload)")
  })

  test("the TUI affordance offers prompt-granted relaxations through the relax seam", () => {
    const plugin = read("../../../src/kilocode/plugins/sandbox.tsx")
    expect(plugin).toContain('name: "session.sandbox.relax"')
    expect(plugin).toContain("/sandbox/relax")
    expect(plugin).toContain("body: JSON.stringify(request)")
    // The dialog only supplies the request: the grant is persisted and
    // recorded by the seam (source "prompt"), so the plugin must never write
    // a session-log line of its own.
    expect(plugin).not.toContain("appendAudit")
  })
})
