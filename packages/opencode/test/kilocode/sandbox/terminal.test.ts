import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { PTY_REVISIT_TRIGGER, terminalDecision } from "@kilocode/sandbox"

// Ticket 17 — terminal handling (ADR 0004). This host has no bun; the seams
// the ticket touches are pinned here and in the same package's node suite:
// the pure decision lives in @kilocode/sandbox (node-tested there, and
// re-asserted here); the wiring below is pinned by source contract.
// — kilocode, ticket-15 style

describe("terminal posture decision", () => {
  test("confined without a relaxation takes the pipes fallback", () => {
    const decision = terminalDecision({ confinementActive: true, terminalRelaxed: false })
    expect(decision.mode).toBe("pipes-fallback")
    expect((decision as { signal: string }).signal).toMatch(/no TTY/)
    expect((decision as { signal: string }).signal).toMatch(/terminal relaxation/i)
  })

  test("the revisit trigger names the engine limitation the fallback exists for", () => {
    expect(PTY_REVISIT_TRIGGER).toMatch(/processcontainer/)
    expect(PTY_REVISIT_TRIGGER).toMatch(/unsupported_containment/)
  })

  test("a granted relaxation returns the unsandboxed terminal", () => {
    expect(terminalDecision({ confinementActive: true, terminalRelaxed: true }).mode).toBe("unsandboxed-pty")
    expect(terminalDecision({ confinementActive: false, terminalRelaxed: true }).mode).toBe("unsandboxed-pty")
  })
})

describe("the spawned terminal respects the sandbox gate", () => {
  test("the pty handler installs the terminal gate and passes the session context through", () => {
    const handler = readFileSync(new URL("../../src/server/routes/instance/httpapi/handlers/pty.ts", import.meta.url), "utf8")
    expect(handler).toContain('import "@/kilocode/sandbox/terminal"')
    expect(handler).toContain("service.create({")
  })

  test("the gate consumes a prompt-granted terminal relaxation for exactly one spawn", () => {
    const policy = readFileSync(new URL("../../src/kilocode/sandbox/policy.ts", import.meta.url), "utf8")
    expect(policy).toContain("consumeTerminalGrant")
    expect(policy).toContain("sandbox.terminal.use")

    const terminal = readFileSync(new URL("../../src/kilocode/sandbox/terminal.ts", import.meta.url), "utf8")
    expect(terminal).toContain("SandboxPolicy.consumeTerminalGrant")
    expect(terminal).toContain("stream: true")
    expect(terminal).toContain("PIPES_FALLBACK_SIGNAL")
    expect(terminal).toContain(PTY_REVISIT_TRIGGER)
  })

  test("the core spawn gate consults the host gate and marks pipes terminals", () => {
    const service = readFileSync(new URL("../../../../packages/core/src/pty.ts", import.meta.url), "utf8")
    expect(service).toContain("KiloPtySpawnGate.current()")
    expect(service).toContain('tty: "pipes"')
  })
})
