import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { PIPES_FALLBACK_SIGNAL, PTY_REVISIT_TRIGGER, pipesTty, terminalDecision } from "../src/terminal.ts"

describe("the PTY revisit trigger", () => {
  test("names the upstream engine limitation and the relaxation posture", () => {
    assert.match(PTY_REVISIT_TRIGGER, /processcontainer/)
    assert.match(PTY_REVISIT_TRIGGER, /spawnWithPty/)
    assert.match(PTY_REVISIT_TRIGGER, /unsupported_containment/)
    assert.match(PTY_REVISIT_TRIGGER, /revisit/i)
    assert.match(
      PTY_REVISIT_TRIGGER,
      /pip(e|es) (fallback|surface)/i,
      "the fallback ships under this constant's watch",
    )
  })
})

describe("terminal decision", () => {
  test("active confinement without a relaxation takes the pipes fallback", () => {
    const decision = terminalDecision({ confinementActive: true, terminalRelaxed: false })
    assert.equal(decision.mode, "pipes-fallback")
    assert.match((decision as { signal: string }).signal, /no TTY/)
    assert.match((decision as { signal: string }).signal, /terminal relaxation/i)
  })

  test("a granted terminal relaxation returns the unsandboxed terminal even under active confinement", () => {
    const decision = terminalDecision({ confinementActive: true, terminalRelaxed: true })
    assert.equal(decision.mode, "unsandboxed-pty")
  })

  test("the signal names the engine's PTY refusal, not a hypothetical", () => {
    assert.match(PIPES_FALLBACK_SIGNAL, /PTY/i)
    assert.match(PIPES_FALLBACK_SIGNAL, /unsupported/i)
  })

  test("inactive confinement leaves the terminal alone", () => {
    assert.equal(terminalDecision({ confinementActive: false, terminalRelaxed: false }).mode, "unsandboxed-pty")
    assert.equal(terminalDecision({ confinementActive: false, terminalRelaxed: true }).mode, "unsandboxed-pty")
  })
})

describe("pipes tty proc", () => {
  function tree() {
    const killed: Array<string | undefined> = []
    const tty = pipesTty({
      pid: 4242,
      kill: (signal) => {
        killed.push(signal)
      },
    })
    return { tty, killed }
  }

  test("presents the host pid for tree-killing and delegates kills to the spawner's tree kill", () => {
    const { tty, killed } = tree()
    assert.equal(tty.pid, 4242)
    tty.kill()
    tty.kill("SIGTERM")
    assert.deepEqual(killed, [undefined, "SIGTERM"], "the kill is the spawner's job-object tree kill, whatever thePTY contract asks")
  })

  test("writes and resizes are refused under confinement and output is delivered subscribed", () => {
    const { tty } = tree()
    const seen: string[] = []
    const listener = tty.onData((data) => seen.push(data))
    tty.write("typed input must not reach a confined process\n")
    tty.resize(80, 25)
    tty.emit("stdout", new TextEncoder().encode("size: "))
    tty.emit("stderr", new TextEncoder().encode("warn"))
    assert.deepEqual(seen, ["size: ", "warn"])
    listener.dispose()
    tty.emit("stdout", new TextEncoder().encode("gone"))
    assert.equal(seen.length, 2, "disposal stops delivery")
  })

  test("output chunks decode utf-8 across byte boundaries", () => {
    const { tty } = tree()
    const seen: string[] = []
    tty.onData((data) => seen.push(data))
    const bytes = new TextEncoder().encode("aé€")
    tty.emit("stdout", bytes.slice(0, 1))
    tty.emit("stdout", bytes.slice(1))
    assert.deepEqual(
      seen,
      ["a", "é€"],
      "chunk boundaries split mid-codepoint never produce replacement characters or dropped bytes",
    )
  })

  test("exited listeners fire exactly once with the observed exit code", () => {
    const { tty } = tree()
    const exits: Array<{ exitCode: number }> = []
    tty.onExit((event) => exits.push(event))
    tty.emitExit({ exitCode: 42 })
    tty.emitExit({ exitCode: 43 })
    tty.emitExit({})
    assert.deepEqual(exits, [{ exitCode: 42 }], "only the first exit is observable")
  })
})
