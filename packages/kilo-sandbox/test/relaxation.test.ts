import { describe, test } from "node:test"
import assert from "node:assert/strict"
import type { Relaxation } from "../src/profile"
import { isRelaxation, merged, pathRelaxations } from "../src/relaxation"

// Ticket 15 — the relaxation model (ADR 0002): every widening of the grant
// table is a deliberate, recorded relaxation. Pure logic here: what counts as
// a relaxation entry, how durable (config) and ephemeral (session) entries
// merge for one command's table, and which entries actually compose into the
// filesystem posture. The composition itself is asserted at the translate
// seam in mxc.test.ts; recording in the session log is asserted in the
// opencode layer.

describe("relaxation entries", () => {
  test("accepts read and write path relaxations", () => {
    assert.equal(isRelaxation({ kind: "path", access: "read", path: "C:\\Users\\me\\.ssh" }), true)
    assert.equal(isRelaxation({ kind: "path", access: "write", path: "C:\\workspace\\build" }), true)
  })

  test("accepts the terminal relaxation kind without a path — ticket 17's PTY hook", () => {
    assert.equal(isRelaxation({ kind: "terminal" }), true)
    assert.equal(isRelaxation({ kind: "terminal", reason: "pty for this session" }), true)
    assert.equal(isRelaxation({ kind: "terminal", path: "C:\\anything" }), false, "a terminal relaxation carries no path")
  })

  test("entries may carry a string reason for the session log", () => {
    assert.equal(isRelaxation({ kind: "path", access: "read", path: "C:\\a", reason: "git push reads ~/.ssh" }), true)
    assert.equal(isRelaxation({ kind: "path", access: "read", path: "C:\\a", reason: 7 }), false)
  })

  test("rejects malformed entries fail-closed", () => {
    assert.equal(isRelaxation(undefined), false)
    assert.equal(isRelaxation(null), false)
    assert.equal(isRelaxation("path"), false)
    assert.equal(isRelaxation({}), false)
    assert.equal(isRelaxation({ kind: "path", access: "read" }), false, "a path relaxation requires its path")
    assert.equal(isRelaxation({ kind: "path", access: "exec", path: "C:\\x" }), false, "only read and write widen a table")
    assert.equal(isRelaxation({ kind: "path", access: "read", path: "" }), false, "an empty path widens nothing")
    assert.equal(isRelaxation({ kind: "path", access: "read", path: 7 }), false)
    assert.equal(isRelaxation({ kind: "network" }), false)
  })

  test("only path relaxations compose into a filesystem table", () => {
    assert.deepEqual(
      pathRelaxations([
        { kind: "path", access: "read", path: "C:\\a" },
        { kind: "terminal" },
      ]),
      [{ kind: "path", access: "read", path: "C:\\a" }],
    )
  })
})

describe("durable and ephemeral relaxations merge for one command", () => {
  test("config entries come first, session entries after, in order", () => {
    const config: ReadonlyArray<Relaxation> = [{ kind: "path", access: "read", path: "C:\\Users\\me\\.ssh" }]
    const session: ReadonlyArray<Relaxation> = [{ kind: "path", access: "write", path: "C:\\out" }]
    assert.deepEqual(merged(config, session), [...config, ...session])
  })

  test("an identical grant requested twice composes once", () => {
    const entry: Relaxation = { kind: "path", access: "read", path: "C:\\Users\\me\\.ssh" }
    assert.deepEqual(merged([entry], [entry]), [entry])
    assert.deepEqual(merged([], [entry, { ...entry }]), [entry])
  })

  test("a read and a write grant on the same path are both kept", () => {
    const read: Relaxation = { kind: "path", access: "read", path: "C:\\x" }
    const write: Relaxation = { kind: "path", access: "write", path: "C:\\x" }
    assert.deepEqual(merged([read], [write]), [read, write])
  })

  test("config and session garbage never reaches the table", () => {
    assert.deepEqual(
      merged(
        [{ kind: "path" } as never, { kind: "path", access: "write", path: "C:\\ok" }],
        [{ nonsense: true } as never],
      ),
      [{ kind: "path", access: "write", path: "C:\\ok" }],
    )
  })

  test("terminal relaxations merge like any other kind", () => {
    assert.deepEqual(merged([{ kind: "terminal" }], [{ kind: "terminal" }]), [{ kind: "terminal" }])
  })
})
