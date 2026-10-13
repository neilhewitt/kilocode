// The session-layer half of the seam-3 enforcement suite (ticket 19): after a
// flow that grants a relaxation, the grant must be present in the session
// audit JSONL with its source. The OS effects of those grants are pinned by
// the probe-gated live cells in
// packages/kilo-sandbox/test/enforcement.test.ts; this file pins the record of
// the grants themselves — the durable config source at session init and the
// prompt source via SandboxPolicy.relax, including the no-duplicate rule for
// an identical regrant.
//
// Runs under the repo's bun test runner in CI. On bun-less hosts the changed
// files are syntax-verified only (ticket-15 precedent; ticket-19 deviation
// reported).

import { createHash } from "node:crypto"
import fs from "node:fs/promises"
import path from "node:path"
import { expect } from "bun:test"
import { Effect, Layer } from "effect"
import { AppNodeBuilder } from "@opencode-ai/core/effect/app-node-builder"
import { CrossSpawnSpawner } from "@opencode-ai/core/cross-spawn-spawner"
import { Database } from "@opencode-ai/core/database/database"
import { Bus } from "@/bus"
import { Config } from "@/config/config"
import * as SandboxPolicy from "@/kilocode/sandbox/policy"
import { SandboxStore } from "@/kilocode/sandbox/store"
import { SessionID } from "@/session/schema"
import { testEffect } from "../../lib/effect"

const it = testEffect(
  Layer.mergeAll(
    Bus.layer,
    AppNodeBuilder.build(Config.node),
    AppNodeBuilder.build(CrossSpawnSpawner.node),
    AppNodeBuilder.build(Database.node),
  ),
)

// Unique per run: the audit store is keyed by the session id hash alone, so a
// fresh id keeps each run's log isolated, and dispose wipes stale rows left by
// earlier runs of the same id on shared machines.
function sessionId(prefix: string) {
  sessionId.counter = (sessionId.counter ?? 0) + 1
  return SessionID.make(`ses_relaxlog${prefix}${sessionId.counter}`)
}

const auditFile = (id: SessionID) => path.join(SandboxStore.root, createHash("sha256").update(id).digest("hex"), "audit.jsonl")

async function relaxationRows(id: SessionID, source: "config" | "prompt") {
  const text = await fs.readFile(auditFile(id), "utf8").catch(() => "")
  return text
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line) as Record<string, unknown>)
    .filter((row) => row["type"] === "sandbox.relaxation" && row["source"] === source)
}

it.instance(
  "durable config relaxations are logged at session init with their source",
  () =>
    Effect.gen(function* () {
      const id = sessionId("config")
      yield* Effect.promise(() => SandboxStore.dispose(id))
      try {
        // The first status in the session initialises the snapshot; durable
        // config relaxations are logged then, once, with source "config".
        yield* SandboxPolicy.status(id)
        const log = yield* Effect.promise(() => relaxationRows(id, "config"))
        expect(log).toHaveLength(1)
        expect(log[0]).toEqual({
          time: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
          type: "sandbox.relaxation",
          source: "config",
          kind: "path",
          access: "read",
          path: "C:/staging",
          reason: "stage read",
        })
      } finally {
        yield* Effect.promise(() => SandboxStore.dispose(id))
      }
    }),
  { config: { sandbox: { enabled: true, relaxations: [{ kind: "path", access: "read", path: "C:/staging", reason: "stage read" }] } } },
)

it.instance(
  "a prompt relaxation lands in the session log with its source and an identical regrant is not re-recorded",
  () =>
    Effect.gen(function* () {
      const id = sessionId("prompt")
      yield* Effect.promise(() => SandboxStore.dispose(id))
      try {
        yield* SandboxPolicy.status(id)
        yield* SandboxPolicy.relax(id, { kind: "path", access: "write", path: "D:/out", reason: "build output" })
        // The identical grant again: recorded once, not twice.
        yield* SandboxPolicy.relax(id, { kind: "path", access: "write", path: "D:/out", reason: "build output" })
        const log = yield* Effect.promise(() => relaxationRows(id, "prompt"))
        expect(log).toHaveLength(1)
        expect(log[0]).toEqual({
          time: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
          type: "sandbox.relaxation",
          source: "prompt",
          kind: "path",
          access: "write",
          path: "D:/out",
          reason: "build output",
        })
      } finally {
        yield* Effect.promise(() => SandboxStore.dispose(id))
      }
    }),
  { config: { sandbox: { enabled: true } } },
)
