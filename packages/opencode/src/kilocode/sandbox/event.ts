import { Schema } from "effect"
import { BusEvent } from "@/bus/bus-event"
import { SessionID } from "@/session/schema"

export const Changed = BusEvent.define(
  "sandbox.status.changed",
  Schema.Struct({
    sessionID: SessionID,
    directory: Schema.String,
    enabled: Schema.Boolean,
    available: Schema.Boolean,
    reason: Schema.optional(Schema.String),
    diagnostics: Schema.optional(Schema.mutable(Schema.Array(Schema.String))),
    unsandboxed: Schema.optional(Schema.Boolean),
    audit: Schema.optional(Schema.Boolean),
    version: Schema.Int,
  }),
)
