import { Schema } from "effect"
import { HttpApi, HttpApiEndpoint, HttpApiGroup, OpenApi } from "effect/unstable/httpapi"
import { SessionID } from "@/session/schema"
import { Authorization } from "@/server/routes/instance/httpapi/middleware/authorization"
import { InstanceContextMiddleware } from "@/server/routes/instance/httpapi/middleware/instance-context"
import {
  WorkspaceRoutingMiddleware,
  WorkspaceRoutingQuery,
} from "@/server/routes/instance/httpapi/middleware/workspace-routing"
import { described } from "@/server/routes/instance/httpapi/groups/metadata"
import { ApiNotFoundError } from "@/server/routes/instance/httpapi/errors"

const root = "/session/:sessionID/sandbox"

export const SandboxStatus = Schema.Struct({
  directory: Schema.String,
  enabled: Schema.Boolean,
  available: Schema.Boolean,
  reason: Schema.optional(Schema.String),
  diagnostics: Schema.optional(Schema.mutable(Schema.Array(Schema.String))),
  unsandboxed: Schema.optional(Schema.Boolean),
  audit: Schema.optional(Schema.Boolean),
  version: Schema.Int,
})

export const SandboxSupport = Schema.Struct({
  available: Schema.Boolean,
  reason: Schema.optional(Schema.String),
})

export const SandboxGatePayload = Schema.Struct({
  choice: Schema.Literals(["abort", "continue-unsandboxed"]),
})

export const SandboxRelaxPayload = Schema.Struct({
  kind: Schema.Literals(["path", "terminal"]),
  access: Schema.optional(Schema.Literals(["read", "write"])),
  path: Schema.optional(Schema.String),
  reason: Schema.optional(Schema.String),
}).annotate({
  description:
    "A relaxation request for the current session: a path relaxation grants read or write outside the default grant table; the terminal kind is the PTY relaxation hook. Granted relaxations apply to this session only and are recorded in the session log.",
})

export const SandboxApi = HttpApi.make("sandbox")
  .add(
    HttpApiGroup.make("sandbox")
      .add(
        HttpApiEndpoint.get("support", "/sandbox/support", {
          query: WorkspaceRoutingQuery,
          success: described(SandboxSupport, "Sandbox backend support"),
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "sandbox.support",
            summary: "Get sandbox backend support",
            description: "Get sandbox backend availability without creating a session.",
          }),
        ),
        HttpApiEndpoint.get("status", root, {
          params: { sessionID: SessionID },
          query: WorkspaceRoutingQuery,
          success: described(SandboxStatus, "Session sandbox status"),
          error: ApiNotFoundError,
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "sandbox.status",
            summary: "Get session sandbox status",
            description: "Get the effective sandbox state for one session.",
          }),
        ),
        HttpApiEndpoint.post("toggle", `${root}/toggle`, {
          params: { sessionID: SessionID },
          query: WorkspaceRoutingQuery,
          success: described(SandboxStatus, "Updated session sandbox status"),
          error: ApiNotFoundError,
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "sandbox.toggle",
            summary: "Toggle session sandbox",
            description: "Toggle and persist the sandbox state for one session.",
          }),
        ),
        HttpApiEndpoint.post("gate", `${root}/gate`, {
          params: { sessionID: SessionID },
          query: WorkspaceRoutingQuery,
          payload: SandboxGatePayload,
          success: described(SandboxStatus, "Resolved session sandbox gate status"),
          error: ApiNotFoundError,
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "sandbox.gate",
            summary: "Resolve the sandbox host gate",
            description:
              "Resolve a host-gate refusal for one session: abort, or continue unsandboxed with unmistakable signalling and an audit record of what would have been denied.",
          }),
        ),
        HttpApiEndpoint.post("relax", `${root}/relax`, {
          params: { sessionID: SessionID },
          query: WorkspaceRoutingQuery,
          payload: SandboxRelaxPayload,
          success: described(SandboxStatus, "Session sandbox status after the relaxation"),
          error: ApiNotFoundError,
        }).annotateMerge(
          OpenApi.annotations({
            identifier: "sandbox.relax",
            summary: "Grant a session relaxation",
            description:
              "Grant one relaxation for the current session — the surface the permission prompt and the PTY relaxation plug into. The grant is recorded in the session log with its source.",
          }),
        ),
      )
      .annotateMerge(OpenApi.annotations({ title: "sandbox", description: "Kilo session sandbox routes." }))
      .middleware(InstanceContextMiddleware)
      .middleware(WorkspaceRoutingMiddleware)
      .middleware(Authorization),
  )
  .annotateMerge(
    OpenApi.annotations({
      title: "kilo HttpApi",
      version: "0.0.1",
      description: "Kilo HttpApi surface.",
    }),
  )
