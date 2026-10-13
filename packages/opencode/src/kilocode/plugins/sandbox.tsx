import type { TuiPlugin, TuiPluginApi, TuiPluginModule } from "@kilocode/plugin/tui"
import { createEffect, createSignal, on, type Accessor } from "solid-js"

const id = "internal:sandbox"

type Status = {
  directory: string
  enabled: boolean
  available: boolean
  reason?: string
  diagnostics?: string[]
  unsandboxed?: boolean
  audit?: boolean
  version: number
}

export function indicator(status?: Status) {
  if (status?.enabled) return "◆ Sandbox on"
  if (status?.audit) return "△ AUDIT — UNSANDBOXED"
  if (status?.unsandboxed) return "△ UNSANDBOXED"
  return undefined
}

function session(api: TuiPluginApi) {
  if (api.route.current.name !== "session") return
  const sessionID = api.route.current.params?.sessionID
  if (typeof sessionID !== "string") return
  return sessionID
}

async function ensureSession(api: TuiPluginApi) {
  const current = session(api)
  if (current) return current
  const result = await api.client.session.create({}, { throwOnError: true })
  const sessionID = result.data?.id
  if (sessionID) api.route.navigate("session", { sessionID })
  return sessionID
}

// The sandbox routes' base URL and headers. The typed SDK client gains the
// gate and relax endpoints at the next sdk regeneration; until then the calls
// ride the client's own connection config so auth and base URL stay correct.
function sandboxRoute(api: TuiPluginApi) {
  const client = (api.client as unknown as {
    client: { getConfig: () => { baseUrl?: string; headers?: Record<string, string> } }
  }).client.getConfig()
  const baseUrl = client.baseUrl?.replace(/\/$/, "")
  if (!baseUrl) throw new Error("cannot reach the sandbox routes without a server connection")
  return { baseUrl, headers: client.headers }
}

// Resolves a host-gate refusal through the sandbox gate route.
async function resolveGate(api: TuiPluginApi, sessionID: string, choice: "abort" | "continue-unsandboxed") {
  const route = sandboxRoute(api)
  const response = await fetch(`${route.baseUrl}/session/${encodeURIComponent(sessionID)}/sandbox/gate`, {
    method: "POST",
    headers: { "content-type": "application/json", ...route.headers },
    body: JSON.stringify({ choice }),
  })
  if (!response.ok) throw new Error(`sandbox gate resolution failed: ${response.status} ${await response.text()}`)
  return (await response.json()) as Status
}

// Grants a relaxation through the session relax seam (the surface the
// permission prompt and the PTY surface plug into as well). The request is
// posted as-is; the seam validates it and records the grant in the session
// log with its source ("prompt"), so this dialog only ever supplies the
// request — never a record.
async function applyRelaxation(api: TuiPluginApi, sessionID: string, request: unknown) {
  const route = sandboxRoute(api)
  const response = await fetch(`${route.baseUrl}/session/${encodeURIComponent(sessionID)}/sandbox/relax`, {
    method: "POST",
    headers: { "content-type": "application/json", ...route.headers },
    body: JSON.stringify(request),
  })
  if (!response.ok) throw new Error(`sandbox relaxation failed: ${response.status} ${await response.text()}`)
  return (await response.json()) as Status
}

function View(props: {
  api: TuiPluginApi
  sessionID: string
  status: Accessor<ReadonlyMap<string, Status>>
  load: (sessionID: string, force?: boolean) => Promise<void>
}) {
  createEffect(
    on(
      () => props.api.state.config.sandbox?.enabled,
      () => void props.load(props.sessionID, true),
    ),
  )
  const colour = () => {
    const current = props.status().get(props.sessionID)
    if (current?.enabled) return props.api.theme.current.success
    if (current?.audit || current?.unsandboxed) return props.api.theme.current.warning
    return props.api.theme.current.success
  }
  return (
    <box flexShrink={0}>
      <text fg={colour()}>{indicator(props.status().get(props.sessionID)) ?? ""}</text>
    </box>
  )
}

const tui: TuiPlugin = async (api) => {
  const [status, setStatus] = createSignal<ReadonlyMap<string, Status>>(new Map())
  const pending = new Set<string>()
  const loads = new Map<string, symbol>()
  const commit = (sessionID: string, value: Status) => {
    const next = new Map(status())
    next.set(sessionID, value)
    setStatus(next)
  }
  const set = (sessionID: string, value: Status) => {
    loads.delete(sessionID)
    commit(sessionID, value)
  }
  const load = async (sessionID: string, force = false) => {
    if (!force && status().has(sessionID)) return
    const token = Symbol()
    loads.set(sessionID, token)
    try {
      const result = await api.client.sandbox.status({ sessionID }, { throwOnError: true })
      if (result.data && loads.get(sessionID) === token) commit(sessionID, result.data)
    } catch (err) {
      api.ui.toast({ message: String(err), variant: "error", duration: 5000 })
    } finally {
      if (loads.get(sessionID) === token) loads.delete(sessionID)
    }
  }
  const changed = api.event.on("sandbox.status.changed", (event) => set(event.properties.sessionID, event.properties))
  api.lifecycle.onDispose(changed)

  const offerGateChoice = (sessionID: string, refused: Status) => {
    const details = () => (
      <box>
        <text fg={api.theme.current.error}>{refused.reason ?? "Sandbox backend is unavailable"}</text>
        {refused.diagnostics?.map((line) => <text fg={api.theme.current.warning}>{line}</text>)}
      </box>
    )
    api.ui.dialog.replace(
      () => (
        <api.ui.Dialog onClose={() => api.ui.dialog.clear()}>
          {details()}
          <api.ui.DialogSelect
            title="This host cannot enforce the sandbox"
            skipFilter={true}
            options={[
              {
                title: "Abort the sandboxed session",
                description: "Stay unsandboxed-off: nothing was enabled, nothing is pending.",
                value: "abort",
              },
              {
                title: "Continue unsandboxed",
                description:
                  "Run this session without OS containment — unmistakably signalled, with the denials you lose recorded in the audit log.",
                value: "continue-unsandboxed",
              },
            ]}
            onSelect={async (option) => {
              api.ui.dialog.clear()
              const choice = option.value as "abort" | "continue-unsandboxed"
              try {
                const value = await resolveGate(api, sessionID, choice)
                set(sessionID, value)
                api.ui.toast({
                  message:
                    choice === "abort"
                      ? "Sandboxed session aborted — sandbox stays off"
                      : "RUNNING UNSANDBOXED — denials recorded in the audit log",
                  variant: choice === "abort" ? "info" : "warning",
                  duration: 8000,
                })
              } catch (err) {
                api.ui.toast({ message: String(err), variant: "error", duration: 5000 })
              }
            }}
          />
        </api.ui.Dialog>
      ),
      () => api.ui.dialog.clear(),
    )
  }

  // Offers the relaxation kinds the session can grant through the relax seam:
  // a path grant (read or write, typed by the user) or the PTY terminal kind.
  // Every grant lands on SandboxPolicy.relax and is recorded with source
  // "prompt"; an identical grant composes once. Grants are session-only —
  // they never seed the next session or touch durable config.
  const offerRelaxation = (sessionID: string) => {
    const grant = async (request: unknown) => {
      api.ui.dialog.clear()
      try {
        const value = await applyRelaxation(api, sessionID, request)
        set(sessionID, value)
        api.ui.toast({
          message: "Relaxation granted for this session — recorded in the session log",
          variant: "warning",
          duration: 8000,
        })
      } catch (err) {
        api.ui.toast({ message: String(err), variant: "error", duration: 5000 })
      }
    }
    api.ui.dialog.replace(
      () => (
        <api.ui.Dialog onClose={() => api.ui.dialog.clear()}>
          <api.ui.DialogSelect
            title="Grant a sandbox relaxation (session-only)"
            skipFilter={true}
            options={[
              {
                title: "Read a directory",
                description: "Grant read access to one directory for this session only.",
                value: "read",
              },
              {
                title: "Write a directory",
                description: "Grant read-write access to one directory for this session only.",
                value: "write",
              },
              {
                title: "Real PTY for the next terminal",
                description: "Bless one new terminal spawn to run unsandboxed, then the grant is spent.",
                value: "terminal",
              },
            ]}
            onSelect={async (option) => {
              const kind = option.value as "read" | "write" | "terminal"
              if (kind === "terminal") return void grant({ kind: "terminal" })
              api.ui.dialog.replace(
                () => (
                  <api.ui.Dialog onClose={() => api.ui.dialog.clear()}>
                    <api.ui.DialogPrompt
                      title={kind === "read" ? "Directory to grant read access" : "Directory to grant read-write access"}
                      placeholder="C:\Users\you\project"
                      onConfirm={(value) => void grant({ kind: "path", access: kind, path: value })}
                      onCancel={() => api.ui.dialog.clear()}
                    />
                  </api.ui.Dialog>
                ),
                () => api.ui.dialog.clear(),
              )
            }}
          />
        </api.ui.Dialog>
      ),
      () => api.ui.dialog.clear(),
    )
  }

  api.keymap.registerLayer({
    commands: [
      {
        namespace: "palette",
        name: "session.toggle.sandbox",
        title: "Toggle sandbox",
        category: "Session",
        slashName: "sandbox",
        async run() {
          const sessionID = await ensureSession(api)
          if (!sessionID || pending.has(sessionID)) return
          pending.add(sessionID)
          try {
            const result = await api.client.sandbox.toggle({ sessionID }, { throwOnError: true })
            const value = result.data
            if (!value) return
            set(sessionID, value)
            if (!value.enabled && !value.available) {
              offerGateChoice(sessionID, value)
              return
            }
            api.ui.toast({ message: `Sandbox ${value.enabled ? "enabled" : "disabled"}`, variant: "success" })
            api.ui.dialog.clear()
          } catch (err) {
            api.ui.toast({ message: String(err), variant: "error", duration: 5000 })
          } finally {
            pending.delete(sessionID)
          }
        },
      },
      {
        namespace: "palette",
        name: "session.sandbox.relax",
        title: "Grant sandbox relaxation",
        category: "Session",
        slashName: "sandbox-relax",
        async run() {
          const sessionID = await ensureSession(api)
          if (!sessionID) return
          offerRelaxation(sessionID)
        },
      },
    ],
  })

  api.slots.register({
    order: 50,
    slots: {
      session_prompt_right(_ctx, props) {
        return <View api={api} sessionID={props.session_id} status={status} load={load} />
      },
    },
  })
}

const plugin: TuiPluginModule & { id: string } = { id, tui }
export default plugin
