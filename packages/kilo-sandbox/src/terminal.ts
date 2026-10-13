// The terminal-handling decision surface (ADR 0004). The MXC engine refuses
// PTY spawning on the processcontainer backend — the SDK's TS plumbing calls
// spawnWithPty, the native engine rejects it with `unsupported_containment` —
// so while a Kilo sandbox session can confine a terminal, that terminal cannot
// also be a real PTY. Every confined command therefore runs through the pipes
// fallback from the same run contract: TTY-dependent behaviour is unavailable
// and the degradation is signalled. A genuinely-TTY-needed terminal is granted
// only as an explicit, recorded PTY relaxation, which runs it unsandboxed.
//
// Upstream revisit trigger (durable, where the fallback decides): when the
// MXC engine ships PTY spawning for the processcontainer backend, the pipes
// fallback should hand over to an engine-side PTY and conpty-aware resizing.
export const PTY_REVISIT_TRIGGER =
  "Revisit when upstream MXC ships PTY spawning for the processcontainer backend: the SDK's TS plumbing exists " +
  "(spawnWithPty on the v1 API) but the native engine refuses it on this backend with `unsupported_containment`, " +
  "so the pipes fallback — confined commands through the run contract with no TTY — is the engine-legal posture " +
  "(ADR 0004). A confirmed TTY need is served only by an explicit, recorded PTY relaxation running the terminal unsandboxed."

// The degradation signal: what a consumer surfaces when a command or session
// terminal runs confined through the pipes fallback instead of a real terminal.
export const PIPES_FALLBACK_SIGNAL =
  "TERMINAL CONFINED — pipes fallback: no TTY (PTY spawning unsupported on the sandbox engine; " +
  "input and resize are unavailable — grant a terminal relaxation for a real terminal)"

export type TerminalDecision =
  | { readonly mode: "pipes-fallback"; readonly signal: string }
  | { readonly mode: "unsandboxed-pty" }

export function terminalDecision(state: { readonly confinementActive: boolean; readonly terminalRelaxed: boolean }): TerminalDecision {
  if (state.terminalRelaxed) return { mode: "unsandboxed-pty" }
  if (!state.confinementActive) return { mode: "unsandboxed-pty" }
  return {
    mode: "pipes-fallback",
    signal: PIPES_FALLBACK_SIGNAL,
  }
}

// The Proc-shaped front of a pipes-fallback command: what the core PTY
// registry, terminal presenter, and teardown paths see. Structurally the same
// contract node-pty drivers satisfy (`pid`, `onData`, `onExit`, `write`,
// `resize`, `kill`) so a pipes-backed session terminal slots into the existing
// terminal machinery unchanged. Confinement semantics are the difference:
// `write` and `resize` are no-ops (pipes carry no input and no cell grid),
// `kill` is the launcher's job-object tree kill, and output is `emit`-driven.
export type PipesTty = {
  readonly pid: number
  readonly onData: (listener: (data: string) => void) => { dispose(): void }
  readonly onExit: (listener: (event: { exitCode: number; signal?: number | string }) => void) => { dispose(): void }
  readonly write: (data: string) => void
  readonly resize: (cols: number, rows: number) => void
  readonly kill: (signal?: string) => void
  // The confined-run driver calls these as output arrives and the run exits.
  readonly emit: (stream: "stdout" | "stderr", data: Uint8Array) => void
  readonly emitExit: (exit: { readonly exitCode?: number | undefined }) => void
}

export function pipesTty(view: { readonly pid?: number | undefined; readonly kill?: (signal?: string) => void }): PipesTty {
  const outputListeners = new Set<(data: string) => void>()
  const exitListeners = new Set<(event: { exitCode: number; signal?: number | string }) => void>()
  let decoder: TextDecoder | undefined
  let exited = false

  return {
    pid: typeof view.pid === "number" ? view.pid : 0,
    onData(listener) {
      outputListeners.add(listener)
      return { dispose: () => outputListeners.delete(listener) }
    },
    onExit(listener) {
      exitListeners.add(listener)
      return { dispose: () => exitListeners.delete(listener) }
    },
    // Deliberately degraded (signal explains it): a confined pipes terminal
    // carries no input. Typed data goes nowhere; the banner is what tells
    // the user why.
    write: () => {},
    resize: () => {},
    kill: (signal?: string) => view.kill?.(signal),
    emit: (_stream, data) => {
      if (outputListeners.size === 0) return
      // Chunk-safe transform: kernel bytes arrive across listener boundaries,
      // decode with stream continuity.
      const streaming = (decoder ??= new TextDecoder())
      const decoded = streaming.decode(data)
      for (const listener of outputListeners) listener(decoded)
    },
    emitExit: (exit) => {
      if (exited) return
      exited = true
      const event = { exitCode: exit.exitCode ?? 0 }
      for (const listener of exitListeners) listener(event)
    },
  }
}
