import fs from "node:fs"

// Records observable runtime activity so contract tests can assert what the
// sidecar actually did (started a run, killed it) from outside the process.
function event(entry) {
  const file = process.env.KILO_MXC_SCRIPT_EVENTS
  if (!file) return
  fs.appendFileSync(file, JSON.stringify(entry) + "\n")
}

export function createRuntime() {
  return {
    getPlatformSupport: async () => ({
      isSupported: true,
      availableMethods: ["processcontainer", "hyperlight"],
      isolationTier: "base-container",
      source: "scripted",
    }),
    run: async (command, bindings) => {
      event({ type: "run", command, bindings: bindings ?? {} })
      const canned = JSON.parse(process.env.KILO_MXC_SCRIPT_RESULT ?? "{}")
      const result = {
        exitCode: canned.exitCode ?? 0,
        stdout: canned.stdout ?? "",
        stderr: canned.stderr ?? "",
        timedOut: canned.timedOut ?? false,
        warnings: canned.warnings ?? [],
      }
      if (process.env.KILO_MXC_SCRIPT_HANG === "1") {
        return {
          wait: () => new Promise(() => {}),
          kill: () => event({ type: "kill" }),
        }
      }
      return {
        wait: () => Promise.resolve(result),
        kill: () => event({ type: "kill" }),
      }
    },
  }
}
