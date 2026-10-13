import os from "node:os"

// The control channel is the authenticated IPC seam between the agent core and the
// sidecar (the TCB boundary). It deliberately lives in a pipe/socket namespace that
// can never collide with the loopback proxy the sidecar will own later: the proxy is
// a TCP port on 127.0.0.1, the control channel is a named pipe (Windows) or a
// user-scoped unix domain socket (everywhere else).
export const CONTROL_CHANNEL_PREFIX = "kilo-mxc-control"

export type EndpointOptions = { platform?: string; tmp?: string }

export function controlEndpoint(id: string, options: EndpointOptions = {}) {
  const platform = options.platform ?? process.platform
  if (platform === "win32") return `\\\\.\\pipe\\${CONTROL_CHANNEL_PREFIX}-${id}`
  const tmp = options.tmp ?? os.tmpdir()
  return `${tmp}/${CONTROL_CHANNEL_PREFIX}-${id}/sock`
}

export function isTcpStyleEndpoint(endpoint: string) {
  return /^(\d{1,3}(\.\d{1,3}){3}|[\w.-]+):\d+$/.test(endpoint)
}
