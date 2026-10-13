// Wire contract for the sidecar control channel. Newline-delimited JSON: one
// request per line, one response per line, matched by id. The first request on
// every connection must be a successful handshake carrying the control token;
// anything else is refused and the connection dropped.

export const PROTOCOL_VERSION = 1

// The wire shape after structural validation. `method` stays a string so unknown
// methods can be answered with a typed `unknown_method` error instead of slipping
// through validation.
export type Request = {
  id: number
  method: string
  token?: string
}

export type Response =
  | { id: number; ok: true; result: unknown }
  | { id: number; ok: false; error: { code: ErrorCode; message: string } }

export type ErrorCode = "unauthorized" | "unknown_method" | "invalid_request" | "internal_error"

export function isRequest(value: unknown): value is Request {
  if (typeof value !== "object" || value === null) return false
  const request = value as Record<string, unknown>
  if (typeof request.id !== "number" || typeof request.method !== "string") return false
  return request.method !== "handshake" || typeof request.token === "string"
}

export function error(id: number, code: ErrorCode, message: string): Response {
  return { id, ok: false, error: { code, message } }
}

export function ok(id: number, result: unknown): Response {
  return { id, ok: true, result }
}
