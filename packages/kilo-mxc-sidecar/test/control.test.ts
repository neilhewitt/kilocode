import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { createControlServer } from "../src/control.ts"
import type { Runtime } from "../src/sdk.ts"
import { generateToken } from "../src/auth.ts"
import { controlEndpoint } from "../src/endpoint.ts"
import { connect, until } from "./wire.ts"

function scripted(): Runtime {
  return {
    getPlatformSupport: async () => ({
      isSupported: true,
      availableMethods: ["processcontainer", "hyperlight"],
      isolationTier: "base-container",
    }),
    run: async () => ({
      wait: () => Promise.resolve({ exitCode: 0, stdout: "", stderr: "", timedOut: false, warnings: [] }),
      kill: () => {},
    }),
  }
}

function id() {
  return Math.random().toString(16).slice(2, 10)
}

describe("control server contract", () => {
  test("handshake round-trips over the authenticated control channel", async () => {
    const token = generateToken()
    const server = createControlServer({ runtime: scripted(), endpoint: controlEndpoint(id()), token })
    await server.listen()
    try {
      const wire = await connect(server.endpoint)
      wire.send({ id: 1, method: "handshake", token })
      const response = JSON.parse(await wire.next())
      assert.equal(response.ok, true)
      assert.equal(response.id, 1)
      assert.equal(response.result.protocol, 1)
      assert.equal(response.result.channel, "control")
      wire.socket.destroy()
    } finally {
      await server.close()
    }
  })

  test("rejects a handshake with a wrong token", async () => {
    const server = createControlServer({ runtime: scripted(), endpoint: controlEndpoint(id()), token: generateToken() })
    await server.listen()
    try {
      const wire = await connect(server.endpoint)
      wire.send({ id: 7, method: "handshake", token: "not-the-token" })
      const response = JSON.parse(await wire.next())
      assert.equal(response.ok, false)
      assert.equal(response.error.code, "unauthorized")
      await until(() => wire.closed)
    } finally {
      await server.close()
    }
  })

  test("rejects requests made before a successful handshake", async () => {
    const server = createControlServer({ runtime: scripted(), endpoint: controlEndpoint(id()), token: generateToken() })
    await server.listen()
    try {
      const wire = await connect(server.endpoint)
      wire.send({ id: 1, method: "platformSupport" })
      const response = JSON.parse(await wire.next())
      assert.equal(response.ok, false)
      assert.equal(response.error.code, "unauthorized")
      await until(() => wire.closed)
    } finally {
      await server.close()
    }
  })

  test("passes the platform-support query through to the runtime unchanged", async () => {
    const token = generateToken()
    const server = createControlServer({ runtime: scripted(), endpoint: controlEndpoint(id()), token })
    await server.listen()
    try {
      const wire = await connect(server.endpoint)
      wire.send({ id: 1, method: "handshake", token })
      await wire.next()
      wire.send({ id: 2, method: "platformSupport" })
      const response = JSON.parse(await wire.next())
      assert.equal(response.ok, true)
      assert.equal(response.id, 2)
      assert.deepEqual(response.result, {
        isSupported: true,
        availableMethods: ["processcontainer", "hyperlight"],
        isolationTier: "base-container",
      })
      wire.socket.destroy()
    } finally {
      await server.close()
    }
  })

  test("answers an unknown method with a typed error and keeps the connection", async () => {
    const token = generateToken()
    const server = createControlServer({ runtime: scripted(), endpoint: controlEndpoint(id()), token })
    await server.listen()
    try {
      const wire = await connect(server.endpoint)
      wire.send({ id: 1, method: "handshake", token })
      await wire.next()
      wire.send({ id: 2, method: "runCommand" })
      const response = JSON.parse(await wire.next())
      assert.equal(response.ok, false)
      assert.equal(response.error.code, "unknown_method")
      wire.send({ id: 3, method: "platformSupport" })
      const still = JSON.parse(await wire.next())
      assert.equal(still.ok, true)
      assert.equal(still.id, 3)
      wire.socket.destroy()
    } finally {
      await server.close()
    }
  })

  test("authorises a request pipelined directly behind its handshake", async () => {
    const token = generateToken()
    const server = createControlServer({ runtime: scripted(), endpoint: controlEndpoint(id()), token })
    await server.listen()
    try {
      const wire = await connect(server.endpoint)
      wire.socket.write(
        JSON.stringify({ id: 1, method: "handshake", token }) + "\n" + JSON.stringify({ id: 2, method: "platformSupport" }) + "\n",
      )
      const handshake = JSON.parse(await wire.next())
      assert.equal(handshake.ok, true)
      const response = JSON.parse(await wire.next())
      assert.equal(response.ok, true)
      assert.equal(response.id, 2)
      assert.equal(response.result.isolationTier, "base-container")
      wire.socket.destroy()
    } finally {
      await server.close()
    }
  })

  test("scopes the socket to the owning user on POSIX", { skip: process.platform === "win32" }, async () => {
    const token = generateToken()
    const endpoint = controlEndpoint(id())
    const server = createControlServer({ runtime: scripted(), endpoint, token })
    await server.listen()
    try {
      const fs = await import("node:fs")
      const mode = fs.statSync(server.endpoint).mode & 0o777
      assert.equal(mode, 0o600, "socket must be readable and writable by the owning user only")
      const dir = fs.statSync(endpoint.slice(0, endpoint.lastIndexOf("/"))).mode & 0o777
      assert.equal(dir, 0o700, "socket directory must be private to the owning user")
    } finally {
      await server.close()
    }
  })
})

