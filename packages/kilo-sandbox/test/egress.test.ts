import { describe, test } from "node:test"
import assert from "node:assert/strict"
import { normalizeDestinations, parseDestination } from "../src/destination.ts"
import { normalizeCidrRules, resolveEgressPosture, STARTER_EGRESS_ALLOWLIST } from "../src/egress.ts"

// The egress policy vocabulary (ADR 0003): a named, default-on starter
// allowlist trimmable to deny-all in one edit, and raw CIDR/port rules that
// exist only as explicit recorded relaxations for non-HTTP egress.

describe("starter egress allowlist", () => {
  test("names the major package registries and git-over-HTTPS hosts, pre-normalised", () => {
    const names = STARTER_EGRESS_ALLOWLIST.join(" ")
    assert.match(names, /registry\.npmjs\.org:443/, "npm")
    assert.match(names, /api\.nuget\.org:443/, "NuGet")
    assert.match(names, /pypi\.org:443/, "PyPI")
    assert.match(names, /files\.pythonhosted\.org:443/, "PyPI packages")
    assert.match(names, /static\.crates\.io:443/, "cargo downloads")
    assert.match(names, /index\.crates\.io:443/, "cargo sparse index")
    assert.match(names, /github\.com:443/, "git-over-HTTPS")
    assert.match(names, /gitlab\.com:443/, "git-over-HTTPS")
    for (const entry of STARTER_EGRESS_ALLOWLIST) {
      assert.equal(parseDestination(entry).authority, entry, `${entry} must already be a normalised authority`)
    }
    assert.deepEqual(normalizeDestinations([...STARTER_EGRESS_ALLOWLIST]), [...STARTER_EGRESS_ALLOWLIST])
  })
})

describe("cidr relaxation validation", () => {
  test("accepts valid v4 and v6 CIDRs and passes rules through", () => {
    const rules = [{ to: ["10.0.0.0/8"], ports: [{ protocol: "tcp", port: 22 }] }] as const
    assert.deepEqual(normalizeCidrRules(rules), [{ to: ["10.0.0.0/8"], ports: [{ protocol: "tcp", port: 22 }] }])
    assert.deepEqual(normalizeCidrRules([{ to: ["2001:db8::/32"] }]), [{ to: ["2001:db8::/32"] }])
  })

  test("normalises a bare address to its single-host CIDR", () => {
    assert.deepEqual(normalizeCidrRules([{ to: ["140.82.112.4"] }]), [{ to: ["140.82.112.4/32"] }])
    assert.deepEqual(normalizeCidrRules([{ to: ["2607:7c80:54:3::251"] }]), [{ to: ["2607:7c80:54:3::251/128"] }])
  })

  test("accepts port ranges and omitted ports (every port)", () => {
    assert.deepEqual(
      normalizeCidrRules([{ to: ["10.0.0.0/8"], ports: [{ protocol: "udp", port: 53, endPort: 55 }] }]),
      [{ to: ["10.0.0.0/8"], ports: [{ protocol: "udp", port: 53, endPort: 55 }] }],
    )
    assert.deepEqual(normalizeCidrRules([{ to: ["10.0.0.0/8"] }]), [{ to: ["10.0.0.0/8"] }])
  })

  test("rejects malformed or empty destinations", () => {
    assert.throws(() => normalizeCidrRules([{ to: ["not-a-cidr"] }]))
    assert.throws(() => normalizeCidrRules([{ to: ["10.0.0.0/33"] }]))
    assert.throws(() => normalizeCidrRules([{ to: [] }]))
  })

  test("rejects invalid protocols and port ranges", () => {
    const bogus = { protocol: "sctp", port: 1 } as unknown as import("@kilocode/mxc-sidecar").CidrPortSelector
    assert.throws(() => normalizeCidrRules([{ to: ["10.0.0.0/8"], ports: [bogus] }]))
    assert.throws(() => normalizeCidrRules([{ to: ["10.0.0.0/8"], ports: [{ protocol: "tcp", port: 0 }] }]))
    assert.throws(() => normalizeCidrRules([{ to: ["10.0.0.0/8"], ports: [{ protocol: "tcp", port: 70000 }] }]))
    assert.throws(() => normalizeCidrRules([{ to: ["10.0.0.0/8"], ports: [{ protocol: "tcp", port: 100, endPort: 50 }] }]))
    assert.throws(() => normalizeCidrRules([{ to: ["10.0.0.0/8"], ports: [] }]))
  })
})

describe("egress posture resolution", () => {
  test("an allow network is unrestricted regardless of hosts", () => {
    assert.deepEqual(resolveEgressPosture({ network: "allow", allowedHosts: ["example.com:443"] }), {
      mode: "allow",
      allowedHosts: [],
    })
  })

  test("an explicit deny network is deny-all in one edit", () => {
    assert.deepEqual(resolveEgressPosture({ network: "deny" }), { mode: "deny", allowedHosts: [] })
    assert.deepEqual(resolveEgressPosture({ network: "deny", allowedHosts: ["example.com:443"] }), {
      mode: "deny",
      allowedHosts: [],
    })
  })

  test("an explicitly empty host list trims to deny-all in one edit", () => {
    assert.deepEqual(resolveEgressPosture({ allowedHosts: [] }), { mode: "deny", allowedHosts: [] })
  })

  test("unset restricted hosts get the starter allowlist by default", () => {
    assert.deepEqual(resolveEgressPosture({}), { mode: "proxy", allowedHosts: [...STARTER_EGRESS_ALLOWLIST] })
    assert.deepEqual(resolveEgressPosture({ network: undefined }), {
      mode: "proxy",
      allowedHosts: [...STARTER_EGRESS_ALLOWLIST],
    })
  })

  test("an explicit host list is honoured as given", () => {
    assert.deepEqual(resolveEgressPosture({ allowedHosts: ["Api.GitHub.com:443", "example.com"] }), {
      mode: "proxy",
      allowedHosts: ["api.github.com:443", "example.com:443"],
    })
  })
})
