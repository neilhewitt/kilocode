export type { Profile } from "./profile"
export type { CidrPortRule, CidrPortSelector } from "@kilocode/mxc-sidecar"
export { assertWrite, enabled, run, unrestricted } from "./context"
export { decorateFileSystem, ensureDirectory } from "./filesystem"
export { assertNetwork, assertSandbox, decorateHttpClient, httpLayer as networkHttpLayer } from "./network"
export { batchMutations, mutate, withRunner, type Runner as MutationRunner } from "./mutation"
export type { Request as MutationRequest } from "./mutation-protocol"
export { backendSupport, prepareCommand } from "./backend"
export { mxcRuntime } from "./mxc"
export {
  ENFORCEMENT_FLOOR_DOC,
  ENFORCEMENT_FLOOR_TIER,
  OFF_PLATFORM_ASSESSMENT,
  assessPlatformSupport,
  deniedByProfile,
  probeMxcSupport,
  type GateAssessment,
  type GateDenials,
  type GateSource,
  type GateVerdict,
  type ProbeOptions,
} from "./probe"
export { isPublicAddress, normalizeDestinations, parseDestination } from "./destination"
export {
  normalizeCidrRules,
  resolveEgressPosture,
  STARTER_EGRESS_ALLOWLIST,
  type EgressPosture,
  type EgressPostureInput,
} from "./egress"
export { CurrentProxyFactory, startProxy, type ProxyFactory, type ProxyResolver } from "./proxy"
