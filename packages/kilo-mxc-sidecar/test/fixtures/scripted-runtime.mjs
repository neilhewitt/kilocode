export function createRuntime() {
  return {
    getPlatformSupport: async () => ({
      isSupported: true,
      availableMethods: ["processcontainer", "hyperlight"],
      isolationTier: "base-container",
      source: "scripted",
    }),
  }
}
