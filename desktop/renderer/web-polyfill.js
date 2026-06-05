// Web fallback for Electron APIs when running in browser preview
if (typeof window !== "undefined" && !window.ctfCompass) {
  window.ctfCompass = {
    pickFiles: async () => {
      return new Promise((resolve) => {
        const input = document.createElement("input");
        input.type = "file";
        input.multiple = true;
        input.onchange = async () => {
          const files = Array.from(input.files || []);
          const paths = files.map((f) => f.name);
          resolve(paths);
        };
        input.click();
      });
    },
    pickFolder: async () => {
      return new Promise((resolve) => {
        const input = document.createElement("input");
        input.type = "file";
        input.webkitdirectory = true;
        input.onchange = async () => {
          const files = Array.from(input.files || []);
          const paths = files.map((f) => f.webkitRelativePath || f.name);
          resolve(paths);
        };
        input.click();
      });
    },
    prepareArtifacts: async (paths) => {
      // Return mock artifact data for web preview
      return paths.map((p, i) => ({
        path: p,
        name: p.split("/").pop() || p,
        size: 1024 * (i + 1),
        family: "binary",
        ext: p.split(".").pop() || "",
      }));
    },
    analyzeChallenge: async (payload) => {
      // Return mock analysis result for web preview
      return {
        category: "misc",
        confidence: 0.75,
        summary: "Web preview mode - analysis requires Electron runtime",
        flagCandidates: [],
        nextSteps: ["Run in Electron for full analysis"],
        findings: [],
        tools: [],
        pipeline: [],
        failures: [],
      };
    },
    runArtifactAction: async () => ({
      success: false,
      message: "Actions require Electron runtime",
    }),
    revealArtifact: async () => {},
    loadWorkspace: async () => null,
    loadPreviousWorkspace: async () => null,
    saveWorkspace: async () => {},
    clearWorkspace: async () => {},
    getSandboxInfo: async () => ({
      path: "(Web Preview)",
      size: "N/A",
    }),
    revealSandbox: async () => {},
    clearSandbox: async () => {},
    exportReport: async () => ({
      success: false,
      message: "Export requires Electron runtime",
    }),
    getMeta: async () => ({
      electron: "Web Preview",
      node: "N/A",
      chrome: navigator.userAgent,
      platform: navigator.platform,
    }),
  };
}
