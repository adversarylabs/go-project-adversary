import { lineSignals, positive } from "./signals.js";
import { type DomainDefinition } from "./types.js";

export const domain: DomainDefinition = {
  name: "go-project",
  displayName: "Go Project",
  observationKey: "go-project.analysis",
  sourceDescription: "Go project",
  includePath: (path) => path.endsWith(".go") || /(^|\/)go\.(?:mod|work)$/.test(path),
  rules: [
    {
      id: "go-project.mutable-global",
      title: "Package behavior depends on exported mutable global state",
      category: "maintainability",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} exported package variable${count === 1 ? "" : "s"} own mutable map, slice, or pointer state.`,
      whyItMatters: "Exported mutable globals erase ownership boundaries and let any importer change package behavior.",
      impact: "Tests, commands, and services become order-dependent and concurrent use requires coordination outside the package.",
      recommendation: "Move the state behind an explicitly constructed owner with narrow methods and injected lifetime.",
    },
    {
      id: "go-project.hidden-init",
      title: "Package initialization performs hidden work",
      category: "maintainability",
      severity: "medium",
      confidence: "medium",
      summary: (count) => `${count} init function${count === 1 ? "" : "s"} introduce implicit package lifecycle.`,
      whyItMatters: "Initialization runs on import, outside the caller's dependency, error, and cancellation model.",
      impact: "Startup behavior becomes difficult to test, order, disable, or recover from.",
      recommendation: "Prefer explicit construction or registration from the application boundary, especially for I/O and mutable state.",
    },
    {
      id: "go-project.catch-all-package",
      title: "A catch-all package obscures domain ownership",
      category: "maintainability",
      severity: "medium",
      confidence: "medium",
      summary: (count) => `${count} package declaration${count === 1 ? "" : "s"} use a generic ownership name.`,
      whyItMatters: "Names such as utils, common, and shared attract unrelated dependencies and make navigation depend on implementation trivia.",
      impact: "The package boundary becomes a coupling point rather than a coherent domain owner.",
      recommendation: "Place the behavior with the domain that owns its invariant, or name a package after the capability it provides.",
    },
  ],
  noRiskSummary: "The reviewed project changes preserve explicit ownership and understandable package boundaries.",
  approvalSummary: "I would approve the repository structure represented by the reviewed change.",
  analyze(file) {
    if (!file.path.endsWith(".go")) return { signals: [], positives: [] };
    return {
      signals: [
        ...lineSignals(
          file,
          "go-project.mutable-global",
          /^\s*var\s+([A-Z]\w*)\s*=\s*(?:map\[|\[\]|\&)/,
          (match) => `Exported variable ${match[1]} owns mutable package state.`,
          (match) => ({ symbol: match[1] }),
        ),
        ...lineSignals(file, "go-project.hidden-init", /^\s*func\s+init\s*\(\s*\)/, () => "This package performs work implicitly at import time."),
        ...lineSignals(
          file,
          "go-project.catch-all-package",
          /^\s*package\s+(utils?|common|shared|helpers?)\s*$/,
          (match) => `Package ${match[1]} has no domain-specific ownership boundary.`,
          (match) => ({ package: match[1] }),
        ),
      ],
      positives: [
        ...positive(file, "go-project-explicit-construction", /^\s*func\s+New[A-Z]\w*\s*\(/, "Package lifecycle is exposed through explicit construction."),
      ],
    };
  },
};
