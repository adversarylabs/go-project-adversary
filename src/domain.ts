import { lineSignals, positive } from "./signals.js";
import { type DomainDefinition, type Signal, type SourceRevision } from "./types.js";

/** Repository hygiene paths for Go project integrity review. */
export function includePath(path: string): boolean {
  if (path.endsWith(".go")) return true;
  if (/(^|\/)go\.(?:mod|work)$/.test(path)) return true;
  if (/(^|\/)(?:[Mm]akefile|GNUmakefile|Taskfile\.ya?ml)$/.test(path)) return true;
  if (/\.sh$/.test(path)) return true;
  if (isPrerequisiteDocument(path)) return true;
  if (/(^|\/)\.github\/workflows\/.+\.ya?ml$/.test(path)) return true;
  if (/(^|\/)\.gitlab-ci\.ya?ml$/.test(path)) return true;
  if (/(^|\/)(?:LICENSE|COPYING|LICENCE)(?:$|\.)/i.test(path)) return true;
  if (/(^|\/)\.gitignore$/.test(path)) return true;
  // Editor / OS junk (text forms) and IDE metadata.
  if (/(^|\/)\.DS_Store$/.test(path)) return true;
  if (/(^|\/)\.idea\//.test(path)) return true;
  if (/\.(?:swp|swo)$/.test(path)) return true;
  if (/(^|\/)Thumbs\.db$/i.test(path)) return true;
  if (/\.exe$/i.test(path)) return true;
  return false;
}

export const domain: DomainDefinition = {
  // Catalog / package identity uses domain/name taxonomy.
  name: "go/project",
  displayName: "Go Project",
  observationKey: "go-project.analysis",
  sourceDescription: "Go project",
  includePath,
  rules: [
    {
      id: "go-project.script-curl-bash",
      title: "Build tooling pipes remote content to a shell",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) =>
        `${count} build script site${count === 1 ? "" : "s"} pipe remote content into a shell.`,
      whyItMatters:
        "curl|sh in Makefiles and bootstrap scripts executes attacker-controllable content on every dev machine and CI runner.",
      impact: "Compromised installer endpoints run arbitrary code with developer and CI privileges.",
      recommendation:
        "Download to a file, verify sha256, then execute; pin tool versions (`go install tool@v1.2.3`).",
    },
    {
      id: "go-project.unpinned-go-install",
      title: "Go build tooling installs a mutable remote tool version",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) =>
        count === 1
          ? "A remote Go tool install lacks an immutable version or SHA pin."
          : `${count} remote Go tool installs lack immutable version or SHA pins.`,
      whyItMatters:
        "Unpinned go install commands make developer and CI tooling depend on whatever upstream serves at install time.",
      impact: "Tool behavior can drift unexpectedly or pick up a compromised upstream revision.",
      recommendation:
        "Pin the tool to an explicit semantic version, pseudo-version, or commit revision.",
    },
    {
      id: "go-project.committed-binary",
      title: "A compiled executable is committed to the repository",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) =>
        `${count} committed binary path${count === 1 ? "" : "s"} are unreviewable supply-chain risk.`,
      whyItMatters: "Opaque binaries in git are unreviewable and bloat every clone forever.",
      impact: "Malicious payloads hide in committed Mach-O/ELF/PE that nobody diffs.",
      recommendation:
        "Delete and build from source; use release artifacts or git-lfs for unavoidable blobs.",
    },
    {
      id: "go-project.ci-toolchain-skew",
      title: "CI builds with a different Go version than the module",
      category: "reliability",
      severity: "high",
      confidence: "high",
      summary: (count) =>
        `${count} CI toolchain declaration${count === 1 ? "" : "s"} diverge from go.mod.`,
      whyItMatters:
        "Version-gated language behavior silently differs between what CI tests and what you ship.",
      impact: "Passes CI, fails locally (or the reverse) with loopvar/timer differences.",
      recommendation: "Point CI at go.mod (`go-version-file: go.mod`) instead of duplicating the version.",
    },
    {
      id: "go-project.editor-junk",
      title: "Editor or OS junk is tracked in the repository",
      category: "maintainability",
      severity: "low",
      confidence: "high",
      summary: (count) =>
        `${count} editor/OS junk path${count === 1 ? "" : "s"} are committed.`,
      whyItMatters: "Noise in diffs and occasional local-path leakage; universally unwanted.",
      impact: "Cluttered reviews and accidental machine-specific metadata in history.",
      recommendation: "Remove and add patterns to .gitignore.",
    },
    {
      id: "go-project.license-missing",
      title: "Published module has no LICENSE file",
      category: "maintainability",
      severity: "low",
      confidence: "high",
      summary: (count) =>
        count === 1
          ? "A public module path has no LICENSE/COPYING at the repository root."
          : `${count} public modules lack a LICENSE file.`,
      whyItMatters: "Legally unusable by most companies; pkg.go.dev needs a recognized license.",
      impact: "Consumers cannot adopt the module under standard open-source policy.",
      recommendation: "Add a LICENSE file at the repository root.",
    },
    {
      id: "go-project.undocumented-cli-prerequisite",
      title: "A repository script depends on an undocumented external CLI",
      category: "maintainability",
      severity: "low",
      confidence: "high",
      summary: (count) =>
        count === 1
          ? "A changed repository script requires an external CLI that its prerequisite documentation omits."
          : `${count} changed repository script dependencies are missing from prerequisite documentation.`,
      whyItMatters:
        "Contributors cannot reliably run repository scripts when required nonstandard tools are absent from the setup instructions.",
      impact: "Local build or generation commands fail until contributors discover and install the missing tool.",
      recommendation:
        "List the required CLI in README, CONTRIBUTING, or prerequisite documentation, or vendor the tool behind a repository-relative command.",
    },
  ],
  noRiskSummary:
    "The reviewed project tooling avoids pipe-to-shell, binary commits, and toolchain skew.",
  approvalSummary: "I would approve the repository hygiene represented by the reviewed change.",
  analyze(file) {
    const signals: Signal[] = [];
    if (isScriptLike(file.path)) {
      signals.push(...curlBashSignals(file));
      signals.push(...unpinnedGoInstallSignals(file));
    }
    if (isBinaryPath(file.path)) {
      signals.push({
        ruleId: "go-project.committed-binary",
        path: file.path,
        line: 1,
        message: "Compiled executable path is tracked outside testdata.",
        snippet: file.path,
        data: { path: file.path },
      });
    }
    if (isEditorJunk(file.path)) {
      signals.push({
        ruleId: "go-project.editor-junk",
        path: file.path,
        line: 1,
        message: "Editor or OS metadata path is tracked in the repository.",
        snippet: file.path,
        data: { path: file.path },
      });
    }
    return {
      signals,
      positives: [
        ...positive(
          file,
          "go-project.toolchain-from-mod",
          /go-version-file:\s*go\.mod/,
          "CI reads the Go version from go.mod.",
        ),
        ...positive(
          file,
          "go-project.explicit-construction",
          /^\s*func\s+New[A-Z]\w*\s*\(/,
          "Package lifecycle is exposed through explicit construction.",
        ),
      ],
    };
  },
};

function isScriptLike(path: string): boolean {
  return (
    /(^|\/)(?:[Mm]akefile|GNUmakefile|Taskfile\.ya?ml)$/.test(path) ||
    /\.sh$/.test(path) ||
    /(^|\/)tools\/.+\.go$/.test(path)
  );
}

function isShellScriptLike(path: string): boolean {
  return (
    /(^|\/)(?:[Mm]akefile|GNUmakefile|Taskfile\.ya?ml)$/.test(path) ||
    /\.sh$/.test(path)
  );
}

/** Documentation whose purpose includes contributor setup or prerequisites. */
export function isPrerequisiteDocument(path: string): boolean {
  const name = path.split("/").at(-1) ?? path;
  if (/^(?:README|CONTRIBUTING|PREREQUISITES?)(?:[._-].*)?$/i.test(name)) return true;
  return /(^|\/)docs\/.*(?:prereq|getting[-_ ]?started|setup).*(?:\.md|\.rst|\.txt)$/i.test(path);
}

function isBinaryPath(path: string): boolean {
  if (/(^|\/)testdata\//.test(path)) return false;
  if (/\.exe$/i.test(path)) return true;
  // Extensionless bin/ paths are too noisy without magic bytes; skip.
  return false;
}

function isEditorJunk(path: string): boolean {
  return (
    /(^|\/)\.DS_Store$/.test(path) ||
    /(^|\/)\.idea\//.test(path) ||
    /\.(?:swp|swo)$/.test(path) ||
    /(^|\/)Thumbs\.db$/i.test(path)
  );
}

function curlBashSignals(file: SourceRevision): Signal[] {
  return lineSignals(
    file,
    "go-project.script-curl-bash",
    /(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/,
    () => "Remote content is piped directly into a shell.",
  );
}

function unpinnedGoInstallSignals(file: SourceRevision): Signal[] {
  const signals: Signal[] = [];

  file.current.split("\n").forEach((line, index) => {
    const command = line.match(/\bgo\s+install\b([^#;&|]*)/);
    if (command?.[1] === undefined) return;

    const modules = command[1]
      .trim()
      .split(/\s+/)
      .map((token) => token.replace(/^["']|["'\\]+$/g, ""))
      .filter((token) => token !== "" && !token.startsWith("-"));

    for (const module of modules) {
      if (!isRemoteModule(module)) continue;
      const separator = module.lastIndexOf("@");
      const selector = separator === -1 ? "" : module.slice(separator + 1).toLowerCase();
      if (separator !== -1 && !["latest", "main", "master", "head"].includes(selector)) {
        continue;
      }

      signals.push({
        ruleId: "go-project.unpinned-go-install",
        path: file.path,
        line: index + 1,
        message: separator === -1
          ? `Remote Go tool ${module} is installed without a version pin.`
          : `Remote Go tool ${module} uses the mutable @${selector} selector.`,
        snippet: line.trim().slice(0, 300),
        data: { module, selector: selector || "missing" },
      });
    }
  });

  return signals;
}

function isRemoteModule(module: string): boolean {
  if (/^(?:\.{0,2}\/|\/)/.test(module)) return false;
  const path = module.includes("@") ? module.slice(0, module.lastIndexOf("@")) : module;
  const firstSegment = path.split("/")[0] ?? "";
  return firstSegment.includes(".");
}

/**
 * Cross-file: compare go.mod `go` / `toolchain` directive with CI setup-go versions.
 */
export function ciToolchainSkewSignals(files: SourceRevision[]): Signal[] {
  const goMod = files.find((f) => /(^|\/)go\.mod$/.test(f.path));
  if (goMod === undefined) return [];
  const modVersion = parseGoModVersion(goMod.current);
  if (modVersion === undefined) return [];

  const signals: Signal[] = [];
  for (const file of files) {
    if (!/\.ya?ml$/.test(file.path)) continue;
    if (!/(^|\/)\.github\/workflows\//.test(file.path) && !/(^|\/)\.gitlab-ci\.ya?ml$/.test(file.path)) {
      continue;
    }
    // Prefer go-version-file — quiet.
    if (/go-version-file:\s*go\.mod/.test(file.current)) continue;

    file.current.split("\n").forEach((line, index) => {
      const match = line.match(/go-version:\s*['"]?(\d+\.\d+(?:\.\d+)?)['"]?/);
      if (match === null) return;
      const ciVersion = match[1]!;
      if (versionsCompatible(modVersion, ciVersion)) return;
      signals.push({
        ruleId: "go-project.ci-toolchain-skew",
        path: file.path,
        line: index + 1,
        message: `CI go-version ${ciVersion} differs from go.mod Go ${modVersion}.`,
        snippet: line.trim().slice(0, 300),
        data: { ciVersion, modVersion },
      });
    });
  }
  return signals;
}

/**
 * Cross-file: public github.com module without LICENSE/COPYING.
 */
export function licenseMissingSignals(files: SourceRevision[]): Signal[] {
  const goMod = files.find((f) => /(^|\/)go\.mod$/.test(f.path) && !f.path.includes("/"));
  // Also accept nested but prefer root go.mod
  const rootGoMod =
    files.find((f) => f.path === "go.mod") ??
    files.find((f) => /(^|\/)go\.mod$/.test(f.path));
  const modFile = rootGoMod ?? goMod;
  if (modFile === undefined) return [];

  const moduleMatch = modFile.current.match(/^\s*module\s+(\S+)/m);
  if (moduleMatch === null) return [];
  const modulePath = moduleMatch[1] ?? "";
  // Only public-host style modules.
  if (!/^(?:github\.com|gitlab\.com|bitbucket\.org|golang\.org)\//.test(modulePath)) {
    return [];
  }
  // Private-by-convention paths.
  if (/\/(?:internal|private)\//.test(modulePath)) return [];

  const hasLicense = files.some((f) =>
    /(^|\/)(?:LICENSE|COPYING|LICENCE)(?:$|\.)/i.test(f.path),
  );
  if (hasLicense) return [];

  const line = modFile.current.slice(0, moduleMatch.index ?? 0).split("\n").length;
  return [
    {
      ruleId: "go-project.license-missing",
      path: modFile.path,
      line,
      message: `Public module ${modulePath} has no LICENSE/COPYING in the reviewed tree.`,
      snippet: (moduleMatch[0] ?? "").trim(),
      data: { module: modulePath },
    },
  ];
}

interface ExternalTool {
  command: string;
  documentationPattern: RegExp;
}

const EXTERNAL_TOOLS: readonly ExternalTool[] = [
  { command: "jq", documentationPattern: /\bjq\b/i },
  { command: "node", documentationPattern: /\bnode(?:\.js)?\b/i },
  { command: "sphinx-build", documentationPattern: /\bsphinx-build\b/i },
  { command: "wasm-pack", documentationPattern: /\bwasm-pack\b/i },
];

/**
 * Cross-file: changed scripts that currently rely on a small set of nonstandard
 * CLIs which the repository's contributor setup documentation does not name.
 */
export function undocumentedExternalCLISignals(files: SourceRevision[]): Signal[] {
  const prerequisiteDocuments = files.filter((file) => isPrerequisiteDocument(file.path));
  const documented = prerequisiteDocuments.map((file) => file.current).join("\n");
  const signals: Signal[] = [];

  for (const file of files) {
    if (file.status === "repository" || !isShellScriptLike(file.path)) continue;

    const lines = file.current.split("\n");
    for (const tool of EXTERNAL_TOOLS) {
      if (tool.documentationPattern.test(documented)) continue;
      if (scriptExplainsPrerequisite(file.current, tool)) continue;

      const commandPattern = shellCommandPattern(tool.command);
      const lineIndex = lines.findIndex((line) => {
        if (/^\s*#/.test(line)) return false;
        return commandPattern.test(line.trim());
      });
      if (lineIndex === -1) continue;

      signals.push({
        ruleId: "go-project.undocumented-cli-prerequisite",
        path: file.path,
        line: lineIndex + 1,
        message: `External CLI ${tool.command} is required here but is not listed in prerequisite documentation.`,
        snippet: lines[lineIndex]!.trim().slice(0, 300),
        data: {
          tool: tool.command,
          prerequisiteDocuments: prerequisiteDocuments.map((item) => item.path),
        },
      });
    }
  }

  return signals;
}

function shellCommandPattern(command: string): RegExp {
  const escaped = command.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(
    `(?:^|[|;&(]\\s*|\\$\\(\\s*|\\$\\(\\s*shell\\s+|\\b(?:command|exec|env|sudo|xargs)\\s+)${escaped}(?=\\s|$)`,
  );
}

function scriptExplainsPrerequisite(source: string, tool: ExternalTool): boolean {
  return source.split("\n").some((line) => {
    if (!tool.documentationPattern.test(line)) return false;
    if (/^\s*#/.test(line)) {
      return /\b(?:depend|install|prereq|requir|setup|vendor)/i.test(line);
    }
    return /\b(?:depend|install|prereq|required|setup|vendor)(?:ed|s|ing)?\b/i.test(line) &&
      /(?:echo|printf|error|fail)/i.test(line);
  });
}

function parseGoModVersion(source: string): string | undefined {
  const toolchain = source.match(/^\s*toolchain\s+go(\d+\.\d+(?:\.\d+)?)\s*$/m);
  if (toolchain?.[1]) return toolchain[1];
  const goLine = source.match(/^\s*go\s+(\d+\.\d+(?:\.\d+)?)\s*$/m);
  return goLine?.[1];
}

/** True when CI version is same major.minor (or newer patch) as module, or intentionally multi-version. */
function versionsCompatible(modVersion: string, ciVersion: string): boolean {
  const mod = parseSemver(modVersion);
  const ci = parseSemver(ciVersion);
  if (mod === undefined || ci === undefined) return modVersion === ciVersion;
  // Exact major.minor match is fine (patch may differ).
  if (mod.major === ci.major && mod.minor === ci.minor) return true;
  // CI newer major.minor is acceptable (testing ahead); older is skew.
  if (ci.major > mod.major) return true;
  if (ci.major === mod.major && ci.minor >= mod.minor) return true;
  return false;
}

function parseSemver(v: string): { major: number; minor: number; patch: number } | undefined {
  const m = v.match(/^(\d+)\.(\d+)(?:\.(\d+))?$/);
  if (m === null) return undefined;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3] ?? 0) };
}
