import { type Signal, type SourceRevision } from "./types.js";

const RULE_ID = "go-project.docker-start-without-readiness";
const DOCKER_DAEMON_OPERATIONS = new Set([
  "attach",
  "build",
  "commit",
  "compose",
  "create",
  "events",
  "exec",
  "export",
  "images",
  "import",
  "inspect",
  "kill",
  "load",
  "logs",
  "network",
  "pause",
  "plugin",
  "ps",
  "pull",
  "push",
  "rename",
  "restart",
  "rm",
  "rmi",
  "run",
  "save",
  "start",
  "stats",
  "stop",
  "system",
  "top",
  "unpause",
  "update",
  "volume",
  "wait",
]);

interface ShellScope {
  name: string;
  startLine: number;
  endLine: number;
  lines: Array<{ line: number; text: string }>;
}

interface UnsafeRelationship {
  scope: string;
  startLine: number;
  useLine: number;
  startText: string;
  useText: string;
  operation: string;
}

/**
 * Find a narrow shell-harness race: the changed script starts Docker and then
 * reaches a daemon-dependent Docker operation without an intervening readiness
 * gate. Function bodies only participate when the script proves they execute.
 */
export function dockerDaemonReadinessSignals(file: SourceRevision): Signal[] {
  if (!/\.sh$/.test(file.path)) return [];

  const current = unsafeRelationships(file.current);
  if (current.length === 0) return [];

  const previousCounts = new Map<string, number>();
  if (file.previous !== undefined) {
    for (const relationship of unsafeRelationships(file.previous)) {
      const key = relationshipKey(relationship);
      previousCounts.set(key, (previousCounts.get(key) ?? 0) + 1);
    }
  }

  const signals: Signal[] = [];
  for (const relationship of current) {
    if (file.status === "modified") {
      const key = relationshipKey(relationship);
      const previousCount = previousCounts.get(key) ?? 0;
      if (previousCount > 0) {
        previousCounts.set(key, previousCount - 1);
        continue;
      }
    }

    const anchor = semanticAnchor(file, relationship);
    if (anchor === undefined) continue;

    signals.push({
      ruleId: RULE_ID,
      path: file.path,
      line: anchor,
      message:
        `Docker is started and then used for \`${relationship.operation}\` without a proven readiness gate.`,
      snippet: lineAt(file.current, anchor).trim().slice(0, 300),
      data: {
        service: "docker",
        operation: relationship.operation,
        startLine: relationship.startLine,
        useLine: relationship.useLine,
        scope: relationship.scope,
      },
    });
  }

  return signals;
}

function unsafeRelationships(source: string): UnsafeRelationship[] {
  const scopes = shellScopes(source);
  const invoked = invokedScopes(scopes);
  const dockerAlias = hasDockerOciAlias(source);
  const scopeCounts = new Map<string, number>();
  for (const scope of scopes) {
    if (scope.name !== "<top-level>") scopeCounts.set(scope.name, (scopeCounts.get(scope.name) ?? 0) + 1);
  }
  const readinessHelpers = new Set(
    scopes
      .filter((scope) => scope.name !== "<top-level>" && scopeCounts.get(scope.name) === 1 &&
        provesBoundedReadiness(scope.lines, dockerAlias, 0, true))
      .map((scope) => scope.name),
  );
  const relationships: UnsafeRelationship[] = [];

  for (const scope of scopes) {
    if (scope.name !== "<top-level>" && !invoked.has(scope.name)) continue;
    const depths = controlDepths(scope.lines);
    const dead = staticallyDeadLines(scope.lines);

    for (let index = 0; index < scope.lines.length; index += 1) {
      const start = scope.lines[index]!;
      const startText = activeShell(start.text);
      if (dead.has(index) || !startsDocker(startText)) continue;
      const startDepth = depths[index] ?? 0;
      const startOpensControl = opensControl(startText);
      const errexit = errexitEnabled(source, scope, index);
      let leftStartControl = false;

      const sameLine = sameLineOutcome(startText, dockerAlias, errexit);
      if (sameLine.kind === "ready") continue;
      if (sameLine.kind === "use") {
        relationships.push({
          scope: scope.name,
          startLine: start.line,
          useLine: start.line,
          startText: normalizeSemanticLine(startText),
          useText: normalizeSemanticLine(sameLine.text),
          operation: sameLine.operation,
        });
        continue;
      }
      for (let candidate = index + 1; candidate < scope.lines.length; candidate += 1) {
        const use = scope.lines[candidate]!;
        const useText = activeShell(use.text);
        if (dead.has(candidate)) continue;
        if ((depths[candidate] ?? 0) < startDepth) leftStartControl = true;
        if (isDockerAliasReassignment(useText)) break;
        if (isUnconditionalTerminator(useText) && (
          (depths[candidate] ?? 0) === 0 ||
          (!startOpensControl && !leftStartControl && (depths[candidate] ?? 0) === startDepth)
        )) break;
        if (isReadinessGate(
          scope.lines,
          index,
          candidate,
          dockerAlias,
          depths,
          startDepth,
          readinessHelpers,
          errexit,
        )) break;

        const operation = dockerDaemonOperation(useText, dockerAlias);
        if (operation === undefined) continue;

        relationships.push({
          scope: scope.name,
          startLine: start.line,
          useLine: use.line,
          startText: normalizeSemanticLine(startText),
          useText: normalizeSemanticLine(useText),
          operation,
        });
        break;
      }
    }
  }

  return relationships;
}

function shellScopes(source: string): ShellScope[] {
  const lines = semanticShellLines(source.split("\n"));
  const functions: ShellScope[] = [];
  const covered = new Set<number>();

  for (let index = 0; index < lines.length; index += 1) {
    const declaration = activeShell(lines[index]!).match(
      /^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\s*\))?\s*\{/,
    );
    if (declaration?.[1] === undefined) continue;

    let depth = braceDelta(lines[index]!);
    let end = index;
    while (depth > 0 && end + 1 < lines.length) {
      end += 1;
      depth += braceDelta(lines[end]!);
    }

    const scopedLines: ShellScope["lines"] = [];
    const openingTail = activeShell(lines[index]!).replace(
      /^\s*(?:function\s+)?[A-Za-z_][A-Za-z0-9_]*\s*(?:\(\s*\))?\s*\{\s*/,
      "",
    );
    const oneLineBody = depth === 0 ? openingTail.replace(/}\s*$/, "") : openingTail;
    if (oneLineBody.trim() !== "") scopedLines.push({ line: index + 1, text: oneLineBody });
    for (let lineIndex = index + 1; lineIndex < end; lineIndex += 1) {
      covered.add(lineIndex);
      scopedLines.push({ line: lineIndex + 1, text: lines[lineIndex]! });
    }
    if (end > index) {
      const closingHead = activeShell(lines[end]!).replace(/}\s*$/, "");
      if (closingHead.trim() !== "") scopedLines.push({ line: end + 1, text: closingHead });
    }
    covered.add(index);
    covered.add(end);
    functions.push({
      name: declaration[1],
      startLine: index + 1,
      endLine: end + 1,
      lines: scopedLines,
    });
    index = end;
  }

  const topLevelLines: ShellScope["lines"] = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (!covered.has(index)) topLevelLines.push({ line: index + 1, text: lines[index]! });
  }

  return [{
    name: "<top-level>",
    startLine: 1,
    endLine: lines.length,
    lines: topLevelLines,
  }, ...functions];
}

function invokedScopes(scopes: ShellScope[]): Set<string> {
  const counts = new Map<string, number>();
  for (const scope of scopes) {
    if (scope.name === "<top-level>") continue;
    counts.set(scope.name, (counts.get(scope.name) ?? 0) + 1);
  }
  const functions = new Set(
    [...counts].filter(([, count]) => count === 1).map(([name]) => name),
  );
  const invoked = new Set<string>();
  const topLevel = scopes.find((scope) => scope.name === "<top-level>");
  if (topLevel !== undefined) collectInvocations(topLevel, functions, invoked);

  let changed = true;
  while (changed) {
    changed = false;
    for (const scope of scopes) {
      if (!invoked.has(scope.name)) continue;
      const before = invoked.size;
      collectInvocations(scope, functions, invoked);
      if (invoked.size !== before) changed = true;
    }
  }
  return invoked;
}

function collectInvocations(scope: ShellScope, functions: Set<string>, invoked: Set<string>): void {
  const dead = staticallyDeadLines(scope.lines);
  for (let index = 0; index < scope.lines.length; index += 1) {
    if (dead.has(index)) continue;
    const { text } = scope.lines[index]!;
    const active = activeShell(text);
    for (const name of functions) {
      const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const call = new RegExp(
        `(?:^|[;&|()]|\\b(?:then|do)\\b)\\s*(?:if\\s+!?\\s*)?${escaped}(?=\\s|[;&|)]|$)`,
      );
      const trap = new RegExp(
        `(?:^|[;&|()]|\\b(?:then|do)\\b)\\s*trap\\s+(?:--\\s+)?["']?${escaped}["']?(?=\\s|[;&|)]|$)`,
      );
      if (call.test(active) || trap.test(active)) invoked.add(name);
    }
  }
}

function startsDocker(line: string): boolean {
  return dockerStartMatch(line) !== undefined;
}

function dockerStartMatch(line: string): RegExpMatchArray | undefined {
  return line.match(/(?:^|[;&|()]|\b(?:then|do)\b)\s*(?:if\s+!?\s*)?(?:sudo\s+)?systemctl\s+(?:--[^\s]+\s+)*start\s+docker(?:\.service)?(?=\s|[;&|)]|$)/) ?? undefined;
}

function sameLineOutcome(
  line: string,
  dockerAlias: boolean,
  errexit: boolean,
): { kind: "none" } | { kind: "ready" } | { kind: "use"; operation: string; text: string } {
  const start = dockerStartMatch(line);
  if (start?.index === undefined) return { kind: "none" };
  const tail = line.slice(start.index + start[0].length);
  const normalized = normalizeDockerAlias(tail, dockerAlias);
  const readiness = directReadinessIndex(normalized, errexit);
  const use = dockerDaemonCommand(normalized);
  if (use !== undefined && (readiness === -1 || use.index < readiness)) {
    return { kind: "use", operation: use.operation, text: normalized.slice(use.index) };
  }
  if (readiness !== -1) return { kind: "ready" };
  return { kind: "none" };
}

function dockerDaemonOperation(line: string, dockerAlias: boolean): string | undefined {
  return dockerDaemonCommand(normalizeDockerAlias(line, dockerAlias))?.operation;
}

function dockerDaemonCommand(normalized: string): { operation: string; index: number } | undefined {
  const pattern = /(?:^|[;&|()]|\b(?:then|do)\b)\s*(?:if\s+!?\s*)?(?:sudo\s+)?["']?docker["']?\s+([a-z][a-z0-9-]*)\b/g;
  for (const match of normalized.matchAll(pattern)) {
    const operation = match[1];
    if (operation !== undefined && DOCKER_DAEMON_OPERATIONS.has(operation)) {
      return { operation, index: match.index };
    }
  }
  return undefined;
}

function directReadinessIndex(line: string, errexit: boolean): number {
  const match = /(?:^|[;()]|\b(?:then|do)\b)\s*["']?docker["']?\s+info\b/.exec(line);
  if (match?.index === undefined) return -1;
  const prefix = line.slice(0, match.index + match[0].length);
  if (/(?:^|[;&|()]|\b(?:then|do)\b)\s*(?:if|while|until)\s+!?\s*["']?docker["']?\s+info\b/.test(prefix)) {
    return -1;
  }
  const tail = line.slice(match.index + match[0].length);
  if (/^[^;]*\|\|\s*(?:true|:)(?:\s|$)/.test(tail)) return -1;
  if (/^[^;]*\|\|\s*(?:exit|return)\s+[1-9]\d*(?:\s|;|$)/.test(tail)) return match.index;
  if (/^[^;]*(?:&&|\|\|)/.test(tail) || /(^|[^|])\|([^|]|$)/.test(tail) || /&\s*(?:$|[;)])/.test(tail)) {
    return -1;
  }
  return errexit ? match.index : -1;
}

function opensControl(line: string): boolean {
  return /^(?:\s*)(?:if\b.*\bthen|(?:while|until|for|select)\b.*\bdo|case\b.*\bin)\b/.test(line);
}

function isReadinessGate(
  lines: ShellScope["lines"],
  startIndex: number,
  candidateIndex: number,
  dockerAlias: boolean,
  depths: number[],
  startDepth: number,
  readinessHelpers: Set<string>,
  errexit: boolean,
): boolean {
  const between = lines.slice(startIndex + 1, candidateIndex);
  for (let index = 0; index < between.length; index += 1) {
    const normalized = normalizeDockerAlias(activeShell(between[index]!.text), dockerAlias);
    const absoluteIndex = startIndex + 1 + index;
    const depth = depths[absoluteIndex] ?? 0;
    if (depth <= startDepth && /\bsystemctl\b[^#\n]*\bis-active\b[^#\n]*\b--wait\b[^#\n]*\bdocker(?:\.service)?\b/.test(normalized)) {
      return true;
    }
    if (depth <= startDepth && directlyCallsAnyFunction(normalized, readinessHelpers)) {
      return true;
    }
    if (!/(?:^|[;&|()]|\b(?:then|do)\b)\s*(?:if\s+!?\s*)?["']?docker["']?\s+info\b/.test(normalized)) {
      continue;
    }
    if (/\|\|\s*(?:true|:)(?:\s|$)/.test(normalized) || /(?:^|\s)&\s*$/.test(normalized)) continue;
    if (depth <= startDepth && directReadinessIndex(normalized, errexit) !== -1) return true;
    if (depth <= startDepth && failClosedInfoGate(between, index, dockerAlias)) return true;
  }
  const annotated = between.map((line, index) => ({
    ...line,
    depth: depths[startIndex + 1 + index] ?? 0,
  }));
  return provesBoundedReadiness(annotated, dockerAlias, startDepth);
}

function provesBoundedReadiness(
  lines: Array<{ line: number; text: string; depth?: number }>,
  dockerAlias: boolean,
  maximumDepth = 0,
  requireProcessExit = false,
): boolean {
  const active = lines.map(({ text }) => normalizeDockerAlias(activeShell(text), dockerAlias));
  for (let infoIndex = 0; infoIndex < active.length; infoIndex += 1) {
    const info = active[infoIndex]!;
    if (!/(?:^|[;&|()]|\b(?:then|do)\b)\s*(?:if\s+!?\s*)?["']?docker["']?\s+info\b/.test(info)) continue;
    if (/\|\|\s*(?:true|:)(?:\s|$)/.test(info) || /(?:^|\s)&\s*$/.test(info)) continue;

    let loopStart = -1;
    for (let index = infoIndex - 1; index >= 0; index -= 1) {
      if (/^\s*(?:while|until)\b.*\bdo\b/.test(active[index]!)) {
        loopStart = index;
        break;
      }
    }
    if (loopStart === -1 || (lines[loopStart]!.depth ?? 0) > maximumDepth) continue;

    let loopEnd = -1;
    for (let index = infoIndex + 1; index < active.length; index += 1) {
      if (/^\s*done\b/.test(active[index]!) &&
          (lines[index]!.depth ?? 0) === (lines[loopStart]!.depth ?? 0)) {
        loopEnd = index;
        break;
      }
    }
    if (loopEnd === -1) continue;

    const prefix = active.slice(0, loopStart).join("\n");
    const bound = prefix.match(/\b([A-Za-z_][A-Za-z0-9_]*(?:timeout|retries|attempts)|(?:timeout|retries|attempts)[A-Za-z0-9_]*)\s*=\s*(?:["']?\$\{[^}]+:-\d+\}["']?|["']?\d+["']?)/i)?.[1];
    if (bound === undefined) continue;
    const escaped = bound.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const loopHeader = active[loopStart]!;
    if (!new RegExp(`(?:\\$${escaped}\\b|\\$\\{${escaped}\\}|\\b${escaped}\\b)["']?\\s*(?:-gt|>|-ne|!=)\\s*["']?0\\b`).test(loopHeader)) {
      continue;
    }
    if (!readinessSuccessEscapes(active, infoIndex, loopEnd)) continue;
    const loop = active.slice(loopStart, loopEnd + 1).join("\n");
    const decrements = new RegExp(
      `(?:\\(\\(\\s*${escaped}--\\s*\\)\\)|${escaped}\\s*=\\s*\\$\\(\\(\\s*${escaped}\\s*-\\s*1\\s*\\)\\)|\\blet\\s+${escaped}--)`,
    ).test(loop);
    if (!decrements || !/\bsleep\b/.test(loop)) continue;

    const suffixLines = active.slice(loopEnd + 1);
    const suffix = suffixLines.join("\n");
    const firstExecutableOffset = suffixLines.findIndex((line) => line.trim() !== "");
    const firstExecutable = firstExecutableOffset === -1 ? "" : suffixLines[firstExecutableOffset]!;
    const firstExecutableDepth = firstExecutableOffset === -1
      ? Number.POSITIVE_INFINITY
      : (lines[loopEnd + 1 + firstExecutableOffset]!.depth ?? 0);
    const failureCommand = requireProcessExit ? "exit" : "(?:exit|return)";
    const directFailure = firstExecutableDepth <= (lines[loopStart]!.depth ?? 0) &&
      new RegExp(`^\\s*${failureCommand}\\s+[1-9]\\d*\\s*;?\\s*$`).test(firstExecutable);
    if (directFailure || new RegExp(`\\b${escaped}\\b[\\s\\S]*\\b${failureCommand}\\s+[1-9]\\d*\\b`).test(suffix)) {
      return true;
    }
  }
  return false;
}

function readinessSuccessEscapes(active: string[], infoIndex: number, loopEnd: number): boolean {
  const info = active[infoIndex]!;
  if (!/^\s*if\b[^\n]*\bdocker\b[^\n]*\binfo\b[^\n]*\bthen\b/.test(info)) return false;
  if (/\bthen\b[^\n]*\b(?:break|return)(?:\s|;|$)/.test(info)) return true;

  for (let index = infoIndex + 1; index < loopEnd; index += 1) {
    const line = active[index]!.trim();
    if (/^fi\b/.test(line)) return false;
    if (/^(?:break|return)(?:\s|;|$)/.test(line)) return true;
  }
  return false;
}

function failClosedInfoGate(lines: ShellScope["lines"], infoIndex: number, dockerAlias: boolean): boolean {
  const info = normalizeDockerAlias(activeShell(lines[infoIndex]!.text), dockerAlias);
  if (!/^\s*if\s+!\s+[^\n]*docker[^\n]*info\b/.test(info)) return false;
  for (let index = infoIndex; index < lines.length; index += 1) {
    const active = activeShell(lines[index]!.text);
    if (/\b(?:exit|return)\s+[1-9]\d*\b/.test(active)) return true;
    if (/^\s*fi\b/.test(active) && index > infoIndex) return false;
  }
  return false;
}

function directlyCallsAnyFunction(line: string, names: Set<string>): boolean {
  for (const name of names) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (new RegExp(
      `^\\s*${escaped}(?:\\s+[^;&|]*)?\\s*;?\\s*$`,
    ).test(line)) return true;
  }
  return false;
}

function hasDockerOciAlias(source: string): boolean {
  const lines = semanticShellLines(source.split("\n")).map(activeShell);
  return lines.some((line) => /^\s*(?:readonly\s+)?OCI_BIN\s*=\s*["']?(?:docker|\$\{OCI_BIN:-docker\})["']?\s*$/.test(line)) &&
    !lines.some(isDockerAliasReassignment);
}

function errexitEnabled(source: string, scope: ShellScope, startIndex: number): boolean {
  const semantic = semanticShellLines(source.split("\n"));
  if (semantic.some((line) => /^\s*set\s+\+[A-Za-z]*e[A-Za-z]*(?:\s|$)/.test(activeShell(line)))) return false;
  const enablesErrexit = (line: string) => /^\s*set\s+-[A-Za-z]*e[A-Za-z]*(?:\s|$)/.test(activeShell(line));
  const localDepths = controlDepths(scope.lines);
  const localDead = staticallyDeadLines(scope.lines);
  if (scope.lines.slice(0, startIndex).some(({ text }, index) =>
    !localDead.has(index) && (localDepths[index] ?? 0) === 0 && enablesErrexit(text))) return true;

  const topLevel = shellScopes(source).find((candidate) => candidate.name === "<top-level>");
  if (topLevel === undefined) return false;
  const topDepths = controlDepths(topLevel.lines);
  const topDead = staticallyDeadLines(topLevel.lines);
  return topLevel.lines.some(({ line, text }, index) =>
    line < scope.startLine && !topDead.has(index) && (topDepths[index] ?? 0) === 0 && enablesErrexit(text));
}

function isDockerAliasReassignment(line: string): boolean {
  const assignment = line.match(/^\s*(?:readonly\s+|export\s+)?OCI_BIN\s*=\s*(.+?)\s*$/);
  if (assignment?.[1] === undefined) return false;
  return !/^["']?(?:docker|\$\{OCI_BIN(?::-[^}]*)?\})["']?$/.test(assignment[1]);
}

function isUnconditionalTerminator(line: string): boolean {
  return /^\s*(?:return|exit)(?:\s+[^;&|]+)?\s*;?\s*$/.test(line);
}

function controlDepths(lines: ShellScope["lines"]): number[] {
  const depths: number[] = [];
  let depth = 0;
  for (const { text } of lines) {
    const active = activeShell(text).trim();
    if (/^(?:fi|done|esac)\b/.test(active)) depth = Math.max(0, depth - 1);
    depths.push(depth);
    if (/^(?:if\b.*\bthen|(?:while|until|for|select)\b.*\bdo|case\b.*\bin)\b/.test(active) &&
        !/\b(?:fi|done|esac)\b/.test(active)) {
      depth += 1;
    }
  }
  return depths;
}

function staticallyDeadLines(lines: ShellScope["lines"]): Set<number> {
  const dead = new Set<number>();
  const stack: Array<{ dead: boolean; kind: "if" | "loop" }> = [];
  for (let index = 0; index < lines.length; index += 1) {
    const active = activeShell(lines[index]!.text).trim();
    const inheritedDead = stack.some((entry) => entry.dead);
    if (/^if\s+(?:\(\s*)?(?:false|\[\s+0\s+-eq\s+1\s+\]|\[\[\s+0\s+-eq\s+1\s+\]\])(?:\s*\))?\s*;?\s*then\b/.test(active)) {
      if (inheritedDead) dead.add(index);
      stack.push({ dead: true, kind: "if" });
      continue;
    }
    if (/^(?:while|until)\s+false\s*;?\s*do\b/.test(active)) {
      if (inheritedDead) dead.add(index);
      stack.push({ dead: true, kind: "loop" });
      continue;
    }
    if (/^else\b/.test(active) && stack.at(-1)?.kind === "if") {
      stack[stack.length - 1]!.dead = !stack[stack.length - 1]!.dead;
      if (stack.some((entry) => entry.dead)) dead.add(index);
      continue;
    }
    if (/^fi\b/.test(active) && stack.at(-1)?.kind === "if") {
      if (inheritedDead) dead.add(index);
      stack.pop();
      continue;
    }
    if (/^done\b/.test(active) && stack.at(-1)?.kind === "loop") {
      if (inheritedDead) dead.add(index);
      stack.pop();
      continue;
    }
    if (inheritedDead) dead.add(index);
  }
  return dead;
}

function normalizeDockerAlias(line: string, enabled: boolean): string {
  if (!enabled) return line;
  return line
    .replace(/["']?\$\{OCI_BIN\}["']?/g, "docker")
    .replace(/["']?\$OCI_BIN["']?/g, "docker");
}

function semanticAnchor(file: SourceRevision, relationship: UnsafeRelationship): number | undefined {
  if (file.status !== "modified") return relationship.startLine;
  if (file.changedLines.has(relationship.startLine)) return relationship.startLine;
  if (file.changedLines.has(relationship.useLine)) return relationship.useLine;

  for (let line = relationship.startLine + 1; line < relationship.useLine; line += 1) {
    if (!file.changedLines.has(line)) continue;
    const semantic = activeShell(lineAt(file.current, line)).trim();
    if (semantic !== "" && semantic !== "{" && semantic !== "}") return line;
  }
  return undefined;
}

function relationshipKey(relationship: UnsafeRelationship): string {
  return [relationship.scope, relationship.operation].join("\u0000");
}

function semanticShellLines(lines: string[]): string[] {
  const result = [...lines];
  let heredoc: { delimiter: string; stripTabs: boolean } | undefined;
  let continuedQuote: "'" | '"' | undefined;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!;
    if (heredoc !== undefined) {
      const candidate = heredoc.stripTabs ? line.replace(/^\t+/, "") : line;
      result[index] = "";
      if (candidate.trimEnd() === heredoc.delimiter) heredoc = undefined;
      continue;
    }
    if (continuedQuote !== undefined) {
      result[index] = "";
      if (closesContinuedQuote(line, continuedQuote)) continuedQuote = undefined;
      continue;
    }

    const marker = activeShell(line).match(/<<(-)?\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?/);
    if (marker?.[2] !== undefined) heredoc = { delimiter: marker[2], stripTabs: marker[1] === "-" };
    continuedQuote = openQuoteAtEnd(line);
  }
  return result;
}

function openQuoteAtEnd(line: string): "'" | '"' | undefined {
  let quote: "'" | '"' | undefined;
  let escaped = false;
  for (const character of line) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }
    if (quote === undefined && (character === "'" || character === '"')) quote = character;
    else if (character === quote) quote = undefined;
    if (quote === undefined && character === "#") break;
  }
  return quote;
}

function closesContinuedQuote(line: string, quote: "'" | '"'): boolean {
  let escaped = false;
  for (const character of line) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\" && quote === '"') {
      escaped = true;
      continue;
    }
    if (character === quote) return true;
  }
  return false;
}

function normalizeSemanticLine(line: string): string {
  return line.trim().replace(/\s+/g, " ").replace(/;\s*(?:then|do)\s*$/, "");
}

function lineAt(source: string, line: number): string {
  return source.split("\n")[line - 1] ?? "";
}

function activeShell(line: string): string {
  let quote: "'" | '"' | undefined;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }
    if (quote !== undefined) {
      if (character === quote) quote = undefined;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      continue;
    }
    if (character === "#" && (index === 0 || /\s/.test(line[index - 1]!))) return line.slice(0, index);
  }
  return line;
}

function braceDelta(line: string): number {
  const active = activeShell(line);
  let quote: "'" | '"' | undefined;
  let escaped = false;
  let delta = 0;
  for (let index = 0; index < active.length; index += 1) {
    const character = active[index]!;
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }
    if (quote !== undefined) {
      if (character === quote) quote = undefined;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      continue;
    }
    if (character === "{") delta += 1;
    if (character === "}") delta -= 1;
  }
  return delta;
}
