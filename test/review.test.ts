import assert from "node:assert/strict";
import { cp, mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { type ReviewResult } from "@adversarylabs/sdk";
import {
  domain,
  staleMockeryVerificationSignals,
  undocumentedExternalCLISignals,
} from "../src/domain.ts";
import { createApp } from "../src/index.ts";
import { type SourceRevision } from "../src/types.ts";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));

async function review(root: string): Promise<ReviewResult> {
  return createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
}

function snapshot(output: ReviewResult) {
  return {
    risk: output.assessment?.risk,
    findings: output.findings.map((finding) => ({
      ruleId: finding.ruleId,
      severity: finding.severity,
      evidenceCount: finding.evidence.length,
    })),
    positiveKeys: output.positives.map((item) => item.key),
    ship: output.opinion?.ship,
  };
}

for (const grade of ["excellent", "good", "average", "poor", "terrible"]) {
  test(`${grade} fixture matches its expected review snapshot`, async () => {
    const fixture = join(projectRoot, "fixtures", grade);
    const root = await isolatedFixture(fixture);
    const expected = JSON.parse(await readFile(join(fixture, "expected.review.json"), "utf8"));
    assert.deepEqual(snapshot(await review(root)), expected);
  });
}

test("review output is deterministic", async () => {
  const root = await isolatedFixture(join(projectRoot, "fixtures", "terrible"));
  assert.deepEqual(await review(root), await review(root));
});

test("flags mutable remote go install targets", () => {
  const file = source("Makefile", [
    "tools:",
    "\tGOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest",
    "\tgo install golang.org/x/tools/cmd/stringer@latest",
    "\tgo install github.com/example/tool@main",
  ].join("\n"));

  const signals = domain.analyze(file).signals.filter(
    (signal) => signal.ruleId === "go-project.unpinned-go-install",
  );

  assert.deepEqual(signals.map((signal) => signal.line), [2, 3, 4]);
});

test("accepts immutable and repository-local go install targets", () => {
  const file = source("tools/bootstrap.sh", [
    "go install github.com/example/tool@v1.4.0",
    "go install github.com/example/tool@v0.0.0-20230118154835-9241bceb3098",
    "go install github.com/example/tool@9241bceb3098",
    "go install github.com/example/tool@${TOOL_VERSION}",
    "go install ./cmd/mytool",
    "go install ../shared/cmd/tool",
    "go install std",
  ].join("\n"));

  assert.equal(
    domain.analyze(file).signals.some(
      (signal) => signal.ruleId === "go-project.unpinned-go-install",
    ),
    false,
  );
});

test("flags an external CLI omitted from contributor prerequisites", async () => {
  const fixture = join(projectRoot, "fixtures", "regressions", "undocumented-cli");
  const signals = undocumentedExternalCLISignals([
    source("scripts/generate.sh", await readFile(join(fixture, "generate.sh"), "utf8")),
    source(
      "CONTRIBUTING.md",
      await readFile(join(fixture, "CONTRIBUTING.md"), "utf8"),
      "repository",
    ),
  ]);

  assert.deepEqual(
    signals.map((signal) => ({ ruleId: signal.ruleId, line: signal.line, tool: signal.data.tool })),
    [{ ruleId: "go-project.undocumented-cli-prerequisite", line: 4, tool: "jq" }],
  );
});

test("stays quiet when the external CLI is documented", async () => {
  const fixture = join(projectRoot, "fixtures", "regressions", "documented-cli");
  assert.deepEqual(undocumentedExternalCLISignals([
    source("scripts/generate.sh", await readFile(join(fixture, "generate.sh"), "utf8")),
    source(
      "CONTRIBUTING.md",
      await readFile(join(fixture, "CONTRIBUTING.md"), "utf8"),
      "repository",
    ),
  ]), []);
});

test("stays quiet for POSIX and repository-relative commands", async () => {
  const fixture = join(projectRoot, "fixtures", "regressions", "local-commands");
  assert.deepEqual(undocumentedExternalCLISignals([
    source("scripts/generate.sh", await readFile(join(fixture, "generate.sh"), "utf8")),
  ]), []);
});

test("stays quiet when the changed script explains its prerequisite", () => {
  assert.deepEqual(undocumentedExternalCLISignals([
    source("scripts/generate.sh", [
      "#!/bin/sh",
      "# Requires jq; install it before running this generator.",
      "jq -r '.version' package.json",
    ].join("\n")),
  ]), []);
});

test("repository context scripts do not become change findings", () => {
  assert.deepEqual(undocumentedExternalCLISignals([
    source("scripts/generate.sh", "jq -r '.version' package.json", "repository"),
  ]), []);
});

test("flags a mockery verifier that cannot expose stale generated files", async () => {
  const path = join(
    projectRoot,
    "fixtures",
    "regressions",
    "stale-mockery-verifier",
    "verify-mocksgen.sh",
  );
  const signals = domain.analyze(source(
    "hack/verify-mocksgen.sh",
    await readFile(path, "utf8"),
  )).signals.filter((signal) => signal.ruleId === "go-project.stale-mockery-verification");

  assert.deepEqual(
    signals.map((signal) => ({ ruleId: signal.ruleId, line: signal.line, generator: signal.data.generator })),
    [{ ruleId: "go-project.stale-mockery-verification", line: 8, generator: "mockery" }],
  );
});

test("accepts marker-scoped cleanup before mockery regeneration", async () => {
  const path = join(
    projectRoot,
    "fixtures",
    "regressions",
    "clean-mockery-verifier",
    "verify-mocksgen.sh",
  );
  assert.deepEqual(staleMockeryVerificationSignals(source(
    "hack/verify-mocksgen.sh",
    await readFile(path, "utf8"),
  )), []);
});

test("accepts an explicit cleanup target delegated before mocksgen", async () => {
  const path = join(
    projectRoot,
    "fixtures",
    "regressions",
    "delegated-mockery-cleanup",
    "check-generated-mocks.sh",
  );
  assert.deepEqual(staleMockeryVerificationSignals(source(
    "hack/check-generated-mocks.sh",
    await readFile(path, "utf8"),
  )), []);
});

test("ignores generated-code verifiers for other generators", async () => {
  const path = join(
    projectRoot,
    "fixtures",
    "regressions",
    "unrelated-generated-verifier",
    "verify-protobuf.sh",
  );
  assert.deepEqual(staleMockeryVerificationSignals(source(
    "hack/verify-protobuf.sh",
    await readFile(path, "utf8"),
  )), []);
});

test("ignores mockery use outside a generated-output verifier", async () => {
  const path = join(
    projectRoot,
    "fixtures",
    "regressions",
    "unrelated-mockery-script",
    "install-mockery.sh",
  );
  assert.deepEqual(staleMockeryVerificationSignals(source(
    "hack/install-mockery.sh",
    await readFile(path, "utf8"),
  )), []);
});

test("ignores instructions that only mention make mocksgen", () => {
  assert.deepEqual(staleMockeryVerificationSignals(source(
    "hack/verify-mocksgen.sh",
    [
      "#!/usr/bin/env bash",
      "echo 'Run make mocksgen if generated mocks are stale'",
      "git status --short",
    ].join("\n"),
  )), []);
});

async function isolatedFixture(fixture: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "go-domain-fixture-"));
  await cp(fixture, root, { recursive: true });
  return root;
}

function source(
  path: string,
  current: string,
  status: SourceRevision["status"] = "added",
): SourceRevision {
  return { path, current, changedLines: new Set(), status };
}
