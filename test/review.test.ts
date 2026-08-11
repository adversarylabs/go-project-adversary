import assert from "node:assert/strict";
import { cp, mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { type ReviewResult } from "@adversarylabs/sdk";
import { domain } from "../src/domain.ts";
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

async function isolatedFixture(fixture: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "go-domain-fixture-"));
  await cp(fixture, root, { recursive: true });
  return root;
}

function source(path: string, current: string): SourceRevision {
  return { path, current, changedLines: new Set(), status: "added" };
}
