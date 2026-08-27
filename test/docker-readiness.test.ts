import assert from "node:assert/strict";
import test from "node:test";
import { dockerDaemonReadinessSignals } from "../src/docker-readiness.ts";
import { type SourceRevision } from "../src/types.ts";

const ruleId = "go-project.docker-start-without-readiness";

test("reports the source-derived Docker start/use race", () => {
  const source = script([
    "#!/bin/bash",
    "set -euo pipefail",
    'readonly OCI_BIN="${OCI_BIN:-docker}"',
    "main() {",
    '  if [[ "${OCI_BIN}" == "docker" ]]; then',
    "    if ! systemctl is-active --quiet docker; then",
    "      systemctl start docker",
    "    fi",
    "  fi",
    '  "${OCI_BIN}" ps -a',
    '  "${OCI_BIN}" build -t test .',
    "}",
    'main "$@"',
  ]);

  assert.deepEqual(dockerDaemonReadinessSignals(source).map(summary), [{
    ruleId,
    line: 7,
    operation: "ps",
    startLine: 7,
    useLine: 10,
  }]);
});

test("a conditional start failure exit does not hide the successful path", () => {
  const source = script([
    "#!/bin/sh",
    "main() {",
    "  if ! systemctl start docker; then",
    "    echo failed >&2",
    "    exit 1",
    "  fi",
    "  if missing_input; then",
    "    exit 1",
    "  fi",
    "  docker ps",
    "}",
    "main",
  ]);
  assert.deepEqual(dockerDaemonReadinessSignals(source).map(summary), [{
    ruleId,
    line: 3,
    operation: "ps",
    startLine: 3,
    useLine: 10,
  }]);
});

test("a branch-local return prevents a start/use path", () => {
  assert.deepEqual(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "main() {",
    "  if enabled; then",
    "    systemctl start docker",
    "    return",
    "  fi",
    "  docker ps",
    "}",
    "main",
  ])), []);
});

test("handles same-line readiness and dependent operations", () => {
  assert.deepEqual(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "set -e",
    "main() {",
    "  systemctl start docker; docker info >/dev/null",
    "  docker ps",
    "}",
    "main",
  ])), []);
  assert.equal(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "main() { systemctl start docker; docker ps; }",
    "main",
  ])).length, 1);
});

test("recognizes trap-invoked helper functions", () => {
  for (const handler of ["cleanup", "'cleanup'"]) {
    assert.equal(dockerDaemonReadinessSignals(script([
      "#!/bin/sh",
      "cleanup() {",
      "  systemctl start docker",
      "  docker ps",
      "}",
      `trap ${handler} EXIT`,
    ])).length, 1);
  }
});

test("accepts the source-derived bounded readiness helper", () => {
  const source = script([
    "#!/bin/bash",
    "set -euo pipefail",
    'readonly OCI_BIN="${OCI_BIN:-docker}"',
    "start_docker() {",
    "  systemctl start docker",
    '  timeout="${DOCKER_TIMEOUT:-30}"',
    '  while [ "$timeout" -gt 0 ]; do',
    "    if docker info >/dev/null 2>&1; then",
    "      return",
    "    fi",
    "    sleep 1",
    "    ((timeout--))",
    "  done",
    "  exit 1",
    "}",
    "main() {",
    "  start_docker",
    '  "${OCI_BIN}" build -t test .',
    "}",
    'main "$@"',
  ]);

  assert.deepEqual(dockerDaemonReadinessSignals(source), []);
});

test("accepts a direct readiness gate before Docker use", () => {
  const source = script([
    "#!/bin/sh",
    "set -eu",
    "main() {",
    "  systemctl start docker",
    "  docker info >/dev/null",
    "  docker build -t test .",
    "}",
    "main",
  ]);

  assert.deepEqual(dockerDaemonReadinessSignals(source), []);
});

test("accepts bounded direct and helper readiness loops", () => {
  const bounded = [
    '  timeout="${DOCKER_TIMEOUT:-30}"',
    '  while [ "$timeout" -gt 0 ]; do',
    "    if docker info >/dev/null 2>&1; then break; fi",
    "    sleep 1",
    "    timeout=$((timeout - 1))",
    "  done",
    '  if [ "$timeout" -eq 0 ]; then exit 1; fi',
  ];
  assert.deepEqual(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "main() {",
    "  systemctl start docker",
    ...bounded,
    "  docker ps",
    "}",
    "main",
  ])), []);
  assert.deepEqual(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "wait_for_docker() {",
    ...bounded,
    "}",
    "main() {",
    "  systemctl start docker",
    "  wait_for_docker",
    "  docker ps",
    "}",
    "main",
  ])), []);
});

test("requires the bounded probe to control success and failure paths", () => {
  assert.equal(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "main() {",
    "  systemctl start docker",
    "  timeout=3",
    '  while [ "$timeout" -gt 0 ]; do',
    "    docker info >/dev/null 2>&1 || true",
    "    sleep 1",
    "    timeout=$((timeout - 1))",
    "  done",
    "  exit_code=1",
    "  echo retry-finished",
    "  docker ps",
    "}",
    "main",
  ])).length, 1);
});

test("does not accept an ignored Docker info failure as readiness", () => {
  assert.equal(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "main() {",
    "  systemctl start docker",
    "  docker info >/dev/null 2>&1 || true",
    "  docker ps",
    "}",
    "main",
  ])).length, 1);
});

test("requires direct Docker info to be fail-closed", () => {
  assert.equal(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "main() {",
    "  systemctl start docker",
    "  docker info >/dev/null 2>&1",
    "  docker ps",
    "}",
    "main",
  ])).length, 1);
  assert.deepEqual(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "main() {",
    "  systemctl start docker; docker info >/dev/null 2>&1 || exit 1",
    "  docker ps",
    "}",
    "main",
  ])), []);
  for (const prefix of [
    "if enabled; then set -e; fi",
    "set -e; set +e",
  ]) {
    assert.equal(dockerDaemonReadinessSignals(script([
      "#!/bin/sh",
      "main() {",
      `  ${prefix}`,
      "  systemctl start docker",
      "  docker info >/dev/null 2>&1",
      "  docker ps",
      "}",
      "main",
    ])).length, 1, prefix);
  }
  assert.equal(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "set -e",
    "main() {",
    "  systemctl start docker",
    "  docker info 2>&1 | tee /tmp/info.log",
    "  docker ps",
    "}",
    "main",
  ])).length, 1);
});

test("requires a unique synchronous fail-closed readiness helper", () => {
  const bounded = [
    "  timeout=3",
    '  while [ "$timeout" -gt 0 ]; do',
    "    if docker info >/dev/null 2>&1; then return; fi",
    "    sleep 1",
    "    timeout=$((timeout - 1))",
    "  done",
    "  exit 1",
  ];
  for (const invocation of ["enabled && wait_for_docker", "wait_for_docker &"]) {
    assert.equal(dockerDaemonReadinessSignals(script([
      "#!/bin/sh",
      "wait_for_docker() {",
      ...bounded,
      "}",
      "main() {",
      "  systemctl start docker",
      `  ${invocation}`,
      "  docker ps",
      "}",
      "main",
    ])).length, 1, invocation);
  }
  assert.equal(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "wait_for_docker() {",
    ...bounded,
    "}",
    "wait_for_docker() { echo replacement; }",
    "main() {",
    "  systemctl start docker",
    "  wait_for_docker",
    "  docker ps",
    "}",
    "main",
  ])).length, 1);
});

test("fails closed when the Docker alias was rebound before service start", () => {
  assert.deepEqual(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    'OCI_BIN="${OCI_BIN:-docker}"',
    "main() {",
    "  OCI_BIN=podman",
    "  systemctl start docker",
    '  "${OCI_BIN}" ps',
    "}",
    "main",
  ])), []);
});

test("stays quiet without a dependent Docker operation", () => {
  assert.deepEqual(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "main() {",
    "  systemctl start docker",
    "  echo ready",
    "}",
    "main",
  ])), []);
});

test("stays quiet for unrelated services, comments, and strings", () => {
  assert.deepEqual(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "main() {",
    "  systemctl start containerd",
    "  docker ps",
    "  # systemctl start docker",
    '  echo "systemctl start docker; docker build ."',
    "}",
    "main",
  ])), []);
});

test("stays quiet for heredoc and multiline-string examples", () => {
  assert.deepEqual(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "cat <<'EXAMPLE'",
    "systemctl start docker",
    "docker ps",
    "EXAMPLE",
    'printf "%s\\n" "systemctl start docker',
    "docker build -t example .",
    '"',
  ])), []);
});

test("stays quiet for an uninvoked helper body", () => {
  assert.deepEqual(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "unused() {",
    "  systemctl start docker",
    "  docker ps",
    "}",
    "echo done",
  ])), []);
});

test("fails closed for ambiguous duplicate function definitions", () => {
  assert.deepEqual(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "run_test() {",
    "  systemctl start docker",
    "  docker ps",
    "}",
    "run_test() {",
    "  echo replacement",
    "}",
    "run_test",
  ])), []);
});

test("stays quiet for statically dead invocations and unreachable Docker use", () => {
  assert.deepEqual(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    "unsafe() {",
    "  systemctl start docker",
    "  docker ps",
    "}",
    "if false; then",
    "  unsafe",
    "fi",
    "main() {",
    "  systemctl start docker",
    "  return",
    "  docker build -t test .",
    "}",
    "main",
  ])), []);
});

test("fails closed when the Docker command alias is reassigned", () => {
  assert.deepEqual(dockerDaemonReadinessSignals(script([
    "#!/bin/sh",
    'OCI_BIN="${OCI_BIN:-docker}"',
    "main() {",
    "  systemctl start docker",
    "  OCI_BIN=podman",
    '  "${OCI_BIN}" ps',
    "}",
    "main",
  ])), []);
});

test("an unrelated or comment-only edit does not revive a legacy relationship", () => {
  const previous = [
    "#!/bin/sh",
    "main() {",
    "  systemctl start docker",
    "  echo old diagnostic",
    "  docker ps",
    "}",
    "main",
  ].join("\n");
  const current = previous.replace("old diagnostic", "new diagnostic # documentation");

  assert.deepEqual(dockerDaemonReadinessSignals(script(
    current.split("\n"),
    "modified",
    new Set([4]),
    previous,
  )), []);
});

test("changing arguments of a legacy dependent operation stays quiet", () => {
  const previous = [
    "#!/bin/sh",
    "main() {",
    "  systemctl start docker",
    "  docker build -t old .",
    "}",
    "main",
  ].join("\n");
  const current = previous.replace("-t old", "-t new");
  assert.deepEqual(dockerDaemonReadinessSignals(script(
    current.split("\n"),
    "modified",
    new Set([4]),
    previous,
  )), []);
});

test("a second same-operation relationship is still new under multiset locality", () => {
  const previous = [
    "#!/bin/sh",
    "main() {",
    "  systemctl start docker",
    "  docker ps",
    "}",
    "main",
  ].join("\n");
  const current = previous.replace("  docker ps", [
    "  docker ps",
    "  systemctl start docker",
    "  docker ps",
  ].join("\n"));
  assert.deepEqual(dockerDaemonReadinessSignals(script(
    current.split("\n"),
    "modified",
    new Set([5, 6]),
    previous,
  )).map(summary), [{
    ruleId,
    line: 5,
    operation: "ps",
    startLine: 5,
    useLine: 6,
  }]);
});

test("a newly added dependent use reports on its changed line", () => {
  const previous = [
    "#!/bin/sh",
    "main() {",
    "  systemctl start docker",
    "  echo ready",
    "}",
    "main",
  ].join("\n");
  const current = previous.replace("  echo ready", "  docker ps");

  assert.deepEqual(dockerDaemonReadinessSignals(script(
    current.split("\n"),
    "modified",
    new Set([4]),
    previous,
  )).map(summary), [{
    ruleId,
    line: 4,
    operation: "ps",
    startLine: 3,
    useLine: 4,
  }]);
});

test("deletion-only readiness removal fails closed without a current anchor", () => {
  const previous = [
    "#!/bin/sh",
    "main() {",
    "  systemctl start docker",
    "  docker info >/dev/null",
    "  docker ps",
    "}",
    "main",
  ].join("\n");
  const current = previous.replace("  docker info >/dev/null\n", "");
  assert.deepEqual(dockerDaemonReadinessSignals(script(
    current.split("\n"),
    "modified",
    new Set(),
    previous,
  )), []);
});

function script(
  lines: string[],
  status: SourceRevision["status"] = "added",
  changedLines = new Set<number>(),
  previous?: string,
): SourceRevision {
  return {
    path: "tests/restart.sh",
    current: lines.join("\n"),
    changedLines,
    status,
    ...(previous === undefined ? {} : { previous }),
  };
}

function summary(signal: ReturnType<typeof dockerDaemonReadinessSignals>[number]) {
  return {
    ruleId: signal.ruleId,
    line: signal.line,
    operation: signal.data.operation,
    startLine: signal.data.startLine,
    useLine: signal.data.useLine,
  };
}
