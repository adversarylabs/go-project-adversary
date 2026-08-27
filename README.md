# Go Project adversary

Reviews Go repository hygiene: shell-harness readiness, build-script prerequisites, pipe-to-shell scripts, committed binaries, CI toolchain skew, and license presence.

## Goals

The adversary is designed to produce a small number of high-confidence,
actionable findings grounded in concrete repository evidence. Its review should
be deterministic where possible, explicit about impact, and quiet when the
available evidence does not justify a finding.

## Scope

It evaluates Go repository structure and automation for service readiness in shell harnesses, toolchain alignment, generated artifacts, licensing, scripts, tooling pins, and CI validation.

The complete detector or review inventory is maintained in
[CHECKS.md](CHECKS.md).

## Boundaries

It owns only this Go specialty. Other Go concerns remain with the corresponding `go/*` adversaries, and it does not execute or modify the target repository.
