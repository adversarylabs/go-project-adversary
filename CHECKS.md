# Checks — what go-project detects

This file is the **public audit list** of detectors for the **go-project** adversary. High-confidence Go repository hygiene and build-integrity defects with file:line evidence — not a layout-opinion bot. Nothing here enforces `pkg/` vs flat layout, README quality, or naming taste.

Runtime source of truth: [`src/spec.ts`](src/spec.ts) / [`src/rules.ts`](src/rules.ts).

**Scope:** Repository-level files around the Go code: `Makefile`, `Taskfile`, shell scripts, committed binaries/artifacts, CI workflow Go-toolchain wiring, `.gitignore`, LICENSE. Module-graph concerns live in `go/modules`, not here.

**Precision stance:** Fire on supply-chain and reproducibility defects (pipe-to-shell in build scripts, opaque committed binaries, CI/toolchain version skew). Layout and documentation opinions are banned. Absence findings only where absence is a near-universal defect (e.g. no LICENSE on a published module) and always at low severity.

Public grounding: supply-chain guidance on pipe-to-shell installers, Go toolchain/CI version documentation, and git hygiene practices (github/gitignore).

---

## High

### `go-project.script-curl-bash`

| | |
| --- | --- |
| **What** | Makefile / Taskfile / repo script pipes remote content to a shell |
| **Why** | `curl … | sh` in build tooling executes attacker-controllable content on every dev machine and CI runner — same class as Dockerfile and CI pipe-to-shell |
| **Looks for** | `curl`/`wget` piped to `sh`/`bash` in `Makefile`, `Taskfile.yml`, `*.sh`, `tools/` scripts; `go install` of tools at `@latest` in bootstrap targets (lower severity variant) |
| **Stays quiet when** | Downloads verified against a pinned checksum before execution; tools installed at pinned versions |
| **Public examples** | Pipe-to-shell criticism is long-settled; the safe download-verify-execute pattern is the contrast |
| **Remediation** | Download to file, verify sha256, then execute; pin tool versions (`go install tool@v1.2.3`) |

### `go-project.committed-binary`

| | |
| --- | --- |
| **What** | Compiled executables committed to the repository |
| **Why** | Opaque binaries in git are unreviewable supply-chain risk (nobody diffs a Mach-O) and bloat every clone forever |
| **Looks for** | Files with ELF/Mach-O/PE magic bytes tracked outside `testdata/`; extension heuristics (`.exe`, extensionless executables with binary content) as secondary signal |
| **Stays quiet when** | Binaries under `testdata/` that tests demonstrably consume; small wasm/embed fixtures that are build products of in-repo source |
| **Public examples** | Supply-chain incidents hiding payloads in committed binaries; git-lfs guidance for genuinely needed artifacts |
| **Remediation** | Delete and build from source; use release artifacts or git-lfs for unavoidable blobs; add patterns to `.gitignore` |

### `go-project.ci-toolchain-skew`

| | |
| --- | --- |
| **What** | CI builds with a different Go version than the module declares |
| **Why** | "Passes CI, fails locally" (or worse, the reverse) — and version-gated behavior (loopvar, timer GC) silently differs between what you test and what you ship |
| **Looks for** | `setup-go` / CI `go-version:` values older than the `go` directive in `go.mod`, or hardcoded versions when `go.mod` has a `toolchain` directive (should use `go-version-file: go.mod`) |
| **Stays quiet when** | CI reads `go-version-file: go.mod`; intentional version matrices that *include* the module version |
| **Public examples** | actions/setup-go `go-version-file` support exists for exactly this; Go toolchain directive docs |
| **Remediation** | Point CI at `go.mod` (`go-version-file`) instead of duplicating the version |

---

## Medium

### `go-project.vet-race-not-in-ci`

| | |
| --- | --- |
| **What** | CI runs Go tests but never `go vet` or `-race` |
| **Why** | The two highest-value free defect detectors in the Go toolchain; several classes of bug (copied locks, data races) are only reliably caught here |
| **Looks for** | LLM-gated: CI workflows invoking `go test` with no `go vet` (or `golangci-lint`, which includes vet) and no `-race` on any test job |
| **Stays quiet when** | vet/race present in any CI job; golangci-lint configured; repos with no CI at all (nothing to anchor the finding to — do not fire) |
| **Public examples** | Go docs recommend vet in CI; race detector blog |
| **Remediation** | Add `go vet ./...` and a `-race` test job |

### `go-project.large-blob`

| | |
| --- | --- |
| **What** | Very large files (≥ 10 MB) tracked in git |
| **Why** | Permanent clone/fetch cost for every user and CI run; usually an accident (datasets, media, tarballs) |
| **Looks for** | Tracked files over threshold outside declared LFS patterns |
| **Stays quiet when** | Managed by git-lfs; deliberate corpora documented in the repo (downgrade to info) |
| **Public examples** | GitHub file-size guidance; git-lfs docs |
| **Remediation** | Move to LFS, release assets, or fetch-on-demand |

---

## Low

### `go-project.editor-junk`

| | |
| --- | --- |
| **What** | Editor/OS junk committed (`.DS_Store`, `.idea/`, `*.swp`, `Thumbs.db`) |
| **Why** | Noise in diffs, occasional local-path leakage; universally accepted as unwanted |
| **Looks for** | Those paths tracked in git |
| **Stays quiet when** | Absent, or explicitly gitignored |
| **Public examples** | github/gitignore templates |
| **Remediation** | Remove and add to `.gitignore` |

### `go-project.license-missing`

| | |
| --- | --- |
| **What** | Published module with no LICENSE file |
| **Why** | Legally unusable by most companies; pkg.go.dev won't display docs without a recognized license |
| **Looks for** | No LICENSE/COPYING at root when `go.mod` module path is on a public host (github.com/…) and repo is not marked private-by-convention |
| **Stays quiet when** | LICENSE present anywhere conventional; internal/private module paths |
| **Public examples** | pkg.go.dev license policy |
| **Remediation** | Add a LICENSE file |

---

## Out of scope (owned elsewhere)

| Concern | Owner |
| --- | --- |
| go.mod/go.sum, replace, toolchain directives | `go/modules` |
| CI workflow security (pins, permissions, injection) | `ci/github-actions` / `ci/depot` |
| Committed secrets | `security/secrets` |
| Dockerfile | `container/dockerfile` |
| Test quality | `go-testing` |

---

## Release gates (repo checklist)

- [ ] `npm test`
- [ ] `adversary validate .`
- [ ] `adversary pack --check .`
- [ ] Five graded fixture snapshots match
- [ ] Benchmark corpus contains 50–100 unique, reachable repositories
- [ ] Runtime artifact executes without `node_modules`
- [ ] No scanned repository writes or model calls
