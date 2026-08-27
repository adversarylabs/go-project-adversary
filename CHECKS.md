# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `go-project.ci-toolchain-skew` | High | CI builds with a different Go version than the module declares |
| `go-project.committed-binary` | High | Compiled executables committed to the repository |
| `go-project.editor-junk` | Low | Editor/OS junk committed (`.DS_Store`, `.idea/`, `*.swp`, `Thumbs.db`) |
| `go-project.license-missing` | Low | Published module with no LICENSE file |
| `go-project.script-curl-bash` | High | Makefile / Taskfile / repo script pipes remote content to a shell |
| `go-project.docker-start-without-readiness` | Medium | Changed shell harness starts Docker and reaches a daemon operation without a proven readiness gate |
| `go-project.stale-mockery-verification` | Medium | A changed mockery verification script regenerates and checks git without first removing tracked generated mocks |
| `go-project.undocumented-cli-prerequisite` | Low | A changed repository script requires a known nonstandard CLI omitted from contributor setup documentation |
| `go-project.unpinned-go-install` | High | Build tooling installs a remote Go tool without an immutable version |

## Docker start/readiness contract

`go-project.docker-start-without-readiness` is intentionally narrower than a generic service-start heuristic. It requires one locally invoked function in a changed shell script to start `docker.service` and then reach a Docker daemon operation without an intervening readiness proof. It recognizes the literal `docker` client and an `OCI_BIN` binding whose local default is proven to be Docker.

The check stays quiet for the accepted bounded readiness-helper shape from bpfman/bpfman#1577, direct fail-closed `docker info` gates, unrelated services, no downstream daemon use, reassigned/dynamic client aliases, uninvoked or duplicate helper definitions, statically dead calls, comments, quoted examples, heredocs, unchanged legacy relationships, argument-only edits to a legacy use, and deletion-only changes with no current semantic anchor.

Evidence is anchored to the changed start, dependent use, or changed current statement that activates a new relationship. One finding groups the start and first reachable dependent operation in that function; uncertain cross-function execution is deliberately left unreported.
