# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `go-project.ci-toolchain-skew` | High | CI builds with a different Go version than the module declares |
| `go-project.committed-binary` | High | Compiled executables committed to the repository |
| `go-project.editor-junk` | Low | Editor/OS junk committed (`.DS_Store`, `.idea/`, `*.swp`, `Thumbs.db`) |
| `go-project.license-missing` | Low | Published module with no LICENSE file |
| `go-project.script-curl-bash` | High | Makefile / Taskfile / repo script pipes remote content to a shell |
| `go-project.stale-mockery-verification` | Medium | A changed mockery verification script regenerates and checks git without first removing tracked generated mocks |
| `go-project.undocumented-cli-prerequisite` | Low | A changed repository script requires a known nonstandard CLI omitted from contributor setup documentation |
| `go-project.unpinned-go-install` | High | Build tooling installs a remote Go tool without an immutable version |
