# go/project — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `go-project`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Go repository hygiene and contributor tooling

## Mission

Review Go repository hygiene: scripts, documented external tool prerequisites, binaries, CI toolchain skew, and licenses.

## In scope (fair miss if humans raised it and we did not)

- Pipe-to-shell install scripts
- Changed scripts that require a known nonstandard CLI omitted from contributor setup documentation
- Mockery generated-file verifiers that cannot expose stale tracked mocks
- Committed binaries
- CI Go toolchain skew
- Missing license hygiene

## Out of scope (not a miss for this adversary)

- Deep application concurrency/security
- Workflow security (github-actions)

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
