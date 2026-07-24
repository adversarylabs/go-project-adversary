# Go Project adversary

Go Project reviews repository-level package boundaries, ownership, dependency direction, and maintainability without prescribing one canonical layout.

The initial review focuses on exported mutable package state, implicit `init` lifecycle, and catch-all packages that obscure domain ownership.

## Fixtures and calibration

Five graded fixtures own expected review snapshots. The 61-repository corpus spans project layouts and package-boundary tradeoffs.

## Automatic detection

`adversary auto` selects Go Project for Go source or module/workspace changes. Full semantic change scoping will use runtime package-graph capabilities when available.

## Development

Run `npm test`, `adversary validate .`, and `adversary pack --check .`.
