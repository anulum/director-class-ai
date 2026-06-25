<!-- SPDX-License-Identifier: BUSL-1.1 -->
# Contributing — Director-Class AI (internal)

Source-available under the Business Source License 1.1 (see `LICENSE`); internal
contribution guide.

## Standard

Every change keeps the repo green to the GOTM standard:

- **Tests + coverage:** `make test` — 100% coverage is the gate.
- **Style:** `make lint` (ruff check + format). Auto-fix with `make fmt`.
- **Types:** `make types` — `mypy --strict`, no untyped defs.
- **SAST:** `make sast` (bandit + semgrep).
- **SPDX:** every source file carries the SPDX header (`make spdx`, enforced in
  pre-commit).
- **Full gate:** `make preflight` before every commit.

## Conventions

- Core (`core/`, `action/`) stays **zero-dependency**; model-backed work lives in
  `detectors/` behind the `[detectors]` extra.
- The action plane is **fail-closed**: a blocked verdict never executes, and an
  escalation needs an explicit human approval (never silently allowed).
- No raw action/prompt text in audit records — digests only.
- Commit messages end with the authorship trailer.

## Records

Public design notes live under `docs/`. Architecture, roadmap, audit, and
positioning records are maintained privately by the maintainers.
