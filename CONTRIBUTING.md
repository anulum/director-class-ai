<!-- SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial -->
# Contributing — Director-Class AI (internal)

Proprietary product (see `LICENSE`); internal contribution guide.

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

Design and decisions live in `docs/internal/` (ARCHITECTURE, PLAN, ADVERSARIAL,
AUDIT_INDEX). Append audit findings to `docs/internal/AUDIT_INDEX.md`.
