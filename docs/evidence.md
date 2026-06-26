# Evidence and Benchmarks

Director-Class AI has local functional test and benchmark evidence. These
artefacts are useful for regression control and engineering review. They are not
a comparative benchmark claim and are not public comparative performance claims.

## Current Local Gates

The local gate stack covers:

- strict type checking with `mypy --strict director_class_ai`;
- Ruff linting and formatting over `director_class_ai`, `tests`, `benchmarks`,
  and `tools`;
- SPDX and public docstring checks;
- repository readiness and Phase 4 task-intake validation;
- full pytest coverage gate;
- Rust formatting, `cargo test`, Clippy, `maturin develop`, Rust/Python
  differential property tests, and the full pytest suite with the PyO3 extension
  present;
- sdist and wheel build.

## Action-Plane Benchmark

Run:

```bash
make bench-evidence
```

The evidence runner records command line, git SHA, optional CPU affinity,
host-load snapshots, CPU governor, Python/platform details, dependency hashes,
heavy-job disclosure, external-source load status, and JSON plus Markdown
reports.

Current committed benchmark evidence is local regression evidence:

- authored action cases: 356;
- external action cases: 0;
- customer/private cases: 0;
- catastrophic recall on authored cases: 1.000;
- false hard-block rate on authored safe cases: 0.000;
- safe route conformance on authored safe routed cases: 1.000.

## Adversarial Red Team

Run:

```bash
make redteam
```

The adversarial benchmark covers composed injection-to-action chains across
tool output, MCP arguments, browser/computer-use metadata, memory, delayed
objectives, plan drift, and safe controls. It is also local functional evidence.

## Claim Boundary

Public comparative claims require all of the following:

- reviewed external JSONL artefacts imported through
  `tools/import_external_action_surface.py`;
- external rows kept separate from authored and customer/private rows;
- isolated execution with CPU/core affinity or a reserved host, recorded host
  load, governor/frequency context, and heavy-job disclosure;
- refreshed JSON and Markdown evidence at the checked-out git SHA;
- remote CI and repository protection for the release commit.

Until those gates exist, describe the results as local functional regression
evidence.
