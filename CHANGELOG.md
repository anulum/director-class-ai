# Changelog

## [Unreleased]
### Added
- Plane-agnostic detector signal and protocol (content / integrity / action).
- Plane-aware fusion: fail-open content, fail-closed action with human escalation.
- ParallelEnsembleScorer: concurrent, tiered detector dispatch.
- Destructive-command detector (action-plane kill-switch core).
- Repository engineering gates: CI (test/lint/types/SAST), pre-commit, coverage gate.
