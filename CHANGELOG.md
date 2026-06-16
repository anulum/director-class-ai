# Changelog

## [Unreleased]
### Added
- Effector-boundary Governor: mandatory fail-closed checkpoint with
  human-approval hook and an immutable, privacy-preserving audit trail.
- LLM-judge detector tier + JudgePanel (diverse, specialised, escalation-only,
  self-consistency); raises risk only, never clears a deterministic block.
- Fusion uncertainty band: borderline / split-panel risk escalates to a human.
- Plane-agnostic detector signal and protocol (content / integrity / action).
- Plane-aware fusion: fail-open content, fail-closed action with human escalation.
- ParallelEnsembleScorer: concurrent, tiered detector dispatch.
- Destructive-command detector (action-plane kill-switch core).
- Repository engineering gates: CI (test/lint/types/SAST), pre-commit, coverage gate.
- Recursive multi-layer command decoder (nested base64, hex escapes, command
  substitution), bounded depth/breadth.
- Action-command de-obfuscation pre-layer (split-flag merge, quote/backslash-break
  removal, base64-of-shell-pipe decode, alias extraction) + find -delete/-exec rule;
  5/5 previously-missed evasions now caught, safe lookalikes stay clean.
- Mixed-threat robustness benchmark (full ensemble 0.938 vs action-only 0.875,
  content-only 0.562).
- Content-plane adapters (token-span, contradiction) over director-ai.
- Per-detector Platt calibration wired into the ensemble.
- Action plane: destructive-command, blast-radius, origin-taint, intent-consistency.
