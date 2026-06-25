# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — parallel multi-detector ensemble runner

"""Run many detectors concurrently, tier by tier, and fuse them into a verdict.

The runner does three things the fusion layer cannot:

* **Parallelism.** Detectors are independent, so a tier's detectors run together
  in a thread pool. Model detectors release the GIL during inference, so the
  wall-clock for a tier is its slowest detector, not the sum.
* **Tiered cascade.** ``Detector.tier`` orders the work cheap-first. The runner
  evaluates one tier, decides whether the verdict is already settled, and only
  then pays for the next (more expensive) tier. This is what keeps the redundant
  ensemble affordable: the cheap tier clears or blocks the vast majority of
  traffic in microseconds, and only the genuinely ambiguous or high-blast-radius
  case escalates to the full model ensemble.
* **One verdict.** All signals gathered so far are fused after each tier (and
  finally), so the caller always gets a complete :class:`Verdict`.

Early-exit is deliberately conservative for the action plane: a confident
high-severity objection short-circuits (no point scoring content once we are
blocking a destructive command), but the runner never *allows* early — silence
from a cheap tier is not consent, so allowing always requires the configured
tiers to have run.
"""

from __future__ import annotations

from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor

from .calibration import CalibrationRegistry
from .fusion import FusionPolicy, Verdict, fuse
from .signal import Detector, DetectorSignal, EvaluationRequest, Plane, Severity

__all__ = ["ParallelEnsembleScorer"]


class ParallelEnsembleScorer:
    """Concurrent, tiered detector ensemble producing a fused governance verdict."""

    def __init__(
        self,
        detectors: Sequence[Detector],
        *,
        policy: FusionPolicy | None = None,
        calibration: CalibrationRegistry | None = None,
        max_workers: int | None = None,
        cascade: bool = True,
    ) -> None:
        if not detectors:
            raise ValueError("at least one detector is required")
        self._detectors = list(detectors)
        self._policy = policy or FusionPolicy()
        self._calibration = calibration
        self._max_workers = max_workers
        self._cascade = cascade
        self._tiers = sorted({d.tier for d in self._detectors})

    def _run_tier(self, tier: int, request: EvaluationRequest) -> list[DetectorSignal]:
        members = [d for d in self._detectors if d.tier == tier]
        if len(members) == 1:
            sig = members[0].evaluate(request)
            signals = [sig] if sig is not None else []
        else:
            with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
                results = pool.map(lambda d: d.evaluate(request), members)
            signals = [s for s in results if s is not None]
        if self._calibration is not None:
            signals = [self._calibration.apply(s) for s in signals]
        return signals

    def _settled_block(self, signals: Sequence[DetectorSignal]) -> bool:
        """Return whether a confident high-severity action objection already blocks.

        Only blocking short-circuits — allowing never does (fail-closed).
        """
        return any(
            s.plane is Plane.ACTION
            and s.severity >= Severity.HIGH
            and s.weighted_score >= self._policy.action_block_threshold
            for s in signals
        )

    def evaluate(self, request: EvaluationRequest) -> Verdict:
        """Score *request* across all detectors and return the fused verdict."""
        collected: list[DetectorSignal] = []
        for tier in self._tiers:
            collected.extend(self._run_tier(tier, request))
            if self._cascade and self._settled_block(collected):
                break
        return fuse(collected, self._policy, provenance=request.action_provenance)
