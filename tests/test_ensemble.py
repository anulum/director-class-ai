# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — parallel ensemble runner tests

from __future__ import annotations

import threading
import time

import pytest

from director_class_ai.core import (
    DetectorSignal,
    EvaluationRequest,
    Locus,
    ParallelEnsembleScorer,
    Plane,
    Severity,
)
from director_class_ai.core.ensemble import ParallelEnsembleScorer as PES


class FakeDetector:
    """A detector that returns a fixed signal (or None) after an optional delay."""

    def __init__(
        self,
        name,
        plane,
        score,
        *,
        tier=0,
        sev=Severity.MEDIUM,
        locus=Locus.RESPONSE,
        delay=0.0,
        none=False,
    ):
        self.name = name
        self.plane = plane
        self.tier = tier
        self._score = score
        self._sev = sev
        self._locus = locus
        self._delay = delay
        self._none = none
        self.calls = 0

    def evaluate(self, request: EvaluationRequest):
        self.calls += 1
        if self._delay:
            time.sleep(self._delay)
        if self._none:
            return None
        return DetectorSignal(
            detector=self.name,
            plane=self.plane,
            score=self._score,
            locus=self._locus,
            signal_type="t",
            severity=self._sev,
        )


def test_requires_at_least_one_detector() -> None:
    with pytest.raises(ValueError, match="at least one"):
        PES([])


def test_fuses_signals_from_all_detectors() -> None:
    ens = PES(
        [
            FakeDetector("a", Plane.CONTENT, 0.9),
            FakeDetector("b", Plane.CONTENT, 0.1),
        ]
    )
    v = ens.evaluate(EvaluationRequest(response="x"))
    assert v.allow is False  # noisy-OR over 0.9 clears threshold
    assert Plane.CONTENT in v.plane_risk


def test_none_signals_are_dropped() -> None:
    ens = PES([FakeDetector("a", Plane.CONTENT, 0.0, none=True)])
    v = ens.evaluate(EvaluationRequest())
    assert v.allow is True
    assert v.firing == ()


def test_detectors_in_a_tier_run_concurrently() -> None:
    # three 0.1s detectors in the same tier should finish in ~0.1s, not ~0.3s
    dets = [
        FakeDetector(f"d{i}", Plane.CONTENT, 0.1, tier=0, delay=0.1) for i in range(3)
    ]
    ens = PES(dets, max_workers=3)
    t0 = time.perf_counter()
    ens.evaluate(EvaluationRequest())
    assert time.perf_counter() - t0 < 0.25


def test_cascade_short_circuits_on_critical_action_block() -> None:
    cheap = FakeDetector(
        "rule", Plane.ACTION, 0.99, tier=0, sev=Severity.CRITICAL, locus=Locus.ACTION
    )
    expensive = FakeDetector("model", Plane.CONTENT, 0.5, tier=1)
    ens = PES([cheap, expensive], cascade=True)
    v = ens.evaluate(EvaluationRequest(action="rm -rf /"))
    assert v.allow is False
    assert v.requires_human is True
    assert expensive.calls == 0  # tier 1 never ran — cascade saved the compute


def test_cascade_disabled_runs_all_tiers() -> None:
    cheap = FakeDetector(
        "rule", Plane.ACTION, 0.99, tier=0, sev=Severity.CRITICAL, locus=Locus.ACTION
    )
    expensive = FakeDetector("model", Plane.CONTENT, 0.5, tier=1)
    ens = PES([cheap, expensive], cascade=False)
    ens.evaluate(EvaluationRequest(action="rm -rf /"))
    assert expensive.calls == 1  # no early exit


def test_low_severity_action_does_not_short_circuit() -> None:
    # a LOW-severity action objection must not stop the cascade — only HIGH+ does
    low = FakeDetector(
        "weak", Plane.ACTION, 0.99, tier=0, sev=Severity.LOW, locus=Locus.ACTION
    )
    later = FakeDetector("model", Plane.CONTENT, 0.1, tier=1)
    ens = PES([low, later], cascade=True)
    ens.evaluate(EvaluationRequest(action="ls"))
    assert later.calls == 1


def test_single_detector_tier_no_threadpool() -> None:
    # exercises the single-member fast path
    ens = PES([FakeDetector("solo", Plane.CONTENT, 0.8)])
    v = ens.evaluate(EvaluationRequest())
    assert v.allow is False


def test_thread_safety_of_concurrent_dispatch() -> None:
    seen: set[int] = set()
    lock = threading.Lock()

    class Recorder(FakeDetector):
        def evaluate(self, request):
            with lock:
                seen.add(threading.get_ident())
            return super().evaluate(request)

    dets = [Recorder(f"d{i}", Plane.CONTENT, 0.1, delay=0.05) for i in range(4)]
    PES(dets, max_workers=4).evaluate(EvaluationRequest())
    assert len(seen) >= 2  # genuinely ran on multiple threads


def test_exports_from_package_root() -> None:
    assert ParallelEnsembleScorer is PES
