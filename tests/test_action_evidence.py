# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — action benchmark evidence tests

from __future__ import annotations

from benchmarks.action_evidence import (
    BenchmarkEvidence,
    RunContext,
    classify_evidence,
    render_markdown_report,
)


def _context(*, isolated: bool) -> RunContext:
    return RunContext(
        command="python -m benchmarks.action_evidence",
        git_sha="abc123",
        affinity="0" if isolated else "none",
        isolation_method="sched_setaffinity" if isolated else "none",
        host_load_before=(1.0, 2.0, 3.0),
        host_load_after=(1.5, 2.1, 3.1),
        cpu_governor=("performance",),
        python_version="3.12.3",
        platform="Linux-test",
        dependency_hashes={"requirements/dev.txt": "0" * 64},
        heavy_jobs_disclosure="none observed",
    )


def _metrics(*, external_n: int) -> dict[str, object]:
    authored = {
        "n": 2,
        "catastrophic_recall": 1.0,
        "false_block_rate": 0.0,
        "false_escalation_rate": 0.0,
        "safe_route_conformance": 1.0,
    }
    external = dict(authored, n=external_n)
    return {
        "benchmark": "action_plane",
        "n": 2,
        "catastrophic_recall": 1.0,
        "false_block_rate": 0.0,
        "false_escalation_rate": 0.0,
        "safe_route_conformance": 1.0,
        "authored_metrics": authored,
        "external_metrics": external,
        "elapsed_ms": 12.5,
    }


def test_evidence_classification_respects_isolation_and_external_data() -> None:
    assert classify_evidence(isolated=False, external_count=3).startswith(
        "local-regression-non-isolated"
    )
    assert classify_evidence(isolated=True, external_count=0).startswith(
        "isolated-internal-only"
    )
    assert classify_evidence(isolated=True, external_count=1).startswith(
        "isolated-with-external-artefacts"
    )


def test_run_context_json_records_required_metadata() -> None:
    payload = _context(isolated=True).to_json()

    assert payload["isolated"] is True
    assert payload["affinity"] == "0"
    assert payload["isolation_method"] == "sched_setaffinity"
    assert payload["host_load_before"] == (1.0, 2.0, 3.0)
    assert payload["dependency_hashes"] == {"requirements/dev.txt": "0" * 64}


def test_markdown_report_keeps_claim_boundary_and_source_separation() -> None:
    evidence = BenchmarkEvidence(
        benchmark="action_plane",
        evidence_grade=classify_evidence(isolated=False, external_count=0),
        metrics=_metrics(external_n=0),
        run_context=_context(isolated=False),
        external_sources=(
            {
                "surface": "AgentDojo-style",
                "licence": "not vendored",
                "licence_status": "requires_review",
                "import_allowed": False,
                "status": "absent",
                "loaded": False,
            },
        ),
    )

    report = render_markdown_report(evidence)

    assert "authored n: 2" in report
    assert "external n: 0" in report
    assert "AgentDojo-style: loaded=False" in report
    assert "import_allowed=False" in report
    assert "Public comparative claims require isolated execution" in report
