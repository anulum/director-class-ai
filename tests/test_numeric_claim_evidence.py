# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — numeric claim evidence tests

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tools.check_numeric_claim_evidence import main, validate_numeric_claim_evidence

_ROOT = Path(__file__).resolve().parent.parent


def test_numeric_claim_guard_accepts_current_repository_surface() -> None:
    """Validate the real repository ledger against public claim surfaces."""
    assert validate_numeric_claim_evidence(_ROOT) == []
    assert main(("--repo-root", str(_ROOT))) == 0


def test_numeric_claim_guard_accepts_backed_metric_line(tmp_path: Path) -> None:
    """Accept a metric line quoted in the ledger and backed by JSON evidence."""
    _write_minimal_repo(
        tmp_path,
        readme="catastrophic recall: 1.000\n",
        evidence={"metrics": {"catastrophic_recall": 1.0}},
        quote="catastrophic recall: 1.000",
        pointer="/metrics/catastrophic_recall",
        expected=1.0,
    )

    assert validate_numeric_claim_evidence(tmp_path) == []


def test_numeric_claim_guard_rejects_uncovered_metric_line(tmp_path: Path) -> None:
    """Reject metric-like numeric prose that is absent from the claim ledger."""
    _write_minimal_repo(
        tmp_path,
        readme="catastrophic recall: 1.000\nfalse hard-block rate: 0.000\n",
        evidence={"metrics": {"catastrophic_recall": 1.0}},
        quote="catastrophic recall: 1.000",
        pointer="/metrics/catastrophic_recall",
        expected=1.0,
    )

    findings = validate_numeric_claim_evidence(tmp_path)

    assert len(findings) == 1
    assert findings[0].path == tmp_path / "README.md"
    assert findings[0].line == 2
    assert "metric-like numeric line" in findings[0].message


def test_numeric_claim_guard_rejects_stale_evidence_pointer(
    tmp_path: Path,
) -> None:
    """Reject a ledger assertion whose expected value drifts from evidence."""
    _write_minimal_repo(
        tmp_path,
        readme="catastrophic recall: 1.000\n",
        evidence={"metrics": {"catastrophic_recall": 0.5}},
        quote="catastrophic recall: 1.000",
        pointer="/metrics/catastrophic_recall",
        expected=1.0,
    )

    findings = validate_numeric_claim_evidence(tmp_path)

    assert any("expected 1.0, got 0.5" in finding.message for finding in findings)


def test_numeric_claim_cli_reports_relative_location(tmp_path: Path) -> None:
    """Exercise the CLI failure path over a real temporary repository."""
    _write_minimal_repo(
        tmp_path,
        readme="catastrophic recall: 1.000\nfalse escalation rate: 0.250\n",
        evidence={"metrics": {"catastrophic_recall": 1.0}},
        quote="catastrophic recall: 1.000",
        pointer="/metrics/catastrophic_recall",
        expected=1.0,
    )

    completed = subprocess.run(
        [
            sys.executable,
            str(_ROOT / "tools" / "check_numeric_claim_evidence.py"),
            "--repo-root",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "README.md:2" in completed.stdout
    assert "validation/numeric_claim_evidence.json" in completed.stdout


def test_numeric_claim_guard_rejects_missing_quote(tmp_path: Path) -> None:
    """Reject ledger quotes that no longer exist in their claimed surface."""
    _write_minimal_repo(
        tmp_path,
        readme="catastrophic recall: 1.000\n",
        evidence={"metrics": {"catastrophic_recall": 1.0}},
        quote="catastrophic recall: 0.500",
        pointer="/metrics/catastrophic_recall",
        expected=1.0,
    )

    findings = validate_numeric_claim_evidence(tmp_path)

    assert any("quote is not in README.md" in finding.message for finding in findings)


def _write_minimal_repo(
    repo: Path,
    *,
    readme: str,
    evidence: object,
    quote: str,
    pointer: str,
    expected: object,
) -> None:
    """Create a minimal claim-surface repository for validator tests."""
    (repo / "README.md").write_text(readme, encoding="utf-8")
    evidence_path = repo / "benchmarks/results/action_plane_evidence.json"
    evidence_path.parent.mkdir(parents=True)
    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    spec_path = repo / "validation/numeric_claim_evidence.json"
    spec_path.parent.mkdir(parents=True)
    spec = {
        "schema_version": "director-class-ai.numeric-claim-evidence.v1",
        "scan_surfaces": ["README.md"],
        "allow_line_patterns": [],
        "claims": [
            {
                "id": "readme-test-claim",
                "surface": "README.md",
                "quote": quote,
                "claim_boundary": "temporary test claim",
                "evidence": [
                    {
                        "path": "benchmarks/results/action_plane_evidence.json",
                        "json_pointers": [
                            {
                                "pointer": pointer,
                                "equals": expected,
                            }
                        ],
                    }
                ],
            }
        ],
    }
    spec_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
