# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — policy governance CLI tests

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from director_class_ai.cli.policy import main


def _section(payload: Mapping[str, object], key: str) -> Mapping[str, object]:
    """Return a nested mapping field of a CLI result, asserting its type."""
    value = payload[key]
    assert isinstance(value, Mapping), f"{key} is not a mapping: {type(value)!r}"
    return value


def _rows(payload: Mapping[str, object], key: str) -> Sequence[Mapping[str, object]]:
    """Return a sequence-of-mappings field of a CLI result, asserting its shape."""
    value = payload[key]
    assert isinstance(value, Sequence) and not isinstance(value, (str, bytes)), (
        f"{key} is not a non-text sequence: {type(value)!r}"
    )
    rows: list[Mapping[str, object]] = []
    for item in value:
        assert isinstance(item, Mapping), f"{key} item is not a mapping: {type(item)!r}"
        rows.append(item)
    return rows


def _str(mapping: Mapping[str, object], key: str) -> str:
    """Return a string field of a mapping, asserting the value is a string."""
    value = mapping[key]
    assert isinstance(value, str), f"{key} is not a str: {type(value)!r}"
    return value


def _profile_toml(
    path: Path, *, threshold: float, capability_profile: str = "deny_all_actions"
) -> Path:
    path.write_text(
        f'name = "staging"\naction_block_threshold = {threshold}\n'
        "uncertainty_margin = 0.0\n"
        f'capability_profile = "{capability_profile}"\n',
        encoding="utf-8",
    )
    return path


def _cases_json(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "label": "c1",
                        "signals": [
                            {
                                "detector": "d",
                                "plane": "action",
                                "score": 0.5,
                                "locus": "action",
                                "signal_type": "destructive_command",
                                "severity": "high",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


def _capability_cases_json(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "cases": [
                    {
                        "label": "workspace-read",
                        "provenance": "user",
                        "signals": [],
                        "capability_context": {
                            "subject": "agent-a",
                            "tenant": "tenant-a",
                            "session": "session-a",
                            "source_origin": "user",
                            "tool": "fs/read_file",
                            "resource": "workspace:README.md",
                            "action": "read",
                            "blast_radius": "low",
                            "now": 10,
                        },
                        "capability_grants": [
                            {
                                "grant_id": "read-workspace",
                                "subject": "agent-a",
                                "tenant": "tenant-a",
                                "session": "session-a",
                                "source_origin": "user",
                                "tool": "fs/read_file",
                                "resource": "workspace:README.md",
                                "action": "read",
                                "max_blast_radius": "low",
                                "expires_at": 20,
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


def _run(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict[str, object]]:
    rc = main(argv)
    out = capsys.readouterr().out
    return rc, (json.loads(out) if out.strip() else {})


def _approved_baseline(
    store: Path, profile: Path, capsys: pytest.CaptureFixture[str]
) -> str:
    _profile_toml(profile, threshold=0.3)
    rc, proposal = _run(
        [
            "propose",
            "--store",
            str(store),
            "--profile",
            str(profile),
            "--proposer",
            "alice",
            "--reason",
            "baseline",
            "--at",
            "t0",
        ],
        capsys,
    )
    assert rc == 0
    digest = proposal["digest"]
    assert isinstance(digest, str)
    rc, _ = _run(
        [
            "approve",
            "--store",
            str(store),
            "--digest",
            digest,
            "--reviewer",
            "bob",
            "--at",
            "t1",
        ],
        capsys,
    )
    assert rc == 0
    return digest


def test_status_on_fresh_store(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, result = _run(["status", "--store", str(tmp_path / "gov.json")], capsys)
    assert rc == 0
    assert result["head_digest"] is None


def test_propose_then_status_shows_pending(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = tmp_path / "gov.json"
    profile = _profile_toml(tmp_path / "p.toml", threshold=0.3)
    rc, proposal = _run(
        [
            "propose",
            "--store",
            str(store),
            "--profile",
            str(profile),
            "--proposer",
            "alice",
            "--reason",
            "baseline",
            "--at",
            "t0",
        ],
        capsys,
    )
    assert rc == 0
    assert proposal["status"] == "pending"
    rc, status = _run(["status", "--store", str(store)], capsys)
    assert status["pending"] == 1


def test_propose_defaults_timestamp_when_omitted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = tmp_path / "gov.json"
    profile = _profile_toml(tmp_path / "p.toml", threshold=0.3)
    rc, proposal = _run(
        [
            "propose",
            "--store",
            str(store),
            "--profile",
            str(profile),
            "--proposer",
            "alice",
            "--reason",
            "baseline",
        ],
        capsys,
    )
    assert rc == 0
    assert _section(proposal, "revision")["created_at"]  # a timestamp was filled in


def test_approve_commits_head(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    store = tmp_path / "gov.json"
    _approved_baseline(store, tmp_path / "p.toml", capsys)
    rc, status = _run(["status", "--store", str(store)], capsys)
    assert rc == 0
    assert status["head_profile"] == "staging"
    assert status["revisions"] == 1


def test_self_approval_is_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = tmp_path / "gov.json"
    profile = _profile_toml(tmp_path / "p.toml", threshold=0.3)
    _, proposal = _run(
        [
            "propose",
            "--store",
            str(store),
            "--profile",
            str(profile),
            "--proposer",
            "alice",
            "--reason",
            "baseline",
            "--at",
            "t0",
        ],
        capsys,
    )
    rc = main(
        [
            "approve",
            "--store",
            str(store),
            "--digest",
            _str(proposal, "digest"),
            "--reviewer",
            "alice",
            "--at",
            "t1",
        ]
    )
    err = capsys.readouterr().err
    assert rc == 1
    assert "error:" in err


def test_deny_marks_pending_proposal_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = tmp_path / "gov.json"
    profile = _profile_toml(tmp_path / "p.toml", threshold=0.3)
    rc, proposal = _run(
        [
            "propose",
            "--store",
            str(store),
            "--profile",
            str(profile),
            "--proposer",
            "alice",
            "--reason",
            "candidate",
            "--at",
            "t0",
        ],
        capsys,
    )
    assert rc == 0

    rc, denied = _run(
        [
            "deny",
            "--store",
            str(store),
            "--digest",
            _str(proposal, "digest"),
            "--reviewer",
            "bob",
            "--at",
            "t1",
        ],
        capsys,
    )

    assert rc == 0
    assert denied["status"] == "denied"
    assert denied["reviewer"] == "bob"


def test_expose_reports_transitions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = tmp_path / "gov.json"
    _approved_baseline(store, tmp_path / "p.toml", capsys)
    candidate = _profile_toml(tmp_path / "cand.toml", threshold=0.7)
    cases = _cases_json(tmp_path / "cases.json")
    rc, report = _run(
        [
            "expose",
            "--store",
            str(store),
            "--candidate",
            str(candidate),
            "--cases",
            str(cases),
        ],
        capsys,
    )
    assert rc == 0
    assert report["transitions"] == {"block->allow": 1}
    assert report["changed_count"] == 1


def test_expose_replays_capability_context_and_grants(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = tmp_path / "gov.json"
    _approved_baseline(store, tmp_path / "p.toml", capsys)
    candidate = _profile_toml(
        tmp_path / "cand.toml",
        threshold=0.3,
        capability_profile="local_operator_actions",
    )
    cases = _capability_cases_json(tmp_path / "cases.json")

    rc, report = _run(
        [
            "expose",
            "--store",
            str(store),
            "--candidate",
            str(candidate),
            "--cases",
            str(cases),
        ],
        capsys,
    )

    assert rc == 0
    assert report["transitions"] == {"block->allow": 1}
    assert report["changed"] == ["workspace-read"]


def test_rollback_requires_second_reviewer_approval(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = tmp_path / "gov.json"
    baseline_digest = _approved_baseline(store, tmp_path / "p.toml", capsys)
    candidate = _profile_toml(tmp_path / "cand.toml", threshold=0.7)
    _, proposal = _run(
        [
            "propose",
            "--store",
            str(store),
            "--profile",
            str(candidate),
            "--proposer",
            "alice",
            "--reason",
            "relax",
            "--at",
            "t2",
        ],
        capsys,
    )
    rc, relaxed = _run(
        [
            "approve",
            "--store",
            str(store),
            "--digest",
            _str(proposal, "digest"),
            "--reviewer",
            "bob",
            "--at",
            "t3",
        ],
        capsys,
    )
    assert rc == 0
    assert relaxed["digest"] == proposal["digest"]

    rc, rollback = _run(
        [
            "rollback",
            "--store",
            str(store),
            "--digest",
            baseline_digest,
            "--author",
            "bob",
            "--reason",
            "revert",
            "--at",
            "t4",
        ],
        capsys,
    )
    assert rc == 0
    assert rollback["status"] == "pending"
    assert rollback["digest"] == baseline_digest

    rc, status = _run(["status", "--store", str(store)], capsys)
    assert rc == 0
    assert status["head_digest"] == relaxed["digest"]
    assert status["pending"] == 1

    rc, restored = _run(
        [
            "approve",
            "--store",
            str(store),
            "--digest",
            rollback["digest"],
            "--reviewer",
            "carol",
            "--at",
            "t5",
        ],
        capsys,
    )
    assert rc == 0
    assert restored["digest"] == baseline_digest


def test_drift_detected_and_absent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = tmp_path / "gov.json"
    _approved_baseline(store, tmp_path / "p.toml", capsys)
    drifted = _profile_toml(tmp_path / "live.toml", threshold=0.9)
    rc, result = _run(
        ["drift", "--store", str(store), "--live", str(drifted), "--at", "t9"],
        capsys,
    )
    assert rc == 0
    assert result["drift"] is True
    assert _rows(_section(result, "event"), "changes")[0]["field"] == (
        "action_block_threshold"
    )

    matching = _profile_toml(tmp_path / "same.toml", threshold=0.3)
    rc, result = _run(
        ["drift", "--store", str(store), "--live", str(matching), "--at", "t9"],
        capsys,
    )
    assert rc == 0
    assert result["drift"] is False
