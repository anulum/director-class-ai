# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — human approval CLI tests

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest

from director_class_ai.approvals import ApprovalQueue
from director_class_ai.cli.approve import main
from director_class_ai.core.governor import digest_request
from director_class_ai.core.signal import EvaluationRequest

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _open_ticket(store: Path, action: str = "rm -rf /") -> str:
    """Open a pending ticket the way the guard does, and return its digest."""
    request = EvaluationRequest(action=action)
    ApprovalQueue(str(store)).request_approval(None, request)
    return digest_request(request)


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, object]:
    rc = main(argv)
    out = capsys.readouterr().out
    return rc, (json.loads(out) if out.strip() else None)


def test_pending_is_empty_on_a_fresh_store(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, result = _run(["pending", "--store", str(tmp_path / "q.json")], capsys)
    assert rc == 0
    assert result == []


def test_pending_lists_open_tickets(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = tmp_path / "q.json"
    digest = _open_ticket(store)
    rc, result = _run(["pending", "--store", str(store)], capsys)
    assert rc == 0
    assert isinstance(result, list)
    assert [t["digest"] for t in result] == [digest]
    assert result[0]["status"] == "pending"


def test_approve_marks_the_ticket_approved(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = tmp_path / "q.json"
    digest = _open_ticket(store)
    rc, result = _run(
        ["approve", "--store", str(store), "--digest", digest, "--approver", "alice"],
        capsys,
    )
    assert rc == 0
    assert isinstance(result, dict)
    assert result["status"] == "approved"
    assert result["approver"] == "alice"
    # no longer pending
    rc, pending = _run(["pending", "--store", str(store)], capsys)
    assert pending == []


def test_deny_marks_the_ticket_denied(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = tmp_path / "q.json"
    digest = _open_ticket(store)
    rc, result = _run(
        ["deny", "--store", str(store), "--digest", digest, "--approver", "bob"],
        capsys,
    )
    assert rc == 0
    assert isinstance(result, dict)
    assert result["status"] == "denied"


def test_show_returns_a_ticket_and_errors_on_unknown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = tmp_path / "q.json"
    digest = _open_ticket(store)
    rc, result = _run(["show", "--store", str(store), "--digest", digest], capsys)
    assert rc == 0
    assert isinstance(result, dict)
    assert result["digest"] == digest

    rc = main(["show", "--store", str(store), "--digest", "deadbeef"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "no ticket" in err


def test_approve_unknown_digest_exits_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(
        [
            "approve",
            "--store",
            str(tmp_path / "q.json"),
            "--digest",
            "deadbeef",
            "--approver",
            "alice",
        ]
    )
    err = capsys.readouterr().err
    assert rc == 1
    assert "error:" in err


def test_approve_already_decided_ticket_exits_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = tmp_path / "q.json"
    digest = _open_ticket(store)
    ApprovalQueue(str(store)).deny(digest, "bob")
    rc = main(
        ["approve", "--store", str(store), "--digest", digest, "--approver", "alice"]
    )
    err = capsys.readouterr().err
    assert rc == 1
    assert "not pending" in err


def test_console_script_is_declared() -> None:
    with _PYPROJECT.open("rb") as handle:
        project = tomllib.load(handle)["project"]

    assert project["scripts"]["director-class-approve"] == (
        "director_class_ai.cli.approve:main"
    )
