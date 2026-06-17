# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — audit export CLI tests

from __future__ import annotations

import json
import tomllib
from pathlib import Path

from director_class_ai.action import DestructiveCommandDetector
from director_class_ai.audit import AuditChainSink, AuditExportOptions, run_export
from director_class_ai.audit.export_cli import main
from director_class_ai.core import EvaluationRequest, Governor, ParallelEnsembleScorer

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


class _Clock:
    def __init__(self) -> None:
        self.t = 100.0

    def __call__(self) -> float:
        self.t += 1.0
        return self.t


def _populate(path: Path) -> None:
    governor = Governor(
        ensemble=ParallelEnsembleScorer([DestructiveCommandDetector()]),
        audit_sink=AuditChainSink(path=path, policy_profile="pilot", clock=_Clock()),
    )
    governor.review(EvaluationRequest(query="inspect", action="ls -la"))
    governor.review(EvaluationRequest(query="inspect", action="rm -rf /"))


def test_audit_export_options_parse_stdout_default(tmp_path: Path) -> None:
    source = tmp_path / "audit.jsonl"

    options = AuditExportOptions.from_argv((str(source),))

    assert options.source == source
    assert options.output is None


def test_audit_export_options_parse_output_path(tmp_path: Path) -> None:
    source = tmp_path / "audit.jsonl"
    output = tmp_path / "soc.jsonl"

    options = AuditExportOptions.from_argv((str(source), "--output", str(output)))

    assert options.source == source
    assert options.output == output


def test_run_export_writes_verified_siem_jsonl(tmp_path: Path) -> None:
    source = tmp_path / "audit.jsonl"
    output = tmp_path / "soc.jsonl"
    _populate(source)

    result = run_export(AuditExportOptions(source=source, output=output))
    events = [
        json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()
    ]

    assert result.ok is True
    assert result.event_count == 2
    assert result.body == output.read_text(encoding="utf-8")
    assert events[1]["approval_state"] == "blocked"
    assert events[1]["chain_entry_hash"] == events[1]["decision_id"]
    assert "rm -rf /" not in repr(events)


def test_run_export_fails_closed_on_tampered_chain(tmp_path: Path) -> None:
    source = tmp_path / "audit.jsonl"
    output = tmp_path / "soc.jsonl"
    _populate(source)
    lines = source.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["risk"] = 0.0
    lines[1] = json.dumps(tampered)
    source.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = run_export(AuditExportOptions(source=source, output=output))

    assert result.ok is False
    assert result.event_count == 0
    assert "audit chain verification failed" in result.reason
    assert not output.exists()


def test_main_writes_stdout_jsonl(capsys, tmp_path: Path) -> None:
    source = tmp_path / "audit.jsonl"
    _populate(source)

    code = main((str(source),))
    captured = capsys.readouterr()
    events = [json.loads(line) for line in captured.out.splitlines()]

    assert code == 0
    assert captured.err == ""
    assert len(events) == 2
    assert events[0]["event_name"] == "director_class_ai.governance.decision"


def test_main_writes_output_file_without_stdout(capsys, tmp_path: Path) -> None:
    source = tmp_path / "audit.jsonl"
    output = tmp_path / "soc.jsonl"
    _populate(source)

    code = main((str(source), "--output", str(output)))
    captured = capsys.readouterr()

    assert code == 0
    assert captured.out == ""
    assert captured.err == ""
    assert len(output.read_text(encoding="utf-8").splitlines()) == 2


def test_main_returns_two_for_invalid_chain(capsys, tmp_path: Path) -> None:
    source = tmp_path / "audit.jsonl"
    source.write_text('{"seq": 1}\n', encoding="utf-8")

    code = main((str(source),))
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out == ""
    assert "audit chain verification failed" in captured.err


def test_siem_export_console_script_is_declared() -> None:
    with _PYPROJECT.open("rb") as handle:
        project = tomllib.load(handle)["project"]

    assert project["scripts"]["director-class-siem-export"] == (
        "director_class_ai.audit.export_cli:main"
    )
