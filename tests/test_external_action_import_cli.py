# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — external action import CLI tests

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.external_action_surfaces import load_external_cases
from tools.import_external_action_surface import (
    ExternalImportOptions,
    import_external_surface,
    main,
)


def _manifest(tmp_path: Path) -> Path:
    path = tmp_path / "MANIFEST.md"
    path.write_text(
        "\n".join(
            [
                "# External Action Surfaces",
                "",
                "| Surface | Threat taxonomy | Licence | Provenance | "
                "Local artefact | Status |",
                "|---|---|---|---|---|---|",
                "| AllowedBench-style | reviewed action risk | MIT | local | "
                "allowed.jsonl | absent |",
                "| BlockedBench-style | unreviewed action risk | unknown | local | "
                "blocked.jsonl | absent |",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _ledger(tmp_path: Path) -> Path:
    path = tmp_path / "SOURCE_LEDGER.json"
    path.write_text(
        json.dumps(
            [
                {
                    "surface": "AllowedBench-style",
                    "upstream_url": "https://example.test/allowed",
                    "licence": "MIT",
                    "licence_url": "https://example.test/license",
                    "licence_status": "allow",
                    "provenance_review": "local fixture allowed",
                    "import_allowed": True,
                    "reviewed_at": "2026-06-18",
                },
                {
                    "surface": "BlockedBench-style",
                    "upstream_url": "https://example.test/blocked",
                    "licence": "not verified",
                    "licence_url": "",
                    "licence_status": "requires_review",
                    "provenance_review": "not reviewed",
                    "import_allowed": False,
                    "reviewed_at": "2026-06-18",
                },
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _jsonl(tmp_path: Path, *, row_id: str = "case-1") -> Path:
    path = tmp_path / "input.jsonl"
    path.write_text(
        json.dumps(
            {
                "id": row_id,
                "action": "rm -rf /",
                "label": "catastrophic",
                "category": "external-shell",
                "severity": "critical",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def test_import_external_surface_copies_allowed_jsonl_and_receipt(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    ledger = _ledger(tmp_path)
    source_jsonl = _jsonl(tmp_path)

    receipt = import_external_surface(
        ExternalImportOptions(
            surface="AllowedBench-style",
            input_jsonl=source_jsonl,
            manifest=manifest,
            source_ledger=ledger,
        )
    )
    target = tmp_path / "allowed.jsonl"
    receipt_path = tmp_path / "allowed.jsonl.import.json"

    assert target.read_text(encoding="utf-8") == source_jsonl.read_text(encoding="utf-8")
    assert receipt["surface"] == "AllowedBench-style"
    assert receipt["row_count"] == 1
    assert receipt["licence_status"] == "allow"
    assert json.loads(receipt_path.read_text(encoding="utf-8"))["source_sha256"]
    cases = load_external_cases(manifest, review_path=ledger)
    assert cases[0]["external_surface"] == "AllowedBench-style"


def test_import_external_surface_refuses_blocked_review(tmp_path: Path) -> None:
    options = ExternalImportOptions(
        surface="BlockedBench-style",
        input_jsonl=_jsonl(tmp_path),
        manifest=_manifest(tmp_path),
        source_ledger=_ledger(tmp_path),
    )

    code = main(
        (
            "--surface",
            options.surface,
            "--input-jsonl",
            str(options.input_jsonl),
            "--manifest",
            str(options.manifest),
            "--source-ledger",
            str(options.source_ledger),
        )
    )

    assert code == 2
    assert not (tmp_path / "blocked.jsonl").exists()


def test_import_external_surface_refuses_replace_without_flag(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    ledger = _ledger(tmp_path)
    source_jsonl = _jsonl(tmp_path)
    options = ExternalImportOptions(
        surface="AllowedBench-style",
        input_jsonl=source_jsonl,
        manifest=manifest,
        source_ledger=ledger,
    )

    import_external_surface(options)

    assert (
        main(
            (
                "--surface",
                "AllowedBench-style",
                "--input-jsonl",
                str(source_jsonl),
                "--manifest",
                str(manifest),
                "--source-ledger",
                str(ledger),
            )
        )
        == 2
    )
    assert (
        main(
            (
                "--surface",
                "AllowedBench-style",
                "--input-jsonl",
                str(source_jsonl),
                "--manifest",
                str(manifest),
                "--source-ledger",
                str(ledger),
                "--replace",
            )
        )
        == 0
    )


def test_import_external_surface_refuses_bad_schema(tmp_path: Path) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({"id": "bad", "label": "safe"}) + "\n", encoding="utf-8")

    code = main(
        (
            "--surface",
            "AllowedBench-style",
            "--input-jsonl",
            str(bad),
            "--manifest",
            str(_manifest(tmp_path)),
            "--source-ledger",
            str(_ledger(tmp_path)),
        )
    )

    assert code == 2
    assert not (tmp_path / "allowed.jsonl").exists()
