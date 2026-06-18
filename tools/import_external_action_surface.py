# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — reviewed external benchmark import tool

"""Import reviewed external action benchmark JSONL artefacts.

The tool is intentionally narrow: it accepts an already-local JSONL export,
checks the source-review ledger, validates row schema, copies the artefact to the
manifest directory, and writes a deterministic import receipt. It never downloads
third-party data and never converts arbitrary upstream schemas automatically.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.external_action_surfaces import (
    CaseRow,
    ExternalSource,
    ExternalSourceReview,
    load_manifest,
    load_source_reviews,
    validate_external_case_rows,
)

_DEFAULT_MANIFEST = Path("benchmarks/external_sources/MANIFEST.md")
_DEFAULT_LEDGER = Path("benchmarks/external_sources/SOURCE_LEDGER.json")


@dataclass(frozen=True)
class ExternalImportOptions:
    """Runtime options for importing a reviewed external JSONL artefact."""

    surface: str
    input_jsonl: Path
    manifest: Path = _DEFAULT_MANIFEST
    source_ledger: Path = _DEFAULT_LEDGER
    replace: bool = False

    @classmethod
    def from_argv(cls, argv: Sequence[str] | None = None) -> ExternalImportOptions:
        """Parse command-line arguments into import options."""
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--surface", required=True)
        parser.add_argument("--input-jsonl", type=Path, required=True)
        parser.add_argument("--manifest", type=Path, default=_DEFAULT_MANIFEST)
        parser.add_argument("--source-ledger", type=Path, default=_DEFAULT_LEDGER)
        parser.add_argument(
            "--replace",
            action="store_true",
            help="Replace an existing local artefact after validation.",
        )
        args = parser.parse_args(argv)
        return cls(
            surface=args.surface,
            input_jsonl=args.input_jsonl,
            manifest=args.manifest,
            source_ledger=args.source_ledger,
            replace=args.replace,
        )


def import_external_surface(options: ExternalImportOptions) -> dict[str, object]:
    """Import one external JSONL artefact after source-review validation.

    Parameters
    ----------
    options:
        Import configuration, including the target surface and local source file.

    Returns
    -------
    dict[str, object]
        Receipt metadata written next to the imported JSONL artefact.

    Raises
    ------
    FileNotFoundError
        If the input JSONL path does not exist.
    ValueError
        If the surface is not in the manifest, lacks an allowed source review, or
        the JSONL rows do not satisfy the action benchmark schema.
    FileExistsError
        If the target artefact already exists and ``replace`` is false.
    """
    source = _find_manifest_source(options)
    review = _find_review(options, source)
    if not review.import_allowed:
        raise ValueError(f"{source.surface}: source review does not allow import")
    if not options.input_jsonl.is_file():
        raise FileNotFoundError(options.input_jsonl)
    rows = _load_jsonl(options.input_jsonl)
    validate_external_case_rows(rows, options.input_jsonl)

    target = source.artifact_path(options.manifest)
    if target.exists() and not options.replace:
        raise FileExistsError(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(options.input_jsonl, target)

    receipt = _receipt(options, source, review, target=target, rows=len(rows))
    receipt_path = _receipt_path(target)
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


def main(argv: Sequence[str] | None = None) -> int:
    """Run the import CLI and print the receipt JSON on success."""
    try:
        receipt = import_external_surface(ExternalImportOptions.from_argv(argv))
    except (FileExistsError, FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"external import failed: {exc}")
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


def _find_manifest_source(options: ExternalImportOptions) -> ExternalSource:
    for source in load_manifest(options.manifest):
        if source.surface == options.surface:
            return source
    raise ValueError(f"{options.surface}: surface is not present in manifest")


def _find_review(
    options: ExternalImportOptions,
    source: ExternalSource,
) -> ExternalSourceReview:
    review = load_source_reviews(options.source_ledger).get(source.surface)
    if review is None:
        raise ValueError(f"{source.surface}: missing source review")
    return review


def _load_jsonl(path: Path) -> list[CaseRow]:
    rows: list[CaseRow] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        loaded = json.loads(line)
        if not isinstance(loaded, dict):
            raise ValueError(f"{path}:{lineno} must contain a JSON object")
        rows.append(loaded)
    return rows


def _receipt(
    options: ExternalImportOptions,
    source: ExternalSource,
    review: ExternalSourceReview,
    *,
    target: Path,
    rows: int,
) -> dict[str, object]:
    return {
        "surface": source.surface,
        "threat_taxonomy": source.threat_taxonomy,
        "local_artifact": source.local_artifact,
        "target": str(target),
        "source_path": str(options.input_jsonl),
        "source_sha256": hashlib.sha256(options.input_jsonl.read_bytes()).hexdigest(),
        "row_count": rows,
        "imported_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "upstream_url": review.upstream_url,
        "licence": review.licence,
        "licence_url": review.licence_url,
        "licence_status": review.licence_status,
        "source_reviewed_at": review.reviewed_at,
        "provenance_review": review.provenance_review,
    }


def _receipt_path(target: Path) -> Path:
    return target.with_suffix(target.suffix + ".import.json")


if __name__ == "__main__":
    raise SystemExit(main())
