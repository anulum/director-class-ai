# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — external action-surface benchmark adapter

"""Load optional external action-risk examples without fabricating artefacts."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

__all__ = [
    "CaseRow",
    "ExternalSource",
    "ExternalSourceReview",
    "load_external_cases",
    "load_manifest",
    "load_source_reviews",
    "source_inventory",
    "validate_external_case_rows",
]

_HERE = Path(__file__).resolve().parent
_DEFAULT_MANIFEST = _HERE / "external_sources" / "MANIFEST.md"
_DEFAULT_SOURCE_LEDGER = _HERE / "external_sources" / "SOURCE_LEDGER.json"
_REQUIRED = frozenset({"id", "action", "label", "category", "severity"})
_LABELS = frozenset({"catastrophic", "safe"})
_REVIEW_REQUIRED = frozenset(
    {
        "surface",
        "upstream_url",
        "licence",
        "licence_url",
        "licence_status",
        "provenance_review",
        "import_allowed",
    }
)
LicenceStatus = Literal["allow", "blocked", "requires_review"]
CaseRow = dict[str, object]


@dataclass(frozen=True)
class ExternalSource:
    """One manifest row describing an optional local external corpus artefact."""

    surface: str
    threat_taxonomy: str
    licence: str
    provenance: str
    local_artifact: str
    status: str

    def artifact_path(self, manifest_path: Path) -> Path:
        return (manifest_path.parent / self.local_artifact).resolve()


@dataclass(frozen=True)
class ExternalSourceReview:
    """Licence and provenance review for one external benchmark surface.

    Parameters
    ----------
    surface:
        Manifest surface name that this review authorises or blocks.
    upstream_url:
        Canonical upstream repository, paper, or project page used for review.
    licence:
        Human-readable licence finding recorded at review time.
    licence_url:
        URL for the licence evidence, when one was found.
    licence_status:
        Import decision state. Only ``"allow"`` permits local JSONL loading.
    provenance_review:
        Operator-readable explanation of the current provenance boundary.
    import_allowed:
        Explicit fail-closed gate for local artefact loading.
    reviewed_at:
        UTC date or timestamp for the review evidence.
    citation:
        Optional paper or benchmark citation URL.
    notes:
        Optional bounded notes that do not override ``import_allowed``.
    """

    surface: str
    upstream_url: str
    licence: str
    licence_url: str
    licence_status: LicenceStatus
    provenance_review: str
    import_allowed: bool
    reviewed_at: str = ""
    citation: str = ""
    notes: str = ""

    @classmethod
    def from_mapping(
        cls, value: object, *, path: Path, index: int
    ) -> ExternalSourceReview:
        """Build a review from a JSON object and validate its required fields."""
        if not isinstance(value, dict):
            raise ValueError(f"{path}: review {index} must be a JSON object")
        missing = _REVIEW_REQUIRED.difference(value)
        if missing:
            raise ValueError(f"{path}: review {index} missing fields {sorted(missing)}")
        status = str(value["licence_status"])
        if status not in {"allow", "blocked", "requires_review"}:
            raise ValueError(f"{path}: review {index} has bad licence_status {status!r}")
        return cls(
            surface=str(value["surface"]),
            upstream_url=str(value["upstream_url"]),
            licence=str(value["licence"]),
            licence_url=str(value["licence_url"]),
            licence_status=cast(LicenceStatus, status),
            provenance_review=str(value["provenance_review"]),
            import_allowed=bool(value["import_allowed"]),
            reviewed_at=str(value.get("reviewed_at", "")),
            citation=str(value.get("citation", "")),
            notes=str(value.get("notes", "")),
        )

    def to_inventory(self) -> dict[str, object]:
        """Return the review fields safe to expose in benchmark evidence."""
        return {
            "upstream_url": self.upstream_url,
            "licence": self.licence,
            "licence_url": self.licence_url,
            "licence_status": self.licence_status,
            "provenance_review": self.provenance_review,
            "import_allowed": self.import_allowed,
            "reviewed_at": self.reviewed_at,
            "citation": self.citation,
            "notes": self.notes,
        }


def load_manifest(path: Path = _DEFAULT_MANIFEST) -> list[ExternalSource]:
    """Parse the external-source Markdown manifest table."""
    if not path.exists():
        return []
    rows: list[ExternalSource] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("|") or "---" in line:
            continue
        cells = [_clean_cell(cell) for cell in line.strip().strip("|").split("|")]
        if len(cells) != 6 or cells[0].lower() == "surface":
            continue
        rows.append(ExternalSource(*cells))
    return rows


def load_source_reviews(
    path: Path = _DEFAULT_SOURCE_LEDGER,
) -> dict[str, ExternalSourceReview]:
    """Load structured licence/provenance reviews for external surfaces."""
    if not path.exists():
        return {}
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, list):
        raise ValueError(f"{path}: source ledger must be a JSON array")
    reviews: dict[str, ExternalSourceReview] = {}
    for index, item in enumerate(loaded, start=1):
        review = ExternalSourceReview.from_mapping(item, path=path, index=index)
        if review.surface in reviews:
            raise ValueError(f"{path}: duplicate source review {review.surface!r}")
        reviews[review.surface] = review
    return reviews


def source_inventory(
    path: Path = _DEFAULT_MANIFEST,
    *,
    review_path: Path | None = None,
) -> list[dict[str, object]]:
    """Return load status for every manifest row, without reading missing files."""
    inventory: list[dict[str, object]] = []
    reviews = load_source_reviews(_review_path(path, review_path))
    for source in load_manifest(path):
        artifact_path = source.artifact_path(path)
        review = reviews.get(source.surface)
        inventory.append(
            {
                "surface": source.surface,
                "threat_taxonomy": source.threat_taxonomy,
                "provenance": source.provenance,
                "local_artifact": source.local_artifact,
                "status": source.status,
                "loaded": artifact_path.is_file(),
                "reviewed": review is not None,
                "import_allowed": review.import_allowed if review is not None else False,
                "licence_status": (
                    review.licence_status if review is not None else "requires_review"
                ),
                **(
                    review.to_inventory()
                    if review is not None
                    else {
                        "upstream_url": "",
                        "licence": source.licence,
                        "licence_url": "",
                        "provenance_review": "no structured source review",
                        "reviewed_at": "",
                        "citation": "",
                        "notes": "",
                    }
                ),
            }
        )
    return inventory


def load_external_cases(
    path: Path = _DEFAULT_MANIFEST,
    *,
    review_path: Path | None = None,
) -> list[CaseRow]:
    """Load only external JSONL artefacts that are already present locally."""
    cases: list[CaseRow] = []
    reviews = load_source_reviews(_review_path(path, review_path))
    for source in load_manifest(path):
        artifact_path = source.artifact_path(path)
        if not artifact_path.is_file():
            continue
        review = reviews.get(source.surface)
        if review is None:
            raise ValueError(
                f"{artifact_path}: missing source review for {source.surface}"
            )
        if not review.import_allowed:
            raise ValueError(
                f"{artifact_path}: source review does not allow import for "
                f"{source.surface}"
            )
        loaded = _load_jsonl(artifact_path)
        validate_external_case_rows(loaded, artifact_path)
        cases.extend(_with_external_metadata(source, review, loaded))
    return cases


def validate_external_case_rows(cases: Iterable[CaseRow], path: Path) -> None:
    """Validate external rows before they enter benchmark partitions.

    Parameters
    ----------
    cases:
        Parsed JSON object rows from a local external artefact.
    path:
        Path used in validation errors.

    Raises
    ------
    ValueError
        If required fields are missing, labels are outside the benchmark
        contract, or case identifiers are duplicated.
    """
    ids: set[str] = set()
    for case in cases:
        missing = _REQUIRED.difference(case)
        if missing:
            raise ValueError(f"{path}: case {case.get('id', '<unknown>')} missing fields")
        if case["label"] not in _LABELS:
            raise ValueError(f"{path}: case {case['id']} has bad label {case['label']!r}")
        if case["id"] in ids:
            raise ValueError(f"{path}: duplicate external id {case['id']}")
        ids.add(str(case["id"]))


def _review_path(manifest_path: Path, review_path: Path | None) -> Path:
    if review_path is not None:
        return review_path
    if manifest_path == _DEFAULT_MANIFEST:
        return _DEFAULT_SOURCE_LEDGER
    return manifest_path.parent / "SOURCE_LEDGER.json"


def _clean_cell(value: str) -> str:
    return value.strip().strip("`").strip()


def _load_jsonl(path: Path) -> list[CaseRow]:
    rows: list[CaseRow] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{lineno} must contain a JSON object")
        rows.append(value)
    return rows


def _with_external_metadata(
    source: ExternalSource,
    review: ExternalSourceReview,
    cases: Iterable[CaseRow],
) -> list[CaseRow]:
    enriched: list[CaseRow] = []
    for case in cases:
        row = dict(case)
        row["id"] = f"{source.surface}:{case['id']}"
        row["external_surface"] = source.surface
        row["external_threat_taxonomy"] = source.threat_taxonomy
        row["external_licence"] = review.licence
        row["external_licence_url"] = review.licence_url
        row["external_upstream_url"] = review.upstream_url
        row["source"] = f"external:{source.surface}"
        enriched.append(row)
    return enriched
