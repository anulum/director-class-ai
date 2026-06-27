# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — numeric claim evidence guard

"""Validate evidence backing for published numeric claims."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias, cast

JsonValue: TypeAlias = (
    None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
)

_DEFAULT_SPEC = Path("validation/numeric_claim_evidence.json")
_SCHEMA_VERSION = "director-class-ai.numeric-claim-evidence.v1"
_NUMERIC_PATTERN = re.compile(
    r"(?<![A-Za-z])(?:\d+\.\d+|\d+)(?:%|\s*ms)?|\bn\s*[=:]\s*\d+"
)
_METRIC_WORD_PATTERN = re.compile(
    r"\b("
    r"benchmark|coverage|recall|rate|conformance|latency|elapsed|"
    r"authored|external|customer/private|customer|host load|python|platform|n"
    r")\b",
    flags=re.IGNORECASE,
)


@dataclass(frozen=True)
class Finding:
    """One numeric-claim evidence failure."""

    path: Path
    line: int
    message: str

    def format(self, root: Path) -> str:
        """Return a stable repository-relative failure message."""
        try:
            relative = self.path.relative_to(root)
        except ValueError:
            relative = self.path
        return f"{relative}:{self.line}: {self.message}"


def validate_numeric_claim_evidence(
    repo_root: Path = Path("."),
    spec_path: Path = _DEFAULT_SPEC,
) -> list[Finding]:
    """Return numeric-claim evidence failures for the configured repository.

    Parameters
    ----------
    repo_root:
        Repository root used to resolve documentation and evidence paths.
    spec_path:
        JSON ledger that lists scan surfaces, allowed non-claim numeric lines,
        claim quotes, and evidence artifact assertions.

    Returns
    -------
    list[Finding]
        Human-readable failures. An empty list means every configured
        metric-like line is covered by an evidence-backed claim or an explicit
        non-claim exclusion.
    """
    root = repo_root.resolve()
    spec_file = _resolve(root, spec_path)
    try:
        loaded = json.loads(spec_file.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        return [Finding(spec_file, 1, f"cannot load numeric-claim spec: {exc}")]
    if not isinstance(loaded, dict):
        return [Finding(spec_file, 1, "top-level JSON value must be an object")]

    spec: Mapping[str, object] = loaded
    findings: list[Finding] = []
    findings.extend(_validate_schema(spec_file, spec))
    allow_patterns = _compile_allow_patterns(spec_file, spec, findings)
    claim_lines: dict[str, set[str]] = {}
    claim_ids: set[str] = set()

    claims = spec.get("claims")
    if not isinstance(claims, list) or not claims:
        findings.append(Finding(spec_file, 1, "claims must be a non-empty list"))
    else:
        for index, claim in enumerate(claims, start=1):
            findings.extend(
                _validate_claim(root, spec_file, index, claim, claim_ids, claim_lines)
            )

    for surface in _string_list(spec, "scan_surfaces"):
        surface_path = root / surface
        if not surface_path.is_file():
            findings.append(Finding(spec_file, 1, f"scan surface missing: {surface}"))
            continue
        findings.extend(
            _scan_surface(
                root,
                surface_path,
                claim_lines.get(surface, set()),
                allow_patterns,
            )
        )
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    """Run the numeric-claim evidence guard."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--spec", type=Path, default=_DEFAULT_SPEC)
    args = parser.parse_args(argv)
    root = args.repo_root.resolve()
    failures = validate_numeric_claim_evidence(root, args.spec)
    for failure in failures:
        print(f"numeric claim evidence failed: {failure.format(root)}")
    return 1 if failures else 0


def _validate_schema(spec_file: Path, spec: Mapping[str, object]) -> list[Finding]:
    findings: list[Finding] = []
    if spec.get("schema_version") != _SCHEMA_VERSION:
        findings.append(
            Finding(
                spec_file,
                1,
                f"schema_version must be {_SCHEMA_VERSION!r}",
            )
        )
    if not _string_list(spec, "scan_surfaces"):
        findings.append(Finding(spec_file, 1, "scan_surfaces must not be empty"))
    return findings


def _compile_allow_patterns(
    spec_file: Path,
    spec: Mapping[str, object],
    findings: list[Finding],
) -> tuple[re.Pattern[str], ...]:
    compiled: list[re.Pattern[str]] = []
    patterns = spec.get("allow_line_patterns", [])
    if not isinstance(patterns, list):
        findings.append(Finding(spec_file, 1, "allow_line_patterns must be a list"))
        return ()
    for index, item in enumerate(patterns, start=1):
        if not isinstance(item, dict):
            findings.append(
                Finding(spec_file, 1, f"allow_line_patterns[{index}] must be an object")
            )
            continue
        pattern = item.get("pattern")
        reason = item.get("reason")
        if not isinstance(pattern, str) or not pattern.strip():
            findings.append(
                Finding(spec_file, 1, f"allow_line_patterns[{index}] needs pattern")
            )
            continue
        if not isinstance(reason, str) or not reason.strip():
            findings.append(
                Finding(spec_file, 1, f"allow_line_patterns[{index}] needs reason")
            )
        try:
            compiled.append(re.compile(pattern))
        except re.error as exc:
            findings.append(
                Finding(
                    spec_file,
                    1,
                    f"allow_line_patterns[{index}] invalid regex: {exc}",
                )
            )
    return tuple(compiled)


def _validate_claim(
    root: Path,
    spec_file: Path,
    index: int,
    raw_claim: object,
    claim_ids: set[str],
    claim_lines: dict[str, set[str]],
) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(raw_claim, dict):
        return [Finding(spec_file, 1, f"claims[{index}] must be an object")]
    claim: Mapping[str, object] = raw_claim
    claim_id = _required_string(spec_file, claim, "id", f"claims[{index}]", findings)
    surface = _required_string(spec_file, claim, "surface", claim_id, findings)
    quote = _required_string(spec_file, claim, "quote", claim_id, findings)
    _required_string(spec_file, claim, "claim_boundary", claim_id, findings)

    if claim_id in claim_ids:
        findings.append(Finding(spec_file, 1, f"duplicate claim id: {claim_id}"))
    if claim_id:
        claim_ids.add(claim_id)

    if surface and quote:
        surface_path = root / surface
        if not surface_path.is_file():
            findings.append(
                Finding(spec_file, 1, f"{claim_id}: surface missing: {surface}")
            )
        else:
            text = surface_path.read_text(encoding="utf-8")
            if quote not in text:
                findings.append(
                    Finding(spec_file, 1, f"{claim_id}: quote is not in {surface}")
                )
            else:
                claim_lines.setdefault(surface, set()).update(_quote_lines(quote))

    evidence = claim.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        findings.append(Finding(spec_file, 1, f"{claim_id}: evidence must be a list"))
    else:
        for evidence_index, evidence_item in enumerate(evidence, start=1):
            findings.extend(
                _validate_evidence_item(
                    root,
                    spec_file,
                    claim_id,
                    evidence_index,
                    evidence_item,
                )
            )
    return findings


def _validate_evidence_item(
    root: Path,
    spec_file: Path,
    claim_id: str,
    index: int,
    raw_item: object,
) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(raw_item, dict):
        return [Finding(spec_file, 1, f"{claim_id}: evidence[{index}] must be object")]
    item: Mapping[str, object] = raw_item
    path_value = _required_string(
        spec_file,
        item,
        "path",
        f"{claim_id}: evidence[{index}]",
        findings,
    )
    if not path_value:
        return findings
    evidence_path = root / path_value
    if not evidence_path.is_file():
        findings.append(
            Finding(spec_file, 1, f"{claim_id}: evidence path missing: {path_value}")
        )
        return findings
    assertions = item.get("json_pointers", [])
    if assertions is None:
        assertions = []
    if not isinstance(assertions, list):
        findings.append(
            Finding(spec_file, 1, f"{claim_id}: json_pointers must be a list")
        )
        return findings
    if assertions:
        findings.extend(
            _validate_json_assertions(
                spec_file,
                claim_id,
                evidence_path,
                assertions,
            )
        )
    return findings


def _validate_json_assertions(
    spec_file: Path,
    claim_id: str,
    evidence_path: Path,
    assertions: Sequence[object],
) -> list[Finding]:
    findings: list[Finding] = []
    try:
        document: JsonValue = json.loads(evidence_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [Finding(spec_file, 1, f"{claim_id}: invalid JSON evidence: {exc}")]
    for assertion_index, assertion in enumerate(assertions, start=1):
        if not isinstance(assertion, dict):
            findings.append(
                Finding(
                    spec_file,
                    1,
                    f"{claim_id}: json_pointers[{assertion_index}] must be object",
                )
            )
            continue
        pointer = assertion.get("pointer")
        if not isinstance(pointer, str):
            findings.append(
                Finding(
                    spec_file,
                    1,
                    f"{claim_id}: json_pointers[{assertion_index}] needs pointer",
                )
            )
            continue
        if "equals" not in assertion:
            findings.append(
                Finding(
                    spec_file,
                    1,
                    f"{claim_id}: json_pointers[{assertion_index}] needs equals",
                )
            )
            continue
        expected = _as_json_value(assertion["equals"])
        actual = _json_pointer(document, pointer)
        if actual != expected:
            findings.append(
                Finding(
                    spec_file,
                    1,
                    f"{claim_id}: {evidence_path.name}{pointer} expected "
                    f"{expected!r}, got {actual!r}",
                )
            )
    return findings


def _scan_surface(
    root: Path,
    surface_path: Path,
    covered_lines: set[str],
    allow_patterns: Iterable[re.Pattern[str]],
) -> list[Finding]:
    findings: list[Finding] = []
    in_code_block = False
    for line_number, raw_line in enumerate(
        surface_path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        stripped = raw_line.strip()
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            continue
        if in_code_block or not stripped:
            continue
        if stripped in covered_lines:
            continue
        if any(pattern.search(stripped) for pattern in allow_patterns):
            continue
        if _is_metric_line(stripped):
            findings.append(
                Finding(
                    surface_path,
                    line_number,
                    "metric-like numeric line is not covered by "
                    "validation/numeric_claim_evidence.json",
                )
            )
    return findings


def _is_metric_line(line: str) -> bool:
    return bool(_NUMERIC_PATTERN.search(line) and _METRIC_WORD_PATTERN.search(line))


def _quote_lines(quote: str) -> set[str]:
    return {line.strip() for line in quote.splitlines() if line.strip()}


def _json_pointer(document: JsonValue, pointer: str) -> JsonValue:
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        return None
    value = document
    for raw_part in pointer.split("/")[1:]:
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            value = value.get(part)
        elif isinstance(value, list) and part.isdigit():
            index = int(part)
            value = value[index] if index < len(value) else None
        else:
            return None
    return value


def _as_json_value(value: object) -> JsonValue:
    return cast(JsonValue, value) if _is_json_value(value) else None


def _is_json_value(value: object) -> bool:
    if value is None or isinstance(value, bool | int | float | str):
        return True
    if isinstance(value, list):
        return all(_is_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _is_json_value(item) for key, item in value.items()
        )
    return False


def _required_string(
    spec_file: Path,
    values: Mapping[str, object],
    key: str,
    context: str,
    findings: list[Finding],
) -> str:
    value = values.get(key)
    if isinstance(value, str) and value.strip():
        return value
    findings.append(Finding(spec_file, 1, f"{context}: {key} must be a string"))
    return ""


def _string_list(spec: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = spec.get(key, [])
    if not isinstance(value, list):
        return ()
    items: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            items.append(item.strip())
    return tuple(items)


def _resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


if __name__ == "__main__":
    raise SystemExit(main())
