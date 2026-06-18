# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — repository readiness guard

"""Validate local repository readiness evidence.

The remaining remote work for this repository is settings-bound: push, remote CI
observation, and branch-protection configuration. This guard validates the local
parts that can be proven before that remote step: package identity, licence
wiring, workflow surfaces, required local gates, and explicit remote blockers.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path

_DEFAULT_SPEC = Path("docs/internal/repository_readiness.json")
_SCHEMA_VERSION = "director-class-ai.repository-readiness.v1"
_EXPECTED_PACKAGE = "director-class-ai"
_EXPECTED_REMOTE = "https://github.com/anulum/director-class-ai.git"
_REQUIRED_WORKFLOWS = (
    ".github/workflows/ci.yml",
    ".github/workflows/pre-commit.yml",
    ".github/workflows/codeql.yml",
    ".github/workflows/scorecard.yml",
)
_REQUIRED_LOCAL_GATES = (
    "spdx",
    "repository-readiness",
    "phase4-intake",
    "lint",
    "types",
    "test",
)
_REQUIRED_SCRIPTS = (
    "director-class-guard",
    "director-class-mcp-gateway",
    "director-class-siem-export",
)
_REMOTE_BLOCKER_STATUSES = frozenset(
    {"blocked_until_push", "blocked_until_repo_settings"}
)


def validate_repository_readiness(
    repo_root: Path = Path("."),
    spec_path: Path = _DEFAULT_SPEC,
) -> list[str]:
    """Return local repository-readiness validation failures.

    Parameters
    ----------
    repo_root:
        Repository root used to resolve project files.
    spec_path:
        Internal JSON readiness specification.

    Returns
    -------
    list[str]
        Human-readable failures. An empty list means the locally verifiable
        repository readiness evidence is coherent.
    """
    root = repo_root.resolve()
    spec_file = _resolve(root, spec_path)
    try:
        spec = json.loads(spec_file.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        return [f"{spec_file}: cannot load readiness spec: {exc}"]
    if not isinstance(spec, dict):
        return [f"{spec_file}: top-level JSON value must be an object"]

    failures: list[str] = []
    failures.extend(_validate_spec(spec))
    failures.extend(_validate_pyproject(root, spec))
    failures.extend(_validate_licence(root))
    failures.extend(_validate_workflows(root, spec))
    failures.extend(_validate_makefile(root, spec))
    return failures


def main(argv: Sequence[str] | None = None) -> int:
    """Run the repository readiness guard."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--spec", type=Path, default=_DEFAULT_SPEC)
    args = parser.parse_args(argv)
    failures = validate_repository_readiness(args.repo_root, args.spec)
    for failure in failures:
        print(f"repository readiness failed: {failure}", file=sys.stderr)
    return 1 if failures else 0


def _validate_spec(spec: Mapping[str, object]) -> list[str]:
    failures: list[str] = []
    if spec.get("schema_version") != _SCHEMA_VERSION:
        failures.append(f"schema_version must be {_SCHEMA_VERSION!r}")
    if spec.get("package_name") != _EXPECTED_PACKAGE:
        failures.append(f"package_name must be {_EXPECTED_PACKAGE!r}")
    if spec.get("remote_url") != _EXPECTED_REMOTE:
        failures.append(f"remote_url must be {_EXPECTED_REMOTE!r}")
    if spec.get("branch") != "main":
        failures.append("branch must be 'main'")
    if spec.get("remote_ci_status") != "blocked_until_push":
        failures.append("remote_ci_status must be 'blocked_until_push'")
    if spec.get("branch_protection_status") != "blocked_until_repo_settings":
        failures.append("branch_protection_status must be 'blocked_until_repo_settings'")
    blockers = _string_list(spec, "open_remote_blockers")
    if not blockers:
        failures.append("open_remote_blockers must list the remote blockers")
    return failures


def _validate_pyproject(root: Path, spec: Mapping[str, object]) -> list[str]:
    pyproject_path = root / "pyproject.toml"
    with pyproject_path.open("rb") as handle:
        pyproject = tomllib.load(handle)
    project = pyproject.get("project", {})
    if not isinstance(project, dict):
        return ["pyproject.toml [project] table is missing"]

    failures: list[str] = []
    if project.get("name") != _EXPECTED_PACKAGE:
        failures.append("pyproject project.name must be director-class-ai")
    if project.get("license-files") != ["LICENSE"]:
        failures.append("pyproject project.license-files must declare LICENSE")
    classifiers = project.get("classifiers", [])
    if not isinstance(classifiers, list) or "Private :: Do Not Upload" not in classifiers:
        failures.append("pyproject classifiers must include Private :: Do Not Upload")
    scripts = project.get("scripts", {})
    if not isinstance(scripts, dict):
        failures.append("pyproject project.scripts table is missing")
    else:
        for script in _REQUIRED_SCRIPTS:
            if script not in scripts:
                failures.append(f"pyproject missing console script {script!r}")
    declared_scripts = tuple(_string_list(spec, "console_scripts"))
    for script in _REQUIRED_SCRIPTS:
        if script not in declared_scripts:
            failures.append(f"readiness spec missing console script {script!r}")
    return failures


def _validate_licence(root: Path) -> list[str]:
    licence = (root / "LICENSE").read_text(encoding="utf-8")
    failures: list[str] = []
    required_fragments = (
        "Proprietary Commercial License",
        "NO LICENSE BY ACCESS",
        "commercial agreement",
    )
    for fragment in required_fragments:
        if fragment not in licence:
            failures.append(f"LICENSE missing required fragment {fragment!r}")
    return failures


def _validate_workflows(root: Path, spec: Mapping[str, object]) -> list[str]:
    failures: list[str] = []
    declared = tuple(_string_list(spec, "workflow_files"))
    for workflow in _REQUIRED_WORKFLOWS:
        if workflow not in declared:
            failures.append(f"readiness spec missing workflow {workflow!r}")
        if not (root / workflow).is_file():
            failures.append(f"workflow file is missing: {workflow}")

    ci_text = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    required_ci_jobs = tuple(_string_list(spec, "required_ci_jobs"))
    for job_name in required_ci_jobs:
        pattern = rf"^\s*name:\s*{re.escape(job_name)}\s*$"
        if re.search(pattern, ci_text, flags=re.MULTILINE) is None:
            failures.append(f"CI workflow missing job name {job_name!r}")
    if not required_ci_jobs:
        failures.append("required_ci_jobs must not be empty")
    return failures


def _validate_makefile(root: Path, spec: Mapping[str, object]) -> list[str]:
    makefile = (root / "Makefile").read_text(encoding="utf-8")
    declared = tuple(_string_list(spec, "required_local_gates"))
    failures: list[str] = []
    for gate in _REQUIRED_LOCAL_GATES:
        if gate not in declared:
            failures.append(f"readiness spec missing local gate {gate!r}")
        if re.search(rf"^{re.escape(gate)}:", makefile, flags=re.MULTILINE) is None:
            failures.append(f"Makefile missing target {gate!r}")
    preflight_line = _target_header(makefile, "preflight")
    for gate in _REQUIRED_LOCAL_GATES:
        if gate != "test" and gate not in preflight_line:
            failures.append(f"preflight target must depend on {gate!r}")
    return failures


def _string_list(spec: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = spec.get(key, [])
    if not isinstance(value, list):
        return ()
    items: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            items.append(item.strip())
    return tuple(items)


def _target_header(makefile: str, target: str) -> str:
    match = re.search(rf"^{re.escape(target)}:[^\n]*", makefile, flags=re.MULTILINE)
    return match.group(0) if match else ""


def _resolve(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


if __name__ == "__main__":
    raise SystemExit(main())
