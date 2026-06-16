# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — packaging metadata consistency tests

from __future__ import annotations

import tomllib
from pathlib import Path

import director_class_ai

_PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _project() -> dict:
    with _PYPROJECT.open("rb") as fh:
        return tomllib.load(fh)["project"]


def test_version_matches_pyproject() -> None:
    assert director_class_ai.__version__ == _project()["version"]


def test_license_file_is_declared() -> None:
    assert _project()["license-files"] == ["LICENSE"]


def test_not_uploadable_to_pypi() -> None:
    # the proprietary product must never be publishable to public PyPI
    assert "Private :: Do Not Upload" in _project()["classifiers"]


def test_no_deprecated_license_classifier() -> None:
    # licence is the bundled LICENSE file, not a deprecated License:: classifier
    assert not any(c.startswith("License ::") for c in _project()["classifiers"])
