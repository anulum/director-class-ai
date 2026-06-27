# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — evidence technique-tag tests

from __future__ import annotations

from director_class_ai.evidence import (
    technique_ids_for_findings,
    technique_tags_for_findings,
)


def test_known_findings_map_to_bounded_standards_tags() -> None:
    tags = technique_tags_for_findings(("destructive_command", "mcp_remote_auth"))
    payload = [tag.to_json() for tag in tags]

    assert {
        (tag["framework"], tag["technique_id"], tag["finding"]) for tag in payload
    } >= {
        ("OWASP ASI", "ASI05", "destructive_command"),
        ("MITRE ATLAS", "AML.T0050", "destructive_command"),
        ("OWASP ASI", "ASI03", "mcp_remote_auth"),
        ("OWASP ASI", "ASI04", "mcp_remote_auth"),
        ("MITRE ATLAS", "AML.T0061", "mcp_remote_auth"),
    }
    assert all("does not" in tag["claim_boundary"] for tag in payload)


def test_prefix_findings_map_without_raw_action_material() -> None:
    tags = technique_tags_for_findings(
        (
            "mcp_untrusted_server",
            "capability_resource_mismatch",
            "browser_metadata_injection",
        )
    )
    payload = [tag.to_json() for tag in tags]

    assert ("ASI04", "mcp_untrusted_server") in {
        (tag["technique_id"], tag["finding"]) for tag in payload
    }
    assert ("AML.T0061", "capability_resource_mismatch") in {
        (tag["technique_id"], tag["finding"]) for tag in payload
    }
    assert ("AML.T0053", "browser_metadata_injection") in {
        (tag["technique_id"], tag["finding"]) for tag in payload
    }
    assert "rm -rf /" not in repr(payload)


def test_technique_ids_are_stable_and_deduplicated() -> None:
    assert technique_ids_for_findings(
        ("destructive_command", "destructive_command", "disk_overwrite")
    ) == ("ASI05", "AML.T0050")


def test_unknown_findings_do_not_fabricate_tags() -> None:
    assert technique_tags_for_findings(("unknown_detector",)) == ()
    assert technique_ids_for_findings(("unknown_detector",)) == ()
