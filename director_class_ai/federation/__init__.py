# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — studio federation surface (schema-A capability manifest)

"""Federation surface for the SCPN-STUDIO dedicated-portal contract.

Exposes the schema-A capability manifest for the GOVERN layer of the Director
family trust stack — the verbs the Institute hub and the family portal consume to
discover Director-Class AI's action-governance capabilities, evidence types, and
federated UI panel. See :mod:`director_class_ai.federation.manifest`.
"""

from .manifest import (
    StudioManifest,
    UiModule,
    Verb,
    build_manifest,
)

__all__ = [
    "StudioManifest",
    "UiModule",
    "Verb",
    "build_manifest",
]
