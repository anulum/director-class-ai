# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — action-corpus generator

"""Build the labelled action-plane corpus from original, category-aligned cases.

Every case here is authored for this project. Where a category mirrors a public
agent-security suite (AgentDojo, MCPSafeBench, SkillInject), it is aligned to that
suite's *threat taxonomy* — the class of attack — and not copied from its data:
the concrete commands, tool calls, paths and prose are original. The ``source``
field records that alignment for provenance, never that any case was lifted.
"""

from .catalogue import build_catalogue
from .generate import assemble, write_corpus

__all__ = ["build_catalogue", "assemble", "write_corpus"]
