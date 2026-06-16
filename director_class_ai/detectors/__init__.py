# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — content/integrity detector adapters

"""Adapters wrapping director-ai model detectors as ensemble Detectors.

These require the ``[detectors]`` extra (director-ai + its model stack). The
adapter glue itself imports nothing heavy — the director-ai model is loaded only
in ``from_pretrained`` — so this package imports cleanly without director-ai, and
the glue is unit-tested with an injected scorer.
"""

from .contradiction import ContradictionContentDetector
from .token_span import TokenSpanContentDetector

__all__ = ["ContradictionContentDetector", "TokenSpanContentDetector"]
