# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — content/integrity detector adapters and LLM judges

"""Adapters wrapping director-ai model detectors, and the LLM-judge tier.

The model adapters require the ``[detectors]`` extra (director-ai + its model
stack); the LLM judge is provider-agnostic (an injected callable). Adapter glue
imports nothing heavy, so this package imports cleanly without director-ai and is
unit-tested with injected scorers / judge functions.
"""

from .contradiction import ContradictionContentDetector
from .llm_judge import (
    JudgePanel,
    JudgeResult,
    JudgeSpec,
    LLMJudgeDetector,
    prompt_judge,
)
from .token_span import TokenSpanContentDetector

__all__ = [
    "ContradictionContentDetector",
    "JudgePanel",
    "JudgeResult",
    "JudgeSpec",
    "LLMJudgeDetector",
    "TokenSpanContentDetector",
    "prompt_judge",
]
