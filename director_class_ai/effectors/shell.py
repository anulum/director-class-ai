# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — shell effector adapter

"""A shell effector that runs every command through the Governor first."""

from __future__ import annotations

from ..core.governor import Governor
from .types import (
    EffectorKind,
    EffectorRequest,
    EffectorResult,
    ExecuteFn,
    GovernedEffector,
)

__all__ = ["ShellEffectorAdapter"]


class ShellEffectorAdapter(GovernedEffector):
    """Governed shell effector. ``execute`` is injected; absent ⇒ dry-run only."""

    kind = EffectorKind.SHELL

    def __init__(self, governor: Governor, execute: ExecuteFn | None = None) -> None:
        super().__init__(governor, execute)

    def run_command(
        self,
        command: str,
        *,
        provenance: str = "",
        query: str = "",
        context: str = "",
        dry_run: bool = True,
    ) -> EffectorResult:
        return self.run(
            EffectorRequest(
                action=command,
                kind=EffectorKind.SHELL,
                provenance=provenance,
                query=query,
                context=context,
                dry_run=dry_run,
            )
        )
