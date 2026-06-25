# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — governed workflow exports

"""Reusable governed workflows built from the core action-control boundary."""

from .authorised_execution import (
    AuthorisedShellWorkflowReport,
    run_authorised_shell_workflow,
)

__all__ = [
    "AuthorisedShellWorkflowReport",
    "run_authorised_shell_workflow",
]
