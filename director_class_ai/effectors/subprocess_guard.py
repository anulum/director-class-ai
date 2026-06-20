# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — guarded subprocess wrapper

"""Run a shell command only after the Governor permits it.

This is the safe replacement for a raw ``subprocess.run`` in an autonomous agent:
the command is reviewed first, and the real shell is invoked only for a permitted,
non-dry-run request. The actual executor is injected (``runner``); with none wired
the guard is dry-run only and never spawns a process. :func:`default_subprocess_runner`
is provided for explicit opt-in to real execution — it is never the default.
"""

from __future__ import annotations

from ..core.governor import Governor
from .shell import ShellEffectorAdapter
from .types import EffectorResult, ExecuteFn

__all__ = ["SubprocessGuard", "default_subprocess_runner"]


def default_subprocess_runner(command: str) -> tuple[str, int]:
    """Execute *command* in a shell and return (combined output, exit code).

    Opt-in only: pass this to :class:`SubprocessGuard` to enable real execution.
    The guard reaches it solely after a permitting Governor decision.
    """
    import subprocess

    proc = subprocess.run(  # nosec B602  # nosemgrep — gated post-permit runner
        command,
        shell=True,  # nosemgrep — gated post-permit runner
        capture_output=True,
        text=True,
        check=False,
    )
    return (proc.stdout + proc.stderr, proc.returncode)


class SubprocessGuard:
    """Governor-gated front end for shell execution; dry-run unless a runner is set."""

    def __init__(self, governor: Governor, *, runner: ExecuteFn | None = None) -> None:
        self._adapter = ShellEffectorAdapter(governor, execute=runner)

    def run(
        self,
        command: str,
        *,
        provenance: str = "",
        query: str = "",
        dry_run: bool = True,
    ) -> EffectorResult:
        """Review one shell command and execute only when explicitly permitted."""
        return self._adapter.run_command(
            command, provenance=provenance, query=query, dry_run=dry_run
        )
