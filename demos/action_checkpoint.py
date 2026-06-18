# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — action checkpoint demo

"""Run a minimal action-checkpoint demo with redacted output.

The demo uses the public Python API that an operator would place in front of a
tool executor. It exercises a safe dry-run command and a destructive command,
then prints only route metadata and detector firing names.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from director_class_ai.cli.guard import CommandGuardOptions, run_guard


def main() -> int:
    """Run safe and blocked command reviews and print redacted JSON events."""
    events = [
        run_guard(CommandGuardOptions(surface="shell", command=("printf", "ok"))),
        run_guard(CommandGuardOptions(surface="shell", command=("rm", "-rf", "/"))),
    ]
    print(json.dumps(events, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
