# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — audit-chain hot-path benchmark

"""Measure the audit append hot path on local functional evidence only."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, ".")

from director_class_ai.audit import AuditChainSink, verify_chain  # noqa: E402
from director_class_ai.core import AuditRecord  # noqa: E402

_RESULT_JSON = Path("benchmarks/results/audit_chain_hot_path.json")
_EVIDENCE_GRADE = "local-functional-non-isolated"
_CLAIM_BOUNDARY = (
    "Audit append hot-path evidence for this checkout and host only; not an "
    "isolated throughput, external benchmark, comparative performance, "
    "certification, or counsel-reviewed evidence-status claim."
)


def _record(index: int) -> AuditRecord:
    digest = hashlib.sha256(f"audit-hot-path:{index}".encode()).hexdigest()
    return AuditRecord(
        permitted=index % 3 != 0,
        escalated=index % 5 == 0,
        risk=0.1 + (index % 10) / 100,
        requires_human=index % 5 == 0,
        rationale="audit hot-path functional benchmark",
        firing=("benchmark",) if index % 3 == 0 else (),
        request_digest=digest,
    )


def run_audit_chain_hot_path(path: Path, *, appends: int) -> dict[str, object]:
    """Measure append throughput for one temporary audit-chain log.

    Parameters
    ----------
    path
        Audit JSONL path used for the benchmark run.
    appends
        Number of synthetic audit records to append.

    Returns
    -------
    dict
        Local functional benchmark evidence including rate, log size, and chain
        verification status.

    Raises
    ------
    ValueError
        If ``appends`` is not positive.
    """
    if appends <= 0:
        raise ValueError("appends must be positive")
    path.parent.mkdir(parents=True, exist_ok=True)
    sink = AuditChainSink(path=path, policy_profile="benchmark")
    started = time.perf_counter()
    for index in range(appends):
        sink(_record(index))
    elapsed = time.perf_counter() - started
    verification = verify_chain(path)
    rate = appends / elapsed if elapsed > 0 else float("inf")
    return {
        "benchmark": "audit_chain_hot_path",
        "evidence_grade": _EVIDENCE_GRADE,
        "claim_boundary": _CLAIM_BOUNDARY,
        "appends": appends,
        "elapsed_seconds": elapsed,
        "appends_per_second": rate,
        "log_bytes": path.stat().st_size,
        "verification_ok": verification.ok,
        "verification_reason": verification.reason,
        "hot_path": "AuditChainSink append with in-process locked head cache",
    }


def main(argv: list[str] | None = None) -> int:
    """Run the audit-chain hot-path benchmark CLI.

    Parameters
    ----------
    argv
        Optional argument vector for tests or programmatic invocation.

    Returns
    -------
    int
        ``0`` when the generated audit chain verifies, otherwise ``1``.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--appends", type=int, default=500)
    parser.add_argument("--output", type=Path, default=_RESULT_JSON)
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="dca-audit-chain-bench-") as tmp:
        result = run_audit_chain_hot_path(Path(tmp) / "audit.jsonl", appends=args.appends)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["verification_ok"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
