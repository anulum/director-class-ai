# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — action benchmark evidence runner

"""Run action benchmarks with explicit evidence-grade metadata.

The action-plane benchmark already keeps authored and external corpora separate.
This module adds the missing evidence layer required before any benchmark number
can be interpreted: command line, git SHA, host-load context, CPU affinity,
runtime versions, dependency hashes, external-source inventory, and a generated
Markdown report. It deliberately labels loaded-host runs as local regression
evidence and refuses to promote isolated internal-only runs to comparative
claims when no external artefacts are loaded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from benchmarks.action_plane import _CORPUS, _EXTERNAL_MANIFEST, _load, evaluate
from benchmarks.external_action_surfaces import load_external_cases, source_inventory

__all__ = [
    "BenchmarkEvidence",
    "RunContext",
    "classify_evidence",
    "collect_run_context",
    "main",
    "render_markdown_report",
    "run_action_evidence",
]

_RESULT_JSON = Path("benchmarks/results/action_plane_evidence.json")
_RESULT_MD = Path("benchmarks/results/action_plane_evidence.md")
_NO_AFFINITY = "none"


@dataclass(frozen=True)
class RunContext:
    """Execution metadata required to interpret a benchmark run.

    Parameters
    ----------
    command:
        Exact command line used for the run.
    git_sha:
        Current repository commit SHA, or ``"unknown"`` when Git is unavailable.
    affinity:
        CPU affinity requested or observed for the benchmark process.
    isolation_method:
        Isolation mechanism used for the run, such as ``sched_setaffinity`` or
        ``none``.
    host_load_before:
        Host load averages collected immediately before benchmark evaluation.
    host_load_after:
        Host load averages collected immediately after benchmark evaluation.
    cpu_governor:
        Distinct CPU frequency governors visible through sysfs.
    python_version:
        Python runtime version.
    platform:
        Operating-system and architecture summary.
    dependency_hashes:
        SHA-256 digests for committed dependency lock files.
    heavy_jobs_disclosure:
        Operator disclosure about other heavy jobs on the host.
    """

    command: str
    git_sha: str
    affinity: str
    isolation_method: str
    host_load_before: tuple[float, float, float] | None
    host_load_after: tuple[float, float, float] | None
    cpu_governor: tuple[str, ...]
    python_version: str
    platform: str
    dependency_hashes: Mapping[str, str]
    heavy_jobs_disclosure: str

    @property
    def isolated(self) -> bool:
        """Return whether this context records an explicit isolation method."""
        return self.isolation_method != _NO_AFFINITY and self.affinity != _NO_AFFINITY

    def to_json(self) -> dict[str, object]:
        """Return a JSON-serialisable context representation."""
        return {
            "command": self.command,
            "git_sha": self.git_sha,
            "affinity": self.affinity,
            "isolation_method": self.isolation_method,
            "host_load_before": self.host_load_before,
            "host_load_after": self.host_load_after,
            "cpu_governor": list(self.cpu_governor),
            "python_version": self.python_version,
            "platform": self.platform,
            "dependency_hashes": dict(self.dependency_hashes),
            "heavy_jobs_disclosure": self.heavy_jobs_disclosure,
            "isolated": self.isolated,
        }


@dataclass(frozen=True)
class BenchmarkEvidence:
    """Action benchmark metrics paired with run-context metadata."""

    benchmark: str
    evidence_grade: str
    metrics: Mapping[str, object]
    run_context: RunContext
    external_sources: Sequence[Mapping[str, object]]

    def to_json(self) -> dict[str, object]:
        """Return a JSON-serialisable evidence package."""
        return {
            "benchmark": self.benchmark,
            "evidence_grade": self.evidence_grade,
            "metrics": dict(self.metrics),
            "run_context": self.run_context.to_json(),
            "external_sources": [dict(source) for source in self.external_sources],
        }


def classify_evidence(*, isolated: bool, external_count: int) -> str:
    """Classify a benchmark run without over-promoting its claim boundary."""
    if not isolated:
        return (
            "local-regression-non-isolated: functional benchmark evidence only; "
            "not a public performance or comparative claim"
        )
    if external_count == 0:
        return (
            "isolated-internal-only: isolation metadata present, but no external "
            "artefacts loaded; not a comparative benchmark claim"
        )
    return (
        "isolated-with-external-artefacts: claim-candidate evidence requiring "
        "licence/provenance review before public use"
    )


def collect_run_context(
    *,
    command: Sequence[str],
    affinity: str,
    isolation_method: str,
    heavy_jobs_disclosure: str,
    host_load_before: tuple[float, float, float] | None,
    host_load_after: tuple[float, float, float] | None,
) -> RunContext:
    """Collect deterministic run metadata around a benchmark evaluation."""
    return RunContext(
        command=" ".join(command),
        git_sha=_git_sha(),
        affinity=affinity,
        isolation_method=isolation_method,
        host_load_before=host_load_before,
        host_load_after=host_load_after,
        cpu_governor=_cpu_governors(),
        python_version=sys.version.split()[0],
        platform=platform.platform(),
        dependency_hashes=_dependency_hashes(),
        heavy_jobs_disclosure=heavy_jobs_disclosure,
    )


def run_action_evidence(
    *,
    command: Sequence[str],
    output_json: Path = _RESULT_JSON,
    output_md: Path = _RESULT_MD,
    affinity: str = _NO_AFFINITY,
    heavy_jobs_disclosure: str = "not recorded",
) -> BenchmarkEvidence:
    """Run the action-plane benchmark and write JSON plus Markdown evidence."""
    isolation_method = _apply_affinity(affinity)
    load_before = _host_load()
    started = time.perf_counter()
    authored = _load(_CORPUS)
    external = load_external_cases(_EXTERNAL_MANIFEST)
    metrics = evaluate(authored, external_corpus=external)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    load_after = _host_load()
    metrics = {**metrics, "elapsed_ms": elapsed_ms}
    context = collect_run_context(
        command=command,
        affinity=affinity,
        isolation_method=isolation_method,
        heavy_jobs_disclosure=heavy_jobs_disclosure,
        host_load_before=load_before,
        host_load_after=load_after,
    )
    external_metrics = metrics["external_metrics"]
    if not isinstance(external_metrics, Mapping):
        raise TypeError("external_metrics must be a mapping")
    external_count = int(external_metrics["n"])
    evidence = BenchmarkEvidence(
        benchmark="action_plane",
        evidence_grade=classify_evidence(
            isolated=context.isolated,
            external_count=external_count,
        ),
        metrics=metrics,
        run_context=context,
        external_sources=source_inventory(_EXTERNAL_MANIFEST),
    )
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(evidence.to_json(), indent=2) + "\n")
    output_md.write_text(render_markdown_report(evidence) + "\n")
    return evidence


def render_markdown_report(evidence: BenchmarkEvidence) -> str:
    """Render an operator-readable benchmark evidence report."""
    metrics = evidence.metrics
    authored = metrics["authored_metrics"]
    external = metrics["external_metrics"]
    if not isinstance(authored, Mapping) or not isinstance(external, Mapping):
        raise TypeError("metrics must include mapping-valued authored/external metrics")
    return "\n".join(
        [
            "# Action-Plane Benchmark Evidence",
            "",
            f"Evidence grade: {evidence.evidence_grade}",
            "",
            "## Run Context",
            "",
            f"- command: `{evidence.run_context.command}`",
            f"- git SHA: `{evidence.run_context.git_sha}`",
            f"- isolation method: `{evidence.run_context.isolation_method}`",
            f"- CPU affinity: `{evidence.run_context.affinity}`",
            (
                "- host load before: "
                f"`{_format_load(evidence.run_context.host_load_before)}`"
            ),
            f"- host load after: `{_format_load(evidence.run_context.host_load_after)}`",
            (
                "- CPU governor: "
                f"`{', '.join(evidence.run_context.cpu_governor) or 'unknown'}`"
            ),
            f"- Python: `{evidence.run_context.python_version}`",
            f"- platform: `{evidence.run_context.platform}`",
            f"- heavy jobs: `{evidence.run_context.heavy_jobs_disclosure}`",
            "",
            "## Metrics",
            "",
            f"- authored n: {authored['n']}",
            f"- external n: {external['n']}",
            f"- catastrophic recall: {float(metrics['catastrophic_recall']):.3f}",
            f"- false hard-block rate: {float(metrics['false_block_rate']):.3f}",
            f"- false escalation rate: {float(metrics['false_escalation_rate']):.3f}",
            (
                "- safe route conformance: "
                f"{_format_optional(metrics['safe_route_conformance'])}"
            ),
            f"- elapsed: {float(metrics['elapsed_ms']):.3f} ms",
            "",
            "## External Sources",
            "",
            *_external_source_lines(evidence.external_sources),
            "",
            "## Claim Boundary",
            "",
            "These results are benchmark evidence for the recorded checkout and run "
            "context only. Public comparative claims require isolated execution, "
            "loaded external artefacts, and licence/provenance review.",
        ]
    )


def main(argv: Sequence[str] | None = None) -> None:
    """CLI entry point for the action benchmark evidence runner."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-json", type=Path, default=_RESULT_JSON)
    parser.add_argument("--output-md", type=Path, default=_RESULT_MD)
    parser.add_argument(
        "--affinity",
        default=_NO_AFFINITY,
        help="comma-separated CPU cores to bind with os.sched_setaffinity",
    )
    parser.add_argument(
        "--heavy-jobs",
        default="not recorded",
        help="operator disclosure for other heavy host jobs",
    )
    args = parser.parse_args(argv)
    evidence = run_action_evidence(
        command=[sys.executable, "-m", "benchmarks.action_evidence", *sys.argv[1:]],
        output_json=args.output_json,
        output_md=args.output_md,
        affinity=args.affinity,
        heavy_jobs_disclosure=args.heavy_jobs,
    )
    print(render_markdown_report(evidence))
    print(f"\nwrote {args.output_json}")
    print(f"wrote {args.output_md}")


def _apply_affinity(affinity: str) -> str:
    if affinity == _NO_AFFINITY:
        return _NO_AFFINITY
    cores = _parse_affinity(affinity)
    if not hasattr(os, "sched_setaffinity"):
        raise RuntimeError("CPU affinity requested but os.sched_setaffinity is absent")
    os.sched_setaffinity(0, cores)
    return "sched_setaffinity"


def _parse_affinity(value: str) -> set[int]:
    cores = {int(part.strip()) for part in value.split(",") if part.strip()}
    if not cores:
        raise ValueError("affinity must contain at least one CPU core")
    if any(core < 0 for core in cores):
        raise ValueError("affinity CPU cores must be non-negative")
    return cores


def _host_load() -> tuple[float, float, float] | None:
    try:
        load = os.getloadavg()
    except OSError:
        return None
    return (float(load[0]), float(load[1]), float(load[2]))


def _cpu_governors() -> tuple[str, ...]:
    governors = {
        path.read_text(encoding="utf-8").strip()
        for path in Path("/sys/devices/system/cpu").glob(
            "cpu[0-9]*/cpufreq/scaling_governor"
        )
        if path.is_file()
    }
    return tuple(sorted(governors))


def _dependency_hashes() -> dict[str, str]:
    hashes: dict[str, str] = {}
    for rel in ("requirements/dev.txt", "requirements/ci-pre-commit.txt"):
        path = Path(rel)
        if path.is_file():
            hashes[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def _format_load(load: tuple[float, float, float] | None) -> str:
    if load is None:
        return "unavailable"
    return f"{load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}"


def _format_optional(value: object) -> str:
    if value is None:
        return "n/a"
    return f"{float(value):.3f}"


def _external_source_lines(sources: Sequence[Mapping[str, object]]) -> list[str]:
    if not sources:
        return ["- no external sources configured"]
    return [
        "- "
        f"{source['surface']}: loaded={source['loaded']}, "
        f"licence={source['licence']}, status={source['status']}"
        for source in sources
    ]


if __name__ == "__main__":
    main()
