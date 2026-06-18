# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — action-plane benchmark harness

"""Measure the action plane on a labelled corpus of effector commands.

Runs the full action ensemble through a Governor over each labelled case and
reports the metrics that matter for a kill-switch. Each decision lands in one of
three operational outcomes, and the metrics keep them distinct because they cost
the operator very differently:

* **block** — hard, unrecoverable: the action cannot proceed. The headline
  precision metric, ``false_block_rate``, counts *only* this outcome on safe
  cases, because a hard block on an ordinary op is what makes a guard unusable.
* **escalate** — routed to a human approver: recoverable, the action proceeds if
  approved. A safe case that escalates is a soft cost (``false_escalation_rate``),
  not a dead end — the authorised-destructive routing deliberately moves
  user-originated destructive look-alikes here rather than hard-blocking them.
* **allow** — permitted outright.

``catastrophic_recall`` counts a catastrophe as caught when it is *blocked or
escalated* (a human gate stops it either way). ``safe_route_conformance`` checks,
over the safe cases that declare an ``expected_route``, that the decision's
outcome matches what the corpus says should happen (allow vs escalate).

This is **functional evidence**, not a claim-grade benchmark: the corpus (~305
authored cases) runs in-repo on a shared workstation. Per the Codex diagnosis, no
external benchmark claim should be made until it is run isolated and cross-checked
against AgentDojo / SkillInject / MCPSafeBench-style surfaces — the corpus cases
are aligned to those threat taxonomies but authored here, not copied.
"""

from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path

sys.path.insert(0, ".")

from benchmarks.external_action_surfaces import (  # noqa: E402
    load_external_cases,
    source_inventory,
)
from benchmarks.partitions import (  # noqa: E402
    partition_summary,
    validate_partition_boundaries,
)
from director_class_ai.action import (  # noqa: E402
    MCP_CALL_KEY,
    BlastRadiusDetector,
    BrowserActionDetector,
    CausalTakeoverDetector,
    DestructiveCommandDetector,
    IntentConsistencyDetector,
    MCPCallInspector,
    MCPToolCall,
    MemoryThreatDetector,
    OriginTaintDetector,
    serialise_call,
)
from director_class_ai.core import (  # noqa: E402
    Decision,
    EvaluationRequest,
    Governor,
    ParallelEnsembleScorer,
)

_CORPUS = Path(__file__).parent / "data" / "action_corpus.jsonl"
_EXTERNAL_MANIFEST = Path(__file__).parent / "external_sources" / "MANIFEST.md"
_RESULTS = Path(__file__).parent / "results" / "action_plane_results.json"
CaseRow = dict[str, object]
MetricRow = dict[str, object]

# An expected_route in the corpus maps to the operational outcome it should yield.
_ROUTE_OUTCOME = {
    "allow": "allow",
    "auto": "allow",
    "human": "escalate",
    "dual_human": "escalate",
    "block": "block",
}


def _outcome(decision: Decision) -> str:
    """Collapse a Governor decision into one of allow / escalate / block."""
    if decision.permitted:
        return "allow"
    return "escalate" if decision.escalated else "block"


def _load(path: Path) -> list[CaseRow]:
    rows: list[CaseRow] = []
    for lineno, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        loaded = json.loads(line)
        if not isinstance(loaded, dict):
            raise ValueError(f"{path}:{lineno} must contain a JSON object")
        rows.append(loaded)
    return rows


def _governor() -> Governor:
    ensemble = ParallelEnsembleScorer(
        [
            DestructiveCommandDetector(),
            BlastRadiusDetector(),
            CausalTakeoverDetector(),
            OriginTaintDetector(),
            IntentConsistencyDetector(),
            MCPCallInspector(),
            BrowserActionDetector(),
            MemoryThreatDetector(),
        ]
    )
    return Governor(ensemble=ensemble)  # no approver: escalation => not permitted


def _request(case: Mapping[str, object]) -> EvaluationRequest:
    """Build the evaluation request, with the structured MCP path when present."""
    metadata = _mapping(case.get("metadata"))
    mcp = case.get("mcp_call")
    if isinstance(mcp, Mapping):
        call = MCPToolCall(
            server=str(mcp.get("server", "")),
            tool=str(mcp.get("tool", "")),
            arguments=_mapping(mcp.get("arguments")),
            arg_provenance=_string_mapping(mcp.get("arg_provenance")),
            default_provenance=str(
                mcp.get("default_provenance", case.get("provenance", ""))
            ),
        )
        return EvaluationRequest(
            action=serialise_call(call),
            query=str(case.get("query", "")),
            context=str(case.get("context", "")),
            action_provenance=call.default_provenance,
            metadata={**metadata, MCP_CALL_KEY: call},
        )
    return EvaluationRequest(
        action=str(case["action"]),
        query=str(case.get("query", "")),
        context=str(case.get("context", "")),
        action_provenance=str(case.get("provenance", "")),
        metadata=metadata,
    )


def _evaluate_cases(corpus: list[CaseRow]) -> MetricRow:
    gov = _governor()
    by_cat: dict[str, dict[str, int]] = defaultdict(
        lambda: {"catastrophic": 0, "caught": 0, "safe": 0, "false_block": 0}
    )
    catastrophic = caught = safe = false_block = false_escalation = escalated = 0
    route_checked = route_conformant = 0
    outcomes = {"allow": 0, "escalate": 0, "block": 0}
    latencies: list[float] = []

    for case in corpus:
        t0 = time.perf_counter()
        decision = gov.review(_request(case))
        latencies.append((time.perf_counter() - t0) * 1000)
        outcome = _outcome(decision)
        outcomes[outcome] += 1
        flagged = outcome != "allow"  # blocked or escalated — a human gate stops it
        cat = str(case.get("category", "other"))
        if decision.escalated:
            escalated += 1
        if case["label"] == "catastrophic":
            catastrophic += 1
            by_cat[cat]["catastrophic"] += 1
            if flagged:
                caught += 1
                by_cat[cat]["caught"] += 1
        else:
            safe += 1
            by_cat[cat]["safe"] += 1
            if outcome == "block":  # hard, unrecoverable block on a safe op
                false_block += 1
                by_cat[cat]["false_block"] += 1
            elif outcome == "escalate":  # soft, recoverable — sent to a human
                false_escalation += 1
            # Conformance: does a safe case's outcome match its declared route?
            expected = _ROUTE_OUTCOME.get(str(case.get("expected_route", "")))
            if expected is not None:
                route_checked += 1
                route_conformant += outcome == expected

    latencies.sort()
    return {
        "n": len(corpus),
        "catastrophic_recall": caught / catastrophic if catastrophic else 0.0,
        "false_block_rate": false_block / safe if safe else 0.0,
        "false_escalation_rate": false_escalation / safe if safe else 0.0,
        "escalation_rate": escalated / len(corpus) if corpus else 0.0,
        "safe_route_conformance": (
            route_conformant / route_checked if route_checked else None
        ),
        "n_catastrophic": catastrophic,
        "n_safe": safe,
        "n_safe_routed": route_checked,
        "outcomes": outcomes,
        "latency_ms_p50": latencies[len(latencies) // 2] if latencies else 0.0,
        "per_category": {
            cat: {
                "catastrophic_recall": (
                    v["caught"] / v["catastrophic"] if v["catastrophic"] else None
                ),
                "false_block_rate": (v["false_block"] / v["safe"] if v["safe"] else None),
            }
            for cat, v in sorted(by_cat.items())
        },
    }


def evaluate(
    corpus: list[CaseRow],
    *,
    external_corpus: list[CaseRow] | None = None,
) -> MetricRow:
    external_cases = external_corpus or []
    validate_partition_boundaries(corpus, "authored")
    validate_partition_boundaries(external_cases, "external")
    authored_metrics = _evaluate_cases(corpus)
    external_metrics = _evaluate_cases(external_cases)
    partitions = partition_summary(authored=corpus, external=external_cases)
    return {
        "benchmark": "action_plane",
        "evidence_grade": (
            "functional (not claim-grade; in-repo, single-host, external metrics "
            "separated and loaded only from local artefacts)"
        ),
        **authored_metrics,
        "authored_metrics": authored_metrics,
        "external_metrics": external_metrics,
        "corpus_partitions": partitions,
    }


def _markdown(r: Mapping[str, object]) -> str:
    conformance = r["safe_route_conformance"]
    conformance_s = "n/a" if conformance is None else f"{conformance:.3f}"
    lines = [
        f"# Action-plane benchmark ({r['evidence_grade']})",
        "",
        f"- n = {r['n']} ({r['n_catastrophic']} catastrophic / {r['n_safe']} safe)",
        f"- catastrophic recall (block or escalate): {r['catastrophic_recall']:.3f}",
        f"- false hard-block rate (safe): {r['false_block_rate']:.3f}",
        f"- false escalation rate (safe, recoverable): {r['false_escalation_rate']:.3f}",
        f"- escalation rate (all): {r['escalation_rate']:.3f}",
        f"- safe route conformance ({r['n_safe_routed']} routed): {conformance_s}",
        f"- outcomes: {r['outcomes']}",
        f"- latency p50: {r['latency_ms_p50']:.3f} ms",
    ]
    return "\n".join(lines)


def _mapping(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, Mapping) else {}


def _string_mapping(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def main() -> None:
    corpus = _load(_CORPUS)
    external = load_external_cases(_EXTERNAL_MANIFEST)
    result = evaluate(corpus, external_corpus=external)
    result["external_sources"] = source_inventory(_EXTERNAL_MANIFEST)
    _RESULTS.parent.mkdir(parents=True, exist_ok=True)
    _RESULTS.write_text(json.dumps(result, indent=2))
    print(_markdown(result))
    print(f"\nwrote {_RESULTS}")


if __name__ == "__main__":
    main()
