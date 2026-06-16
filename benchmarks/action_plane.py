# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — action-plane benchmark harness

"""Measure the action plane on a labelled corpus of effector commands.

Runs the full action ensemble through a Governor over each labelled case and
reports the metrics that matter for a kill-switch: catastrophic recall (did we
stop the dangerous ones?), false-block rate on safe look-alikes (did we let the
ordinary ones through?), and the human-escalation rate. Results are written
machine-readably so they can be tracked across changes.

This is **seed / functional evidence**, not a claim-grade benchmark: the corpus is
small (~45 cases) and runs on a shared workstation. Per the Codex diagnosis, no
external benchmark claim should be made until the corpus reaches the ≥300-example,
isolated-run bar and is cross-checked against AgentDojo / SkillInject /
MCPSafeBench-style surfaces.
"""

from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, ".")

from director_class_ai.action import (  # noqa: E402
    MCP_CALL_KEY,
    BlastRadiusDetector,
    DestructiveCommandDetector,
    IntentConsistencyDetector,
    MCPCallInspector,
    MCPToolCall,
    OriginTaintDetector,
    serialise_call,
)
from director_class_ai.core import (  # noqa: E402
    EvaluationRequest,
    Governor,
    ParallelEnsembleScorer,
)

_CORPUS = Path(__file__).parent / "data" / "action_corpus_seed.jsonl"
_RESULTS = Path(__file__).parent / "results" / "action_plane_results.json"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _governor() -> Governor:
    ensemble = ParallelEnsembleScorer(
        [
            DestructiveCommandDetector(),
            BlastRadiusDetector(),
            OriginTaintDetector(),
            IntentConsistencyDetector(),
            MCPCallInspector(),
        ]
    )
    return Governor(ensemble=ensemble)  # no approver: escalation => not permitted


def _request(case: dict) -> EvaluationRequest:
    """Build the evaluation request, with the structured MCP path when present."""
    mcp = case.get("mcp_call")
    if mcp:
        call = MCPToolCall(
            server=mcp.get("server", ""),
            tool=mcp.get("tool", ""),
            arguments=mcp.get("arguments", {}),
            arg_provenance=mcp.get("arg_provenance", {}),
            default_provenance=mcp.get("default_provenance", case.get("provenance", "")),
        )
        return EvaluationRequest(
            action=serialise_call(call),
            query=case.get("query", ""),
            context=case.get("context", ""),
            action_provenance=call.default_provenance,
            metadata={MCP_CALL_KEY: call},
        )
    return EvaluationRequest(
        action=case["action"],
        query=case.get("query", ""),
        context=case.get("context", ""),
        action_provenance=case.get("provenance", ""),
    )


def evaluate(corpus: list[dict]) -> dict:
    gov = _governor()
    by_cat: dict[str, dict[str, int]] = defaultdict(
        lambda: {"catastrophic": 0, "caught": 0, "safe": 0, "false_block": 0}
    )
    catastrophic = caught = safe = false_block = escalated = 0
    latencies: list[float] = []

    for case in corpus:
        t0 = time.perf_counter()
        decision = gov.review(_request(case))
        latencies.append((time.perf_counter() - t0) * 1000)
        flagged = not decision.permitted  # blocked or escalated
        cat = case.get("category", "other")
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
            if flagged:
                false_block += 1
                by_cat[cat]["false_block"] += 1

    latencies.sort()
    return {
        "benchmark": "action_plane_seed",
        "evidence_grade": "functional-seed (not claim-grade; corpus < 300, shared host)",
        "n": len(corpus),
        "catastrophic_recall": caught / catastrophic if catastrophic else 0.0,
        "false_block_rate": false_block / safe if safe else 0.0,
        "escalation_rate": escalated / len(corpus) if corpus else 0.0,
        "n_catastrophic": catastrophic,
        "n_safe": safe,
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


def _markdown(r: dict) -> str:
    lines = [
        f"# Action-plane benchmark ({r['evidence_grade']})",
        "",
        f"- n = {r['n']} ({r['n_catastrophic']} catastrophic / {r['n_safe']} safe)",
        f"- catastrophic recall: {r['catastrophic_recall']:.3f}",
        f"- false-block rate (safe): {r['false_block_rate']:.3f}",
        f"- escalation rate: {r['escalation_rate']:.3f}",
        f"- latency p50: {r['latency_ms_p50']:.3f} ms",
    ]
    return "\n".join(lines)


def main() -> None:
    corpus = _load(_CORPUS)
    result = evaluate(corpus)
    _RESULTS.parent.mkdir(parents=True, exist_ok=True)
    _RESULTS.write_text(json.dumps(result, indent=2))
    print(_markdown(result))
    print(f"\nwrote {_RESULTS}")


if __name__ == "__main__":
    main()
