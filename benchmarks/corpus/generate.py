# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — action-corpus assembly + validation

"""Assemble the hand-curated seed and the authored catalogue into one corpus.

Deterministic: same inputs → byte-identical output. Validates the schema, unique
ids, and that both classes are present before writing, so a malformed case fails
the build rather than silently skewing the benchmark.
"""

from __future__ import annotations

import json
from pathlib import Path

from .catalogue import build_catalogue

_HERE = Path(__file__).resolve().parent
_SEED = _HERE.parent / "data" / "action_corpus_seed.jsonl"
_OUT = _HERE.parent / "data" / "action_corpus.jsonl"

_REQUIRED = {"id", "action", "label", "category", "severity"}
_LABELS = {"catastrophic", "safe"}


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def assemble(seed_path: Path | None = None) -> list[dict]:
    """Return seed ∪ catalogue as one validated, de-duplicated corpus."""
    seed = _load_jsonl(seed_path or _SEED)
    corpus = [*seed, *build_catalogue()]
    _validate(corpus)
    return corpus


def _validate(corpus: list[dict]) -> None:
    ids: set[str] = set()
    for case in corpus:
        missing = _REQUIRED - set(case)
        if missing:
            raise ValueError(f"case {case.get('id')!r} missing fields {missing}")
        if case["label"] not in _LABELS:
            raise ValueError(f"case {case['id']!r} has bad label {case['label']!r}")
        if case["id"] in ids:
            raise ValueError(f"duplicate id {case['id']!r}")
        ids.add(case["id"])
    labels = {c["label"] for c in corpus}
    if labels != _LABELS:
        raise ValueError(f"corpus must contain both classes, has {labels}")


def write_corpus(out_path: Path | None = None) -> Path:
    """Write the assembled corpus as JSONL and return the path."""
    out = out_path or _OUT
    corpus = assemble()
    lines = [json.dumps(case, ensure_ascii=False) for case in corpus]
    out.write_text("\n".join(lines) + "\n")
    return out


def main() -> None:
    corpus = assemble()
    out = write_corpus()
    catastrophic = sum(c["label"] == "catastrophic" for c in corpus)
    print(
        f"wrote {out} — {len(corpus)} cases "
        f"({catastrophic} catastrophic / {len(corpus) - catastrophic} safe)"
    )


if __name__ == "__main__":
    main()
