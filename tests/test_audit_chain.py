# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — hash-chained audit tests

from __future__ import annotations

import importlib
import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import director_class_ai.audit.chain as audit_chain
from director_class_ai.action import DestructiveCommandDetector
from director_class_ai.audit import AuditChainSink, verify_chain
from director_class_ai.core import (
    EvaluationRequest,
    Governor,
    ParallelEnsembleScorer,
)


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        self.t += 1.0
        return self.t


def _governor(path) -> Governor:
    sink = AuditChainSink(path=path, policy_profile="test", clock=_Clock())
    ensemble = ParallelEnsembleScorer([DestructiveCommandDetector()])
    return Governor(ensemble=ensemble, audit_sink=sink)


def _signed_governor(path, *, anchor_path=None) -> Governor:
    sink = AuditChainSink(
        path=path,
        policy_profile="test",
        clock=_Clock(),
        head_signing_key=b"test-signing-key",
        anchor_path=anchor_path,
    )
    ensemble = ParallelEnsembleScorer([DestructiveCommandDetector()])
    return Governor(ensemble=ensemble, audit_sink=sink)


def _populate(path, n: int = 4) -> Governor:
    gov = _governor(path)
    gov.review(EvaluationRequest(action="rm -rf /"))
    gov.review(EvaluationRequest(action="ls -la"))
    gov.review(EvaluationRequest(action="DROP TABLE t;"))
    gov.review(EvaluationRequest(action="cat x"))
    return gov


def test_appends_and_verifies(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _populate(p)
    assert p.read_text().count("\n") == 4
    assert verify_chain(p).ok is True


def test_genesis_and_linkage(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _populate(p)
    lines = [json.loads(line) for line in p.read_text().splitlines()]
    assert lines[0]["prev_hash"] == "0" * 64
    assert lines[1]["prev_hash"] == lines[0]["entry_hash"]
    assert [line["seq"] for line in lines] == [0, 1, 2, 3]


def test_mutation_detected(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _populate(p)
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["permitted"] = not rec["permitted"]  # tamper
    lines[1] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    v = verify_chain(p)
    assert v.ok is False and v.first_bad_index == 1


def test_reordering_detected(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _populate(p)
    lines = p.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    p.write_text("\n".join(lines) + "\n")
    assert verify_chain(p).ok is False


def test_deletion_detected(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _populate(p)
    lines = p.read_text().splitlines()
    del lines[1]  # remove a middle entry
    p.write_text("\n".join(lines) + "\n")
    assert verify_chain(p).ok is False


def test_tail_truncation_detected_via_head(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _populate(p)
    lines = p.read_text().splitlines()
    p.write_text(
        "\n".join(lines[:-1]) + "\n"
    )  # drop the last entry; head still points at it
    v = verify_chain(p)
    assert v.ok is False and "truncated" in v.reason


def test_one_entry_beyond_head_is_recoverable_crash_window(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _populate(p)
    lines = p.read_text(encoding="utf-8").splitlines()
    previous = json.loads(lines[-2])
    p.with_suffix(".jsonl.head").write_text(
        json.dumps(
            {"seq": previous["seq"], "entry_hash": previous["entry_hash"]},
        ),
        encoding="utf-8",
    )

    v = verify_chain(p)

    assert v.ok is True
    assert "recoverable" in v.reason


def test_signed_head_blocks_tail_truncation_with_rewritten_head(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _signed_governor(p).review(EvaluationRequest(action="rm -rf /"))
    _signed_governor(p).review(EvaluationRequest(action="ls -la"))
    lines = p.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    p.write_text(lines[0] + "\n", encoding="utf-8")
    p.with_suffix(".jsonl.head").write_text(
        json.dumps({"seq": first["seq"], "entry_hash": first["entry_hash"]}),
        encoding="utf-8",
    )

    unsigned = verify_chain(p)
    signed = verify_chain(p, head_signing_key=b"test-signing-key")

    assert unsigned.ok is True
    assert signed.ok is False
    assert "signature" in signed.reason


def test_signed_head_anchor_blocks_replayed_signed_prefix(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    anchor = tmp_path / "external-anchor.jsonl"
    gov = _signed_governor(p, anchor_path=anchor)
    gov.review(EvaluationRequest(action="rm -rf /"))
    old_head = p.with_suffix(".jsonl.head").read_text(encoding="utf-8")
    old_signature = p.with_suffix(".jsonl.head.sig").read_text(encoding="utf-8")
    old_log = p.read_text(encoding="utf-8")
    gov.review(EvaluationRequest(action="ls -la"))
    assert verify_chain(p, head_signing_key=b"test-signing-key", anchor_path=anchor).ok

    p.write_text(old_log, encoding="utf-8")
    p.with_suffix(".jsonl.head").write_text(old_head, encoding="utf-8")
    p.with_suffix(".jsonl.head.sig").write_text(old_signature, encoding="utf-8")
    replayed = verify_chain(p, head_signing_key=b"test-signing-key", anchor_path=anchor)

    assert replayed.ok is False
    assert "anchor" in replayed.reason


def test_signed_sink_requires_key_for_anchor(tmp_path) -> None:
    with pytest.raises(ValueError, match="anchor_path requires head_signing_key"):
        AuditChainSink(
            path=tmp_path / "audit.jsonl",
            anchor_path=tmp_path / "anchor.jsonl",
        )


def test_signed_head_verifies_without_anchor(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _signed_governor(p).review(EvaluationRequest(action="ls -la"))

    verification = verify_chain(p, head_signing_key=b"test-signing-key")

    assert verification.ok is True


def test_verify_chain_uses_python_when_rust_verifier_unavailable(
    tmp_path,
    monkeypatch,
) -> None:
    p = tmp_path / "audit.jsonl"
    _populate(p)
    monkeypatch.setattr(audit_chain, "_RUST_VERIFY_CHAIN", None)

    assert verify_chain(p).ok is True


def test_signed_verification_requires_signature_sidecar(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _signed_governor(p).review(EvaluationRequest(action="rm -rf /"))
    p.with_suffix(".jsonl.head.sig").unlink()

    verification = verify_chain(p, head_signing_key=b"test-signing-key")

    assert verification.ok is False
    assert "signature" in verification.reason


def test_corrupt_line_detected(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _populate(p)
    p.write_text(p.read_text() + "{ this is not json\n")
    assert verify_chain(p).ok is False


def test_restart_continuity(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _populate(p)  # first process
    _populate(p)  # a fresh sink/Governor on the same file continues the chain
    lines = [json.loads(line) for line in p.read_text().splitlines()]
    assert [line["seq"] for line in lines] == list(range(8))
    assert verify_chain(p).ok is True


def test_no_raw_action_text_in_log(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _populate(p)
    body = p.read_text()
    assert "rm -rf /" not in body and "DROP TABLE" not in body


def test_concurrent_writes(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    gov = _governor(p)

    def work() -> None:
        for _ in range(10):
            gov.review(EvaluationRequest(action="rm -rf /"))

    threads = [threading.Thread(target=work) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    lines = p.read_text().splitlines()
    assert len(lines) == 40
    assert verify_chain(p).ok is True


def test_missing_log_is_not_ok(tmp_path) -> None:
    assert verify_chain(tmp_path / "nope.jsonl").ok is False


from director_class_ai.core import DetectorSignal, Locus, Plane, Severity  # noqa: E402


class _BorderlineAction:
    name = "border"
    plane = Plane.ACTION
    tier = 0

    def evaluate(self, request):
        if "maybe" not in request.action:
            return None
        return DetectorSignal(
            detector=self.name,
            plane=Plane.ACTION,
            score=0.2,
            locus=Locus.ACTION,
            signal_type="border",
            severity=Severity.MEDIUM,
        )


def _escalating(path, approval):
    sink = AuditChainSink(path=path, clock=_Clock())
    ens = ParallelEnsembleScorer([_BorderlineAction()])
    return Governor(ensemble=ens, audit_sink=sink, approval=approval)


def test_approval_state_approved(tmp_path) -> None:
    p = tmp_path / "a.jsonl"
    _escalating(p, lambda _v, _r: True).review(EvaluationRequest(action="maybe op"))
    rec = json.loads(p.read_text().splitlines()[0])
    assert rec["approval_state"] == "approved" and rec["escalated"] is True


def test_approval_state_denied_or_pending(tmp_path) -> None:
    p = tmp_path / "a.jsonl"
    _escalating(p, None).review(EvaluationRequest(action="maybe op"))
    rec = json.loads(p.read_text().splitlines()[0])
    assert rec["approval_state"] == "denied_or_pending"


def test_append_continues_from_preexisting_empty_file(tmp_path) -> None:
    p = tmp_path / "a.jsonl"
    p.write_text("")  # exists but empty
    _populate(p)
    assert verify_chain(p).ok is True
    assert json.loads(p.read_text().splitlines()[0])["seq"] == 0


def test_blank_lines_tolerated(tmp_path) -> None:
    p = tmp_path / "a.jsonl"
    _populate(p)
    p.write_text(p.read_text().replace("\n", "\n\n", 1))  # inject a blank line
    assert verify_chain(p).ok is True


def test_prev_hash_only_mutation_detected(tmp_path) -> None:
    p = tmp_path / "a.jsonl"
    _populate(p)
    lines = p.read_text().splitlines()
    rec = json.loads(lines[2])
    rec["prev_hash"] = "f" * 64  # break linkage but keep seq
    lines[2] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    v = verify_chain(p)
    assert v.ok is False and "prev_hash" in v.reason


def test_missing_head_sidecar_still_verifies(tmp_path) -> None:
    p = tmp_path / "a.jsonl"
    _populate(p)
    p.with_suffix(".jsonl.head").unlink()  # remove the sidecar
    assert verify_chain(p).ok is True


def test_last_skips_blank_lines_on_append(tmp_path) -> None:
    p = tmp_path / "a.jsonl"
    _populate(p)
    p.write_text(p.read_text() + "\n")  # trailing blank line
    _governor(p).review(EvaluationRequest(action="ls"))  # _last must skip the blank
    assert verify_chain(p).ok is True
    assert json.loads(p.read_text().splitlines()[-1])["seq"] == 4


def test_sink_caches_head_after_initial_tail_scan(tmp_path, monkeypatch) -> None:
    p = tmp_path / "audit.jsonl"
    sink = AuditChainSink(path=p, policy_profile="test", clock=_Clock())
    ensemble = ParallelEnsembleScorer([DestructiveCommandDetector()])
    gov = Governor(ensemble=ensemble, audit_sink=sink)
    calls = 0
    original_last = AuditChainSink._last

    def counted_last(self: AuditChainSink) -> tuple[int, str]:
        nonlocal calls
        calls += 1
        return original_last(self)

    monkeypatch.setattr(AuditChainSink, "_last", counted_last)

    for action in ("rm -rf /", "ls -la", "DROP TABLE t;", "cat x"):
        gov.review(EvaluationRequest(action=action))

    assert calls == 1
    lines = [json.loads(line) for line in p.read_text().splitlines()]
    assert [line["seq"] for line in lines] == [0, 1, 2, 3]
    assert verify_chain(p).ok is True


def test_sink_reloads_head_after_partial_sidecar_failure(tmp_path, monkeypatch) -> None:
    p = tmp_path / "audit.jsonl"
    sink = AuditChainSink(path=p, policy_profile="test", clock=_Clock())
    ensemble = ParallelEnsembleScorer([DestructiveCommandDetector()])
    gov = Governor(ensemble=ensemble, audit_sink=sink)
    failed = False
    original_atomic_write = audit_chain.atomic_write_text

    def fail_first_head_write(
        path: str | Path,
        text: str,
        *,
        encoding: str = "utf-8",
    ) -> None:
        nonlocal failed
        if not failed and Path(path).suffix == ".head":
            failed = True
            raise OSError("simulated sidecar crash")
        original_atomic_write(path, text, encoding=encoding)

    monkeypatch.setattr(audit_chain, "atomic_write_text", fail_first_head_write)

    with pytest.raises(OSError, match="simulated sidecar crash"):
        gov.review(EvaluationRequest(action="rm -rf /"))
    gov.review(EvaluationRequest(action="ls -la"))

    lines = [json.loads(line) for line in p.read_text().splitlines()]
    assert [line["seq"] for line in lines] == [0, 1]
    assert lines[1]["prev_hash"] == lines[0]["entry_hash"]
    assert verify_chain(p).ok is True


def test_anchor_verification_requires_signed_head(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _populate(p)

    verification = verify_chain(p, anchor_path=tmp_path / "anchor.jsonl")

    assert verification.ok is False
    assert "requires head signature" in verification.reason


def test_signed_verification_requires_head_sidecar(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _signed_governor(p).review(EvaluationRequest(action="ls -la"))
    p.with_suffix(".jsonl.head").unlink()

    verification = verify_chain(p, head_signing_key=b"test-signing-key")

    assert verification.ok is False
    assert "head sidecar" in verification.reason


@pytest.mark.parametrize(
    ("head_payload", "signature_payload"),
    [
        ("[]", "{}"),
        ("{bad json", "{}"),
        ('{"seq":"bad","entry_hash":"x"}', "{}"),
    ],
)
def test_signed_head_metadata_corruption_is_rejected(
    tmp_path,
    head_payload: str,
    signature_payload: str,
) -> None:
    p = tmp_path / "audit.jsonl"
    _signed_governor(p).review(EvaluationRequest(action="ls -la"))
    p.with_suffix(".jsonl.head").write_text(head_payload, encoding="utf-8")
    p.with_suffix(".jsonl.head.sig").write_text(
        signature_payload,
        encoding="utf-8",
    )

    verification = verify_chain(p, head_signing_key=b"test-signing-key")

    assert verification.ok is False
    assert (
        "metadata is corrupt" in verification.reason
        or "head sidecar is corrupt" in verification.reason
        or "head sidecar mismatch" in verification.reason
    )


def test_signed_head_rejects_algorithm_and_signature_mismatch(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _signed_governor(p).review(EvaluationRequest(action="ls -la"))
    signature_path = p.with_suffix(".jsonl.head.sig")
    signature = json.loads(signature_path.read_text(encoding="utf-8"))
    signature["alg"] = "none"
    signature_path.write_text(json.dumps(signature), encoding="utf-8")

    bad_algorithm = verify_chain(p, head_signing_key=b"test-signing-key")
    signature["alg"] = "HMAC-SHA256"
    signature["signature"] = "0" * 64
    signature_path.write_text(json.dumps(signature), encoding="utf-8")
    bad_signature = verify_chain(p, head_signing_key=b"test-signing-key")

    assert bad_algorithm.ok is False
    assert "algorithm" in bad_algorithm.reason
    assert bad_signature.ok is False
    assert "mismatch" in bad_signature.reason


def test_signed_head_rejects_corrupt_signature_sidecar(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    _signed_governor(p).review(EvaluationRequest(action="ls -la"))
    signature_path = p.with_suffix(".jsonl.head.sig")

    signature_path.write_text("[]", encoding="utf-8")
    non_object = verify_chain(p, head_signing_key=b"test-signing-key")
    signature_path.write_text("{bad json", encoding="utf-8")
    corrupt_json = verify_chain(p, head_signing_key=b"test-signing-key")

    assert non_object.ok is False
    assert "metadata is corrupt" in non_object.reason
    assert corrupt_json.ok is False
    assert "metadata is corrupt" in corrupt_json.reason


@pytest.mark.parametrize(
    ("anchor_payload", "reason"),
    [
        ("", "empty"),
        ("{bad json\n", "corrupt"),
        ("[]\n", "corrupt"),
        ('{"alg":"none","signature":"x","head":{}}\n', "algorithm"),
        ('{"alg":"HMAC-SHA256","signature":"x","head":{}}\n', "signature"),
        ('{"alg":"HMAC-SHA256","signature":"__REAL__","head":[]}\n', "head mismatch"),
        (
            '{"alg":"HMAC-SHA256","signature":"__REAL__","head":{"seq":999}}\n',
            "head mismatch",
        ),
    ],
)
def test_anchor_log_corruption_is_rejected(
    tmp_path,
    anchor_payload: str,
    reason: str,
) -> None:
    p = tmp_path / "audit.jsonl"
    anchor = tmp_path / "anchor.jsonl"
    _signed_governor(p, anchor_path=anchor).review(EvaluationRequest(action="ls -la"))
    if anchor_payload:
        if "__REAL__" in anchor_payload:
            signature = json.loads(
                p.with_suffix(".jsonl.head.sig").read_text(encoding="utf-8")
            )["signature"]
            anchor_payload = anchor_payload.replace("__REAL__", signature)
        anchor.write_text(anchor_payload, encoding="utf-8")
    else:
        anchor.write_text("", encoding="utf-8")

    verification = verify_chain(
        p,
        head_signing_key=b"test-signing-key",
        anchor_path=anchor,
    )

    assert verification.ok is False
    assert reason in verification.reason


def test_missing_anchor_log_is_rejected(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    anchor = tmp_path / "anchor.jsonl"
    _signed_governor(p).review(EvaluationRequest(action="ls -la"))

    verification = verify_chain(
        p,
        head_signing_key=b"test-signing-key",
        anchor_path=anchor,
    )

    assert verification.ok is False
    assert "anchor log does not exist" in verification.reason


def test_anchor_verification_uses_latest_nonblank_anchor(tmp_path) -> None:
    p = tmp_path / "audit.jsonl"
    anchor = tmp_path / "anchor.jsonl"
    _signed_governor(p, anchor_path=anchor).review(EvaluationRequest(action="ls -la"))
    anchor.write_text("\n" + anchor.read_text(encoding="utf-8"), encoding="utf-8")

    verification = verify_chain(
        p,
        head_signing_key=b"test-signing-key",
        anchor_path=anchor,
    )

    assert verification.ok is True


class TestRustAuditPrimitivesParity:
    def test_loader_ignores_missing_callables(self, monkeypatch) -> None:
        module = SimpleNamespace(audit_entry_hash=object(), audit_verify_chain=object())
        monkeypatch.setattr(importlib, "import_module", lambda _: module)
        assert audit_chain._load_rust_entry_hash() is None
        assert audit_chain._load_rust_verify_chain() is None

    def test_loaders_return_none_when_extension_is_absent(self, monkeypatch) -> None:
        def missing_extension(_name: str) -> object:
            raise ImportError("extension absent")

        monkeypatch.setattr(importlib, "import_module", missing_extension)

        assert audit_chain._load_rust_entry_hash() is None
        assert audit_chain._load_rust_verify_chain() is None

    def test_entry_hash_uses_python_when_rust_unavailable(self, monkeypatch) -> None:
        payload = {"seq": 0, "prev_hash": "0" * 64, "risk": 1.0}
        monkeypatch.setattr(audit_chain, "_RUST_ENTRY_HASH", None)
        expected = audit_chain._entry_hash_python("0" * 64, payload)
        assert audit_chain._entry_hash("0" * 64, payload) == expected

    def test_entry_hash_mismatch_falls_back_to_python(self, monkeypatch) -> None:
        payload = {"seq": 0, "prev_hash": "0" * 64, "risk": 1.0}
        monkeypatch.setattr(audit_chain, "_RUST_ENTRY_HASH", lambda _prev, _payload: "x")
        expected = audit_chain._entry_hash_python("0" * 64, payload)
        assert audit_chain._entry_hash("0" * 64, payload) == expected

    def test_entry_hash_exception_falls_back_to_python(self, monkeypatch) -> None:
        payload = {"seq": 0, "prev_hash": "0" * 64, "risk": 1.0}

        def broken_hash(_prev: str, _payload: str) -> str:
            raise RuntimeError("boom")

        monkeypatch.setattr(audit_chain, "_RUST_ENTRY_HASH", broken_hash)
        expected = audit_chain._entry_hash_python("0" * 64, payload)
        assert audit_chain._entry_hash("0" * 64, payload) == expected

    def test_verify_mismatch_falls_back_to_python(self, tmp_path, monkeypatch) -> None:
        p = tmp_path / "audit.jsonl"
        _populate(p)

        def wrong_verify(_lines, _head):
            return (False, 0, "wrong")

        monkeypatch.setattr(audit_chain, "_RUST_VERIFY_CHAIN", wrong_verify)
        assert verify_chain(p) == audit_chain._verify_chain_python(p)

    def test_verify_exception_falls_back_to_python(self, tmp_path, monkeypatch) -> None:
        p = tmp_path / "audit.jsonl"
        _populate(p)

        def broken_verify(_lines, _head):
            raise RuntimeError("boom")

        monkeypatch.setattr(audit_chain, "_RUST_VERIFY_CHAIN", broken_verify)
        assert verify_chain(p) == audit_chain._verify_chain_python(p)

    def test_installed_rust_primitives_match_python_when_present(self, tmp_path) -> None:
        if audit_chain._RUST_ENTRY_HASH is None or audit_chain._RUST_VERIFY_CHAIN is None:
            return
        p = tmp_path / "audit.jsonl"
        _populate(p)
        payload = {"seq": 0, "prev_hash": "0" * 64, "risk": 1.0}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        assert audit_chain._RUST_ENTRY_HASH("0" * 64, canonical) == (
            audit_chain._entry_hash_python("0" * 64, payload)
        )
        lines = p.read_text(encoding="utf-8").splitlines()
        head = p.with_suffix(".jsonl.head").read_text(encoding="utf-8")
        assert audit_chain.ChainVerification(
            *audit_chain._RUST_VERIFY_CHAIN(lines, head)
        ) == audit_chain._verify_chain_python(p)
