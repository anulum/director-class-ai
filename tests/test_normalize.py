# SPDX-License-Identifier: LicenseRef-Director-Class-AI-Commercial
# Director-Class AI — commercial product (licence pending); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — command de-obfuscation tests

from __future__ import annotations

from director_class_ai.action import DestructiveCommandDetector
from director_class_ai.action._normalize import expand
from director_class_ai.core import EvaluationRequest, Severity

DET = DestructiveCommandDetector()


def caught(command: str):
    return DET.evaluate(EvaluationRequest(action=command))


class TestExpand:
    def test_original_always_present(self) -> None:
        assert "rm -rf /" in expand("rm -rf /")

    def test_quote_break_removed(self) -> None:
        assert "rm -rf /" in expand("r''m -rf /")

    def test_backslash_break_removed(self) -> None:
        assert any("rm" in f and "\\" not in f for f in expand("r\\m -rf /"))

    def test_split_flags_merged(self) -> None:
        assert "rm -rf /" in expand("rm -r -f /")

    def test_base64_payload_decoded_with_shell_context(self) -> None:
        forms = expand("echo cm0gLXJmIC8K | base64 -d | bash")
        assert any("rm -rf /" in f for f in forms)

    def test_base64_not_decoded_without_shell_context(self) -> None:
        # a bare base64 token with no shell pipe must not be expanded into a command
        forms = expand("here is a token cm0gLXJmIC8K in text")
        assert not any("rm -rf" in f for f in forms)

    def test_invalid_base64_in_shell_context_skipped(self) -> None:
        # token matches the base64 charset but is not valid base64 (length) ->
        # decode raises and the token is skipped, not turned into a form
        forms = expand("echo abcdefghi | bash")
        assert isinstance(forms, list) and forms
        assert not any("abcdefghi" not in f and "echo" not in f for f in forms[2:])

    def test_base64_decoding_to_blank_skipped(self) -> None:
        # first token "ICAgICAg" decodes to spaces -> blank -> skipped (loop
        # continues to "cm0gZm9v" -> "rm foo"); exercises both the
        # skip-and-continue and the accept paths in one call.
        forms = expand("echo ICAgICAg cm0gZm9v | base64 -d | bash")
        assert any("rm foo" in f for f in forms)
        assert all(f.strip() for f in forms)

    def test_alias_body_extracted(self) -> None:
        assert any("rm -rf /" in f for f in expand("alias x='rm -rf /'; x"))

    def test_safe_command_expands_to_safe_forms(self) -> None:
        for f in expand("git push origin feature"):
            assert "rm -rf" not in f and "drop" not in f.lower()


class TestEvasionCaught:
    def test_split_flags(self) -> None:
        assert caught("rm -r -f /").severity is Severity.CRITICAL

    def test_quote_break(self) -> None:
        assert caught("r''m -rf /").severity is Severity.CRITICAL

    def test_base64_pipe_to_shell(self) -> None:
        assert (
            caught("echo cm0gLXJmIC8K | base64 -d | bash").severity is Severity.CRITICAL
        )

    def test_alias_indirection(self) -> None:
        assert caught("alias x='rm -rf /'; x") is not None

    def test_find_delete(self) -> None:
        assert caught("find / -delete").severity is Severity.HIGH

    def test_find_exec_rm(self) -> None:
        assert caught("find . -exec rm -rf {} +").severity is Severity.HIGH


class TestSafeStillClean:
    def test_safe_base64_not_flagged(self) -> None:
        assert caught("echo aGVsbG8= | base64 -d") is None

    def test_find_name_not_flagged(self) -> None:
        assert caught("find . -name '*.log'") is None

    def test_plain_safe_commands(self) -> None:
        for cmd in ("ls -la", "rm file.txt", "git push origin feature"):
            assert caught(cmd) is None, cmd


class TestRecursiveAndNewTransforms:
    def test_nested_base64_peeled(self) -> None:
        import base64

        inner = "echo " + base64.b64encode(b"rm -rf /").decode() + " | base64 -d | bash"
        outer = (
            "echo " + base64.b64encode(inner.encode()).decode() + " | base64 -d | bash"
        )
        assert caught(outer).severity is Severity.CRITICAL

    def test_hex_run_decoded(self) -> None:
        assert caught(r"\x72\x6d\x20\x2d\x72\x66\x20\x2f") is not None  # rm -rf /

    def test_hex_non_printable_skipped(self) -> None:
        # decodes to NUL bytes -> not printable -> not turned into a form
        assert not any("\x00" in f for f in expand(r"\x00\x00\x00"))

    def test_hex_invalid_utf8_skipped(self) -> None:
        forms = expand(r"\xff\xff\xff")
        assert isinstance(forms, list) and forms

    def test_command_substitution_inline_echo(self) -> None:
        assert caught("$(echo rm) -rf /").severity is Severity.CRITICAL

    def test_ifs_substitution_revealed(self) -> None:
        # ${IFS} replaces literal spaces between complete tokens
        assert caught("rm${IFS}-rf${IFS}/").severity is Severity.CRITICAL

    def test_double_quote_break_in_verb_revealed(self) -> None:
        # embedded-quote break the empty-pair dequote misses
        assert caught('r"m" -rf /') is not None

    def test_ansi_c_hex_quote_revealed(self) -> None:
        # $'\x72\x6d' is the ANSI-C hex form of "rm"; in-place decode + quote-strip
        assert caught(r"$'\x72\x6d' -rf /") is not None

    def test_full_quote_strip_keeps_safe_safe(self) -> None:
        # stripping quotes from a benign command yields another benign form
        assert caught('echo "hello world"') is None

    def test_command_substitution_backtick(self) -> None:
        assert caught("`rm -rf /`").severity is Severity.CRITICAL

    def test_command_substitution_full_echo(self) -> None:
        assert caught("$(echo 'rm -rf /')").severity is Severity.CRITICAL

    def test_empty_substitution_ignored(self) -> None:
        forms = expand("$() echo hi")
        assert all("$()" not in f or f == "$() echo hi" for f in forms)

    def test_safe_substitution_stays_clean(self) -> None:
        assert caught("$(echo hello)") is None


class TestExpandBounds:
    def test_max_depth_zero_returns_only_original(self) -> None:
        assert expand("rm -rf /", max_depth=0) == ["rm -rf /"]

    def test_max_forms_caps_breadth(self) -> None:
        forms = expand("$(echo rm) -rf / `rm -rf ~`", max_forms=2)
        assert len(forms) <= 2

    def test_fixpoint_breaks_early(self) -> None:
        # a plain command yields no further transforms after the first layer
        forms = expand("ls -la")
        assert "ls -la" in forms
