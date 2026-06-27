# SPDX-License-Identifier: BUSL-1.1
# Director-Class AI — commercial product (BUSL-1.1); not the Apache base.
# © Concepts 1996–2026 Miroslav Šotek. All rights reserved.
# © Code 2020–2026 Miroslav Šotek. All rights reserved.
# ORCID: 0009-0009-3560-0851
# Contact: www.anulum.li | protoscience@anulum.li
# Director-Class AI — command de-obfuscation tests

from __future__ import annotations

from types import SimpleNamespace

import pytest

import director_class_ai.action._normalize as normalize
from director_class_ai.action import DestructiveCommandDetector, _shell_segments
from director_class_ai.action._normalize import (
    _expand_python,
    expand,
    rust_backend_available,
)
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

    def test_invalid_shell_assignment_name_is_not_classified(self) -> None:
        assert _shell_segments._is_shell_assignment("1BAD=rm") is False


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

    def test_octal_run_decoded(self) -> None:
        assert any(f == "rm" for f in expand(r"\162\155"))

    def test_octal_invalid_utf8_skipped(self) -> None:
        forms = expand(r"\377\377")
        assert isinstance(forms, list) and forms

    def test_octal_non_printable_skipped(self) -> None:
        assert not any("\x00" in f for f in expand(r"\000\000"))

    def test_xargs_octal_printf_reconstructs_command(self) -> None:
        forms = expand(r"printf '\162\155' | xargs -I{} {} -rf /")
        assert "rm -rf /" in forms

    def test_xargs_malformed_payload_stays_clean(self) -> None:
        forms = expand(r"printf \ | xargs -I{} {} -rf /")
        assert "rm -rf /" not in forms

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

    def test_safe_octal_printf_stays_clean(self) -> None:
        assert caught(r"printf '\154\163'") is None

    def test_xargs_echo_lookalike_stays_clean(self) -> None:
        assert caught(r"printf '\162\155' | xargs -I{} echo {} -rf /") is None

    def test_xargs_project_local_cleanup_stays_clean(self) -> None:
        assert caught(r"printf '\162\155' | xargs -I{} {} -rf ./build") is None

    def test_gzip_base64_payload_decoded_with_shell_context(self) -> None:
        import base64
        import gzip

        payload = base64.b64encode(gzip.compress(b"rm -rf /")).decode()
        assert caught(f"echo {payload} | base64 -d | gunzip | bash") is not None

    def test_zlib_base64_payload_decoded_with_shell_context(self) -> None:
        import base64
        import zlib

        payload = base64.b64encode(zlib.compress(b"DROP TABLE users;")).decode()
        assert caught(f"echo {payload} | base64 -d | zlib-flate -uncompress | sh")

    def test_bzip2_base64_payload_decoded_with_shell_context(self) -> None:
        import base64
        import bz2

        payload = base64.b64encode(bz2.compress(b"rm -rf /")).decode()
        assert caught(f"echo {payload} | base64 -d | bunzip2 | bash") is not None

    def test_lzma_base64_payload_decoded_with_shell_context(self) -> None:
        import base64
        import lzma

        payload = base64.b64encode(lzma.compress(b"DROP TABLE users;")).decode()
        assert caught(f"echo {payload} | base64 -d | xz -d | sh") is not None

    def test_binary_payload_without_shell_context_stays_opaque(self) -> None:
        import base64
        import gzip

        payload = base64.b64encode(gzip.compress(b"rm -rf /")).decode()
        assert not any("rm -rf /" in f for f in expand(f"archive={payload}"))

    def test_bzip2_payload_without_shell_context_stays_opaque(self) -> None:
        import base64
        import bz2

        payload = base64.b64encode(bz2.compress(b"rm -rf /")).decode()
        assert not any("rm -rf /" in f for f in expand(f"archive={payload}"))

    def test_lzma_payload_without_shell_context_stays_opaque(self) -> None:
        import base64
        import lzma

        payload = base64.b64encode(lzma.compress(b"DROP TABLE users;")).decode()
        assert not any("DROP TABLE users;" in f for f in expand(f"archive={payload}"))

    def test_compressed_non_printable_payload_skipped(self) -> None:
        import base64
        import zlib

        payload = base64.b64encode(zlib.compress(b"\x00\x00")).decode()
        forms = expand(f"echo {payload} | base64 -d | zlib-flate -uncompress | sh")
        assert not any("\x00" in f for f in forms)

    def test_env_var_command_indirection_revealed(self) -> None:
        assert caught("X=rm; $X -rf /").severity is Severity.CRITICAL

    def test_env_var_full_payload_revealed(self) -> None:
        assert caught("CMD='DROP TABLE users;'; $CMD").severity is Severity.CRITICAL

    def test_env_var_echo_lookalike_stays_clean(self) -> None:
        assert caught("X=rm; echo $X -rf /") is None

    def test_env_var_non_printable_value_skipped(self) -> None:
        forms = expand("X='" + chr(0) + "'; $X -rf /")
        assert "\x00 -rf /" not in forms

    def test_zero_width_command_revealed(self) -> None:
        assert caught("r\u200bm -rf /").severity is Severity.CRITICAL

    def test_fullwidth_command_revealed(self) -> None:
        assert caught("ｒｍ -rf /").severity is Severity.CRITICAL

    def test_homoglyph_command_revealed(self) -> None:
        assert caught("rм -rf /").severity is Severity.CRITICAL

    def test_printed_homoglyph_lookalike_stays_clean(self) -> None:
        assert caught("echo r\u200bm -rf /") is None

    def test_brace_list_command_revealed(self) -> None:
        assert caught("{rm,-rf,/}").severity is Severity.CRITICAL

    def test_brace_embedded_command_revealed(self) -> None:
        assert caught("r{m,} -rf /").severity is Severity.CRITICAL

    def test_brace_split_flags_revealed(self) -> None:
        assert caught("rm -{r,f} /").severity is Severity.CRITICAL

    def test_printed_brace_lookalike_stays_clean(self) -> None:
        assert caught("echo {rm,-rf,/}") is None

    def test_safe_brace_glob_stays_clean(self) -> None:
        assert caught("touch file{1,2}.txt") is None

    def test_arithmetic_printf_xargs_reconstructs_command(self) -> None:
        command = (
            r"printf \"$(printf '\\%03o' $((0x72)))"
            r"$(printf '\\%03o' $((0x6d)))\" | xargs -I{} {} -rf /"
        )
        assert caught(command).severity is Severity.CRITICAL

    def test_arithmetic_printf_xargs_echo_stays_clean(self) -> None:
        command = (
            r"printf \"$(printf '\\%03o' $((0x72)))"
            r"$(printf '\\%03o' $((0x6d)))\" | xargs -I{} echo {} -rf /"
        )
        assert caught(command) is None

    def test_arithmetic_printf_xargs_local_cleanup_stays_clean(self) -> None:
        command = (
            r"printf \"$(printf '\\%03o' $((0x72)))"
            r"$(printf '\\%03o' $((0x6d)))\" | xargs -I{} {} -rf ./build"
        )
        assert caught(command) is None

    def test_arithmetic_expansion_reveals_supported_integer_ops(self) -> None:
        command = (
            "echo $((+1)) $((-2)) $((~0)) $((2+3)) $((5-2)) $((3*4)) "
            "$((5%2)) $((1<<3)) $((8>>1)) $((1|2)) $((3&1)) $((1^3))"
        )
        assert "echo 1 -2 -1 5 3 12 1 8 4 3 1 2" in expand(command)

    def test_invalid_arithmetic_expansions_stay_opaque(self) -> None:
        for command in (
            "echo $((1+))",
            "echo $((name))",
            "echo $((+name))",
            "echo $((name+1))",
            "echo $((5%0))",
        ):
            forms = expand(command)
            assert forms == [command]

    def test_out_of_bounds_arithmetic_expansion_stays_opaque(self) -> None:
        command = "echo $((1<<30))"
        assert expand(command) == [command]

    def test_malformed_brace_lists_stay_opaque(self) -> None:
        commands = (
            "{,}",
            "{1,2,3,4,5,6,7,8,9}",
            "{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,b}",
        )
        for command in commands:
            assert expand(command) == [command]

    def test_arithmetic_printf_xargs_out_of_byte_range_stays_clean(self) -> None:
        command = r"printf \"$(printf '\\%03o' $((0x100)))\" | xargs -I{} {} -rf /"
        assert caught(command) is None

    def test_arithmetic_printf_xargs_non_command_word_stays_clean(self) -> None:
        command = r"printf \"$(printf '\\%03o' $((0x20)))\" | xargs -I{} {} -rf /"
        assert caught(command) is None


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


class TestRustExpandParity:
    def test_rust_backend_status_is_boolean(self) -> None:
        assert isinstance(rust_backend_available(), bool)

    def test_public_expand_preserves_python_reference_forms(self) -> None:
        commands = (
            "rm -r -f /",
            "r''m -rf /",
            "echo cm0gLXJmIC8K | base64 -d | bash",
            r"\x72\x6d\x20\x2d\x72\x66\x20\x2f",
            r"printf '\162\155' | xargs -I{} {} -rf /",
            "X=rm; $X -rf /",
            "{rm,-rf,/}",
            "r\u200bm -rf /",
        )
        for command in commands:
            assert expand(command) == _expand_python(command)

    def test_loader_ignores_extension_without_callable_expand(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            normalize.importlib,
            "import_module",
            lambda _: SimpleNamespace(expand="not-callable"),
        )

        assert normalize._load_rust_expand() is None

    def test_loader_returns_none_when_extension_is_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def missing_extension(_name: str) -> object:
            raise ImportError("extension absent")

        monkeypatch.setattr(normalize.importlib, "import_module", missing_extension)

        assert normalize._load_rust_expand() is None

    def test_public_expand_uses_python_when_rust_loader_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(normalize, "_load_rust_expand", lambda: None)

        assert normalize.expand("rm -r -f /") == _expand_python("rm -r -f /")

    def test_public_expand_accepts_exact_rust_parity(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reference = _expand_python("rm -r -f /")

        monkeypatch.setattr(normalize, "_load_rust_expand", lambda: lambda *_: reference)

        assert normalize.expand("rm -r -f /") == reference

    def test_public_expand_falls_back_on_rust_exception(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken_expand(command: str, max_depth: int, max_forms: int) -> list[str]:
            raise RuntimeError("rust backend unavailable")

        monkeypatch.setattr(normalize, "_load_rust_expand", lambda: broken_expand)

        assert normalize.expand("rm -r -f /") == _expand_python("rm -r -f /")

    def test_public_expand_falls_back_on_rust_mismatch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(normalize, "_load_rust_expand", lambda: lambda *_: ["rm"])

        assert normalize.expand("rm -r -f /") == _expand_python("rm -r -f /")

    def test_installed_rust_backend_matches_reference_on_contract_cases(self) -> None:
        if not rust_backend_available():
            assert expand("rm -rf /") == _expand_python("rm -rf /")
            return

        from director_class_ai import _rust

        commands = (
            "rm -r -f /",
            "r''m -rf /",
            "echo cm0gLXJmIC8K | base64 -d | bash",
            r"\x72\x6d\x20\x2d\x72\x66\x20\x2f",
            r"\162\155",
            "X=rm; $X -rf /",
            "{rm,-rf,/}",
            "$((2+3))",
            "r\u200bm -rf /",
        )
        for command in commands:
            assert _rust.expand(command, 4, 64) == _expand_python(command)
