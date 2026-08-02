# SPDX-FileCopyrightText: 2026 Sean Whalen
# SPDX-License-Identifier: MIT
"""Tests for the command line: exit codes, dump output, and file writing."""

from __future__ import annotations

import json
from pathlib import Path
from types import ModuleType

import pytest

SECRET = "742 Evergreen Terrace"


class TestExitCodes:
    """The exit-code contract is public API and must not drift."""

    @pytest.mark.parametrize(
        ("sample", "expected"),
        [
            ("clean.pdf", 0),
            ("tagged.pdf", 0),
            ("attachments.pdf", 1),
            ("unapplied.pdf", 2),
            ("orphan_font.pdf", 2),
        ],
    )
    def test_structural_run(
        self, prc: ModuleType, fixtures: Path, sample: str, expected: int
    ) -> None:
        assert prc.main([str(fixtures / sample)]) == expected

    @pytest.mark.parametrize(
        "sample",
        [
            "fake_redacted.pdf",
            "tagged.pdf",
            "annotated.pdf",
            "xmp.pdf",
            "unapplied.pdf",
            # Not a text layer, but the run must still complete: the
            # font charset is skipped by the secret search.
            "orphan_font.pdf",
        ],
    )
    def test_secret_is_found_in_every_layer(
        self, prc: ModuleType, fixtures: Path, sample: str
    ) -> None:
        assert prc.main([str(fixtures / sample), "-s", SECRET]) == 2

    def test_missing_file(self, prc: ModuleType, tmp_path: Path, capsys) -> None:
        assert prc.main([str(tmp_path / "nope.pdf")]) == 3
        assert "no such file" in capsys.readouterr().err

    def test_unreadable_file(self, prc: ModuleType, tmp_path: Path, capsys) -> None:
        broken = tmp_path / "broken.pdf"
        broken.write_bytes(b"not a pdf at all")
        assert prc.main([str(broken)]) == 3
        assert "could not read" in capsys.readouterr().err


class TestSecretSources:
    """Secrets arrive on the command line or from a file."""

    def test_secret_file(self, prc: ModuleType, fixtures: Path, tmp_path: Path) -> None:
        listing = tmp_path / "secrets.txt"
        listing.write_text(f"\n{SECRET}\n\n", encoding="utf-8")
        code = prc.main(
            [str(fixtures / "fake_redacted.pdf"), "--secret-file", str(listing)]
        )
        assert code == 2

    def test_blank_lines_are_not_treated_as_secrets(
        self, prc: ModuleType, fixtures: Path, tmp_path: Path
    ) -> None:
        listing = tmp_path / "secrets.txt"
        listing.write_text("\n   \n", encoding="utf-8")
        assert (
            prc.main([str(fixtures / "clean.pdf"), "--secret-file", str(listing)]) == 0
        )


class TestDumpOutput:
    """Recovered text reaches stdout, JSON, or a file."""

    def test_hidden_dump_reports_the_tag_tree(
        self, prc: ModuleType, fixtures: Path, capsys
    ) -> None:
        prc.main([str(fixtures / "tagged.pdf"), "--dump-hidden"])
        out = capsys.readouterr().out
        assert "hidden text recovered" in out
        assert SECRET in out

    def test_hidden_dump_omits_visible_text(
        self, prc: ModuleType, fixtures: Path, capsys
    ) -> None:
        prc.main([str(fixtures / "fake_redacted.pdf"), "--dump-hidden"])
        out = capsys.readouterr().out.split("hidden text recovered")[1]
        assert "Dear Sir or Madam" not in out

    def test_dump_all_includes_visible_text(
        self, prc: ModuleType, fixtures: Path, capsys
    ) -> None:
        prc.main([str(fixtures / "fake_redacted.pdf"), "--dump-all"])
        out = capsys.readouterr().out.split("recoverable text")[1]
        assert "Dear Sir or Madam" in out

    def test_attachment_names_are_listed(
        self, prc: ModuleType, fixtures: Path, capsys
    ) -> None:
        prc.main([str(fixtures / "attachments.pdf"), "--dump-hidden"])
        out = capsys.readouterr().out
        assert "original_address.txt" in out
        assert "bytes)" in out

    def test_annotation_text_is_recovered(
        self, prc: ModuleType, fixtures: Path, capsys
    ) -> None:
        prc.main([str(fixtures / "annotated.pdf"), "--dump-hidden"])
        out = capsys.readouterr().out
        assert "reviewer note" in out
        assert SECRET in out

    def test_xmp_is_recovered(self, prc: ModuleType, fixtures: Path, capsys) -> None:
        prc.main([str(fixtures / "xmp.pdf"), "--dump-hidden"])
        assert SECRET in capsys.readouterr().out

    def test_font_orphans_are_labelled_as_characters(
        self, prc: ModuleType, fixtures: Path, capsys
    ) -> None:
        prc.main([str(fixtures / "orphan_font.pdf"), "--dump-hidden"])
        out = capsys.readouterr().out
        assert "characters, not text" in out

    def test_nothing_recovered_says_so(self, prc: ModuleType) -> None:
        rendered = prc.render_dump(Path("x.pdf"), "hidden", [])
        assert "(nothing recovered)" in rendered

    def test_json_carries_the_dump(
        self, prc: ModuleType, fixtures: Path, capsys
    ) -> None:
        prc.main([str(fixtures / "tagged.pdf"), "--dump-all", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["dump"]["mode"] == "all"
        layers = {e["layer"]: e for e in payload["dump"]["extracts"]}
        assert layers[prc.STRUCTURE_TREE]["hidden"] is True
        assert layers[prc.CONTENT_STREAM]["hidden"] is False

    def test_json_without_dump_has_no_dump_key(
        self, prc: ModuleType, fixtures: Path, capsys
    ) -> None:
        prc.main([str(fixtures / "clean.pdf"), "--json"])
        assert "dump" not in json.loads(capsys.readouterr().out)


class TestOutputFile:
    """Writing recovered text to disk is guarded."""

    def test_writes_text_and_reports_to_stderr(
        self, prc: ModuleType, fixtures: Path, tmp_path: Path, capsys
    ) -> None:
        target = tmp_path / "recovered.txt"
        prc.main([str(fixtures / "tagged.pdf"), "--dump-hidden", "-o", str(target)])
        captured = capsys.readouterr()
        assert SECRET in target.read_text(encoding="utf-8")
        assert "wrote" in captured.err
        # The recovered text must not also land on stdout.
        assert SECRET not in captured.out

    def test_writes_json_when_asked(
        self, prc: ModuleType, fixtures: Path, tmp_path: Path
    ) -> None:
        target = tmp_path / "recovered.json"
        prc.main(
            [str(fixtures / "tagged.pdf"), "--dump-all", "--json", "-o", str(target)]
        )
        payload = json.loads(target.read_text(encoding="utf-8"))
        assert payload["mode"] == "all"

    def test_rejects_unwritable_target(
        self, prc: ModuleType, fixtures: Path, tmp_path: Path, capsys
    ) -> None:
        target = tmp_path / "missing" / "out.txt"
        code = prc.main(
            [str(fixtures / "tagged.pdf"), "--dump-hidden", "-o", str(target)]
        )
        assert code == 3
        assert "does not exist" in capsys.readouterr().err

    def test_reports_a_write_failure(
        self, prc: ModuleType, fixtures: Path, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        def explode(path: Path, text: str) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(prc, "write_output", explode)
        code = prc.main(
            [
                str(fixtures / "tagged.pdf"),
                "--dump-hidden",
                "-o",
                str(tmp_path / "out.txt"),
            ]
        )
        assert code == 3
        assert "could not write" in capsys.readouterr().err

    def test_output_requires_a_dump_mode(
        self, prc: ModuleType, fixtures: Path, tmp_path: Path
    ) -> None:
        with pytest.raises(SystemExit) as exit_info:
            prc.main([str(fixtures / "clean.pdf"), "-o", str(tmp_path / "out.txt")])
        assert exit_info.value.code == 2

    def test_force_requires_output(self, prc: ModuleType, fixtures: Path) -> None:
        with pytest.raises(SystemExit) as exit_info:
            prc.main([str(fixtures / "clean.pdf"), "--dump-hidden", "--force"])
        assert exit_info.value.code == 2

    def test_dump_modes_are_mutually_exclusive(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        with pytest.raises(SystemExit) as exit_info:
            prc.main([str(fixtures / "clean.pdf"), "--dump-hidden", "--dump-all"])
        assert exit_info.value.code == 2


class TestTextReport:
    """The human-readable verdict line matches the exit code."""

    @pytest.mark.parametrize(
        ("sample", "phrase"),
        [
            ("clean.pdf", "no evidence of surviving content"),
            ("attachments.pdf", "SUSPICIOUS"),
            ("unapplied.pdf", "FAILED"),
        ],
    )
    def test_verdict(
        self, prc: ModuleType, fixtures: Path, capsys, sample: str, phrase: str
    ) -> None:
        prc.main([str(fixtures / sample)])
        assert phrase in capsys.readouterr().out


class TestRunWrapper:
    """The console-script wrapper survives a closed pipe."""

    def test_returns_main_result(self, prc: ModuleType, monkeypatch) -> None:
        monkeypatch.setattr(prc, "main", lambda: 2)
        assert prc.run() == 2

    def test_broken_pipe_exits_zero(self, prc: ModuleType, monkeypatch) -> None:
        import io

        def explode() -> int:
            raise BrokenPipeError

        monkeypatch.setattr(prc, "main", explode)
        monkeypatch.setattr(prc.sys, "stderr", io.StringIO())
        assert prc.run() == 0
