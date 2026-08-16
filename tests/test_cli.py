# SPDX-FileCopyrightText: 2026 Sean Whalen
# SPDX-License-Identifier: MIT
"""Tests for the command line: exit codes, dump output, and file writing."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
from conftest import ROOT

SECRET = "742 Evergreen Terrace"

SCRIPT = ROOT / "pdf-redaction-check.py"

# A committed sample for every layer the secret search covers, named by
# the module constant that layer lives in. `test_every_searchable_layer_
# has_a_sample` keeps this list honest against the tool's own set.
SECRET_LAYER_SAMPLES = [
    ("fake_redacted.pdf", "CONTENT_STREAM"),
    # The page text of these two is only legible through the font's own
    # tables, so finding the address proves the decoding as well as the
    # search.
    ("differences.pdf", "CONTENT_STREAM"),
    ("identity_h.pdf", "CONTENT_STREAM"),
    ("tagged.pdf", "STRUCTURE_TREE"),
    ("annotated.pdf", "ANNOTATIONS"),
    ("unapplied.pdf", "ANNOTATIONS"),
    ("xmp.pdf", "METADATA"),
    ("attachments.pdf", "ATTACHMENTS"),
    ("outline.pdf", "RAW_STRINGS"),
]


class TestExitCodes:
    """The exit-code contract is public API and must not drift."""

    @pytest.mark.parametrize(
        ("sample", "expected"),
        [
            ("clean.pdf", 0),
            ("tagged.pdf", 0),
            ("smart_quotes.pdf", 0),
            # A form that gives the page's own font name to a font of
            # its own. Every character both fonts declare is drawn, so a
            # reading that keeps the two apart has nothing to report.
            ("rebound_font.pdf", 0),
            # A JPEG cannot be decoded here, and must not be reported as
            # a layer that could not be read -- every scan has one.
            ("image_stream.pdf", 0),
            # The same JPEG spelled in printable characters, which is
            # what a Distiller-lineage producer writes.
            ("armored_image.pdf", 0),
            ("attachments.pdf", 1),
            # A stream that says it is a picture and holds compressed
            # text: bytes nobody could read, and not a picture.
            ("lying_image.pdf", 1),
            # Text drawn inside a Form XObject is text on the page. The
            # warning here is the one font that really does declare a
            # character nothing draws.
            ("form_xobject.pdf", 1),
            # Fonts this cannot read all the way, and one orphan.
            ("broken_fonts.pdf", 1),
            # Drawing instructions that are not a content stream, which
            # a parser hands back as no instructions at all.
            ("broken_contents.pdf", 1),
            # Structures nested deeper than any walk here follows. The
            # address is in the file and out of reach, so the run must
            # report what it could not read rather than nothing at all.
            ("deep_nesting.pdf", 1),
            # A stream that will not decompress: a layer of this
            # document nothing here could read, on a run given no
            # secret to look for.
            ("cleartext_stream.pdf", 1),
            ("unapplied.pdf", 2),
            ("orphan_font.pdf", 2),
            # The font a q saved and a Q put back: the leftovers the
            # page really carries, once its text is read through the
            # font a reader would have in effect.
            ("saved_state.pdf", 2),
        ],
    )
    def test_structural_run(
        self, prc: ModuleType, fixtures: Path, sample: str, expected: int
    ) -> None:
        assert prc.main([str(fixtures / sample)]) == expected

    @pytest.mark.parametrize(("sample", "layer"), SECRET_LAYER_SAMPLES)
    def test_secret_is_found_in_every_layer(
        self, prc: ModuleType, fixtures: Path, sample: str, layer: str
    ) -> None:
        """Every layer the secret search covers has a sample that proves it.

        The exit code alone would not: most of these documents carry the
        address in the raw object sweep as well, so a layer that stopped
        being searched would still come back as a failure.
        """
        report, _ = prc.analyze(fixtures / sample, [SECRET])
        reported = {
            finding.check
            for finding in report.findings
            if finding.severity is prc.Severity.CRITICAL
            and repr(SECRET) in finding.detail
        }
        assert getattr(prc, layer) in reported
        assert prc.main([str(fixtures / sample), "-s", SECRET]) == prc.EXIT_RECOVERABLE

    def test_every_searchable_layer_has_a_sample(self, prc: ModuleType) -> None:
        """The list above is an enumeration, so derive the set it claims.

        A layer added to the secret search with no sample behind it is an
        assertion about PDFs that nobody has tested.
        """
        covered = {getattr(prc, name) for _sample, name in SECRET_LAYER_SAMPLES}
        assert covered == set(prc.SECRET_DETAIL)

    def test_the_font_layer_is_never_searched_for_a_secret(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The font charset is characters, not wording.

        A secret whose letters all appear in a font subset has not been
        found there, so the search must not claim it has -- while the
        font check itself still reports the orphans on its own terms.
        """
        report, _ = prc.analyze(fixtures / "orphan_font.pdf", [SECRET])
        font_findings = [f for f in report.findings if f.check == prc.FONT_CHARSET]
        assert font_findings, "the fixture must still trigger the font check"
        assert not [f for f in font_findings if repr(SECRET) in f.detail]

    def test_missing_file(
        self, prc: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert prc.main([str(tmp_path / "nope.pdf")]) == 3
        assert "no such file" in capsys.readouterr().err

    def test_unreadable_file(
        self, prc: ModuleType, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
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

    @pytest.mark.parametrize("blank", ["", " ", "\t", "\n", "   \t "])
    def test_a_blank_secret_is_a_usage_error(
        self,
        prc: ModuleType,
        fixtures: Path,
        blank: str,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A blank secret is in every document, so it convicts every one.

        The shape this arrives in is a CI gate running `--secret
        "$NAME"` with the variable unset. Matching it would report a
        clean document as a failed redaction; dropping it silently would
        report an unchecked document as a clean one. Neither is an
        answer, so the invocation is refused.
        """
        code = prc.main([str(fixtures / "clean.pdf"), "--secret", blank])
        assert code == prc.EXIT_USAGE
        assert "--secret" in capsys.readouterr().err

    def test_a_blank_secret_is_refused_beside_a_real_one(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """One good secret does not make the blank one harmless: it would
        still match, and every document would still fail."""
        code = prc.main([str(fixtures / "fake_redacted.pdf"), "-s", SECRET, "-s", ""])
        assert code == prc.EXIT_USAGE

    def test_a_blank_secret_is_refused_for_a_library_caller_too(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The command line is not the only way in.

        `analyze` is what anything embedding this calls, and text with
        nothing in it matches every document there exactly as it would
        from a terminal, so the guard belongs to the function rather
        than to the argument parsing in front of it.
        """
        with pytest.raises(prc.UsageError, match="nothing in it"):
            prc.analyze(fixtures / "clean.pdf", [""])

    def test_a_secret_of_ordinary_text_is_not_refused(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The negative half: only a secret with nothing in it is."""
        assert prc.main([str(fixtures / "clean.pdf"), "-s", SECRET]) == 0

    def test_missing_secret_file_is_a_usage_error(
        self,
        prc: ModuleType,
        fixtures: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A bad invocation must never be mistaken for a failed redaction."""
        code = prc.main(
            [str(fixtures / "clean.pdf"), "--secret-file", str(tmp_path / "nope.txt")]
        )
        assert code == prc.EXIT_USAGE
        assert "could not read" in capsys.readouterr().err

    def test_a_secret_file_that_is_not_text_is_a_usage_error(
        self,
        prc: ModuleType,
        fixtures: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        listing = tmp_path / "secrets.bin"
        listing.write_bytes(b"\xff\xfe\x00\x80not text")
        code = prc.main([str(fixtures / "clean.pdf"), "--secret-file", str(listing)])
        assert code == prc.EXIT_USAGE
        assert "not UTF-8 text" in capsys.readouterr().err


class TestDumpOutput:
    """Recovered text reaches stdout, JSON, or a file."""

    def test_hidden_dump_reports_the_tag_tree(
        self, prc: ModuleType, fixtures: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        prc.main([str(fixtures / "tagged.pdf"), "--dump-hidden"])
        out = capsys.readouterr().out
        assert "hidden text recovered" in out
        assert SECRET in out

    def test_hidden_dump_omits_visible_text(
        self, prc: ModuleType, fixtures: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        prc.main([str(fixtures / "fake_redacted.pdf"), "--dump-hidden"])
        out = capsys.readouterr().out.split("hidden text recovered")[1]
        assert "Dear Sir or Madam" not in out

    def test_dump_all_includes_visible_text(
        self, prc: ModuleType, fixtures: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        prc.main([str(fixtures / "fake_redacted.pdf"), "--dump-all"])
        out = capsys.readouterr().out.split("recoverable text")[1]
        assert "Dear Sir or Madam" in out

    def test_attachment_names_are_listed(
        self, prc: ModuleType, fixtures: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        prc.main([str(fixtures / "attachments.pdf"), "--dump-hidden"])
        out = capsys.readouterr().out
        assert "original_address.txt" in out
        assert "bytes)" in out

    def test_annotation_text_is_recovered(
        self, prc: ModuleType, fixtures: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        prc.main([str(fixtures / "annotated.pdf"), "--dump-hidden"])
        out = capsys.readouterr().out
        assert "reviewer note" in out
        assert SECRET in out

    def test_xmp_is_recovered(
        self, prc: ModuleType, fixtures: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        prc.main([str(fixtures / "xmp.pdf"), "--dump-hidden"])
        assert SECRET in capsys.readouterr().out

    def test_font_orphans_are_labelled_as_characters(
        self, prc: ModuleType, fixtures: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        prc.main([str(fixtures / "orphan_font.pdf"), "--dump-hidden"])
        out = capsys.readouterr().out
        assert "characters, not text" in out

    def test_nothing_recovered_says_so(self, prc: ModuleType) -> None:
        rendered = prc.render_dump(Path("x.pdf"), "hidden", [])
        assert "(nothing recovered)" in rendered

    def test_json_carries_the_dump(
        self, prc: ModuleType, fixtures: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        prc.main([str(fixtures / "tagged.pdf"), "--dump-all", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["dump"]["mode"] == "all"
        layers = {e["layer"]: e for e in payload["dump"]["extracts"]}
        assert layers[prc.STRUCTURE_TREE]["hidden"] is True
        assert layers[prc.CONTENT_STREAM]["hidden"] is False

    def test_json_without_dump_has_no_dump_key(
        self, prc: ModuleType, fixtures: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        prc.main([str(fixtures / "clean.pdf"), "--json"])
        assert "dump" not in json.loads(capsys.readouterr().out)


class TestJSONFindings:
    """The findings list is public output, not a byproduct of the exit code."""

    def test_each_finding_is_serialized_with_its_own_severity(
        self, prc: ModuleType, fixtures: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        prc.main([str(fixtures / "unapplied.pdf"), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["file"].endswith("unapplied.pdf")
        by_severity = {f["severity"] for f in payload["findings"]}
        # Both halves: the alarming finding must not be flattened to
        # INFO, and the informational ones must not be raised to it.
        assert by_severity == {"CRITICAL", "INFO"}
        assert {
            "severity": "CRITICAL",
            "check": prc.ANNOTATIONS,
            "detail": ("unapplied /Redact annotation -- marks were saved, not applied"),
            "location": "page 1",
        } in payload["findings"]

    def test_worst_severity_is_the_highest_one_present(
        self, prc: ModuleType, fixtures: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        prc.main([str(fixtures / "unapplied.pdf"), "--json"])
        assert json.loads(capsys.readouterr().out)["worst_severity"] == "CRITICAL"

    def test_worst_severity_reports_a_warning_as_a_warning(
        self, prc: ModuleType, fixtures: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        prc.main([str(fixtures / "broken_fonts.pdf"), "--json"])
        assert json.loads(capsys.readouterr().out)["worst_severity"] == "WARNING"

    def test_a_report_with_no_findings_has_a_null_worst_severity(
        self, prc: ModuleType
    ) -> None:
        payload = prc.Report(path=Path("x.pdf")).to_dict()
        assert payload["worst_severity"] is None
        assert payload["findings"] == []


class TestOutputFile:
    """Writing recovered text to disk is guarded."""

    def test_writes_text_and_reports_to_stderr(
        self,
        prc: ModuleType,
        fixtures: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
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
        self,
        prc: ModuleType,
        fixtures: Path,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        target = tmp_path / "missing" / "out.txt"
        code = prc.main(
            [str(fixtures / "tagged.pdf"), "--dump-hidden", "-o", str(target)]
        )
        assert code == 3
        assert "does not exist" in capsys.readouterr().err

    def test_reports_a_write_failure(
        self,
        prc: ModuleType,
        fixtures: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
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
        assert exit_info.value.code == prc.EXIT_USAGE

    def test_force_requires_output(self, prc: ModuleType, fixtures: Path) -> None:
        with pytest.raises(SystemExit) as exit_info:
            prc.main([str(fixtures / "clean.pdf"), "--dump-hidden", "--force"])
        assert exit_info.value.code == prc.EXIT_USAGE

    def test_dump_modes_are_mutually_exclusive(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        with pytest.raises(SystemExit) as exit_info:
            prc.main([str(fixtures / "clean.pdf"), "--dump-hidden", "--dump-all"])
        assert exit_info.value.code == prc.EXIT_USAGE

    def test_a_usage_error_is_not_the_recoverable_content_code(
        self, prc: ModuleType
    ) -> None:
        """The point of the usage code is that it is not code 2.

        Code 2 means redacted content is recoverable, which is the worst
        verdict this tool has. A mistyped option must never produce it.
        """
        assert prc.EXIT_USAGE != prc.EXIT_RECOVERABLE
        with pytest.raises(SystemExit) as exit_info:
            prc.main(["--no-such-option"])
        assert exit_info.value.code == prc.EXIT_USAGE


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
        self,
        prc: ModuleType,
        fixtures: Path,
        capsys: pytest.CaptureFixture[str],
        sample: str,
        phrase: str,
    ) -> None:
        prc.main([str(fixtures / sample)])
        assert phrase in capsys.readouterr().out


class TestBrokenPipe:
    """A reader that hangs up must not cost the caller the verdict."""

    def test_returns_main_result(
        self, prc: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(prc, "main", lambda: 2)
        assert prc.run() == 2

    def test_a_failed_document_still_reports_failure(
        self, prc: ModuleType, fixtures: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The verdict is known before anything is printed.

        Losing the reader loses the output, not the answer -- a hook
        that pipes this into `head` still has to learn that redacted
        content is recoverable.
        """

        def explode(*args: object, **kwargs: object) -> None:
            raise BrokenPipeError

        monkeypatch.setattr(prc, "print_report", explode)
        assert prc.main([str(fixtures / "unapplied.pdf")]) == prc.EXIT_RECOVERABLE

    @pytest.mark.parametrize("failure", [BrokenPipeError, ValueError])
    def test_an_unusable_error_stream_does_not_cost_the_verdict_either(
        self,
        prc: ModuleType,
        fixtures: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        failure: type[Exception],
    ) -> None:
        """Standard error is where the diagnostics go, not the verdict.

        `-o` reports what it wrote on standard error, after the file has
        been written. A stream that cannot take that message costs the
        message, not the answer -- and not the file either. Both ways it
        refuses are covered: a reader that hung up raises
        BrokenPipeError, and a stream someone closed raises ValueError,
        which is not an OSError at all.
        """

        class Unusable(io.StringIO):
            def write(self, text: str) -> int:
                raise failure("no")

        monkeypatch.setattr(prc.sys, "stderr", Unusable())
        target = tmp_path / "recovered.txt"
        code = prc.main(
            [str(fixtures / "unapplied.pdf"), "--dump-all", "-o", str(target)]
        )
        assert code == prc.EXIT_RECOVERABLE
        assert SECRET in target.read_text(encoding="utf-8")

    def test_no_error_stream_at_all_leaves_the_report_alone(
        self,
        prc: ModuleType,
        fixtures: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A process started with that file descriptor closed has none.

        `sys.stderr` is None there, and `print(..., file=None)` writes to
        standard output -- which would drop a diagnostic into the middle
        of the report the caller is parsing.
        """
        monkeypatch.setattr(prc.sys, "stderr", None)
        assert prc.main([str(fixtures / "nope.pdf")]) == prc.EXIT_INCOMPLETE
        assert capsys.readouterr().out == ""

    def test_a_pipe_broken_before_the_report_cannot_report(
        self, prc: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Reaching the wrapper's guard means no verdict was reached."""

        def explode() -> int:
            raise BrokenPipeError

        monkeypatch.setattr(prc, "main", explode)
        assert prc.run() == prc.EXIT_INCOMPLETE

    def test_a_closed_reader_does_not_replace_the_exit_code(
        self, fixtures: Path
    ) -> None:
        """End to end, in a real process, with a pipe nobody is reading.

        Left unhandled, the interpreter retries the undelivered output
        while shutting down, fails the same way, complains on standard
        error, and exits 120 instead of the verdict.

        The child is run the way a shell runs it, with the block
        buffering Python uses for a pipe: a report this short never
        reaches the pipe on its own, so the tool has to push it out
        while it is still the one holding the verdict. Forcing the
        child's output unbuffered would hide that entirely.
        """
        env = dict(os.environ)
        env.pop("PYTHONUNBUFFERED", None)
        read_end, write_end = os.pipe()
        os.close(read_end)
        try:
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), str(fixtures / "unapplied.pdf")],
                stdout=write_end,
                stderr=subprocess.PIPE,
                env=env,
                check=False,
            )
        finally:
            os.close(write_end)
        assert completed.returncode == 2
        assert completed.stderr == b""


class TestDiscardStdout:
    """Dropping standard output is deliberate, and narrowly scoped."""

    def test_a_substituted_stdout_is_left_alone(
        self, prc: ModuleType, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Redirecting a file descriptor is not undoable.

        Something else owns standard output here -- pytest's capture --
        so this must leave it exactly as it found it.
        """
        prc.discard_stdout()
        print("still delivered")
        assert "still delivered" in capsys.readouterr().out

    def test_a_stdout_with_no_file_descriptor_is_left_alone(
        self, prc: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        buffer = io.StringIO()
        monkeypatch.setattr(prc.sys, "stdout", buffer)
        monkeypatch.setattr(prc.sys, "__stdout__", buffer)
        prc.discard_stdout()
        buffer.write("still delivered")
        assert buffer.getvalue() == "still delivered"

    def test_the_real_stdout_is_pointed_at_the_null_device(
        self, prc: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Everything written afterwards goes nowhere, and nothing raises."""
        target = tmp_path / "stdout.txt"
        with target.open("w", encoding="utf-8") as handle:
            monkeypatch.setattr(prc.sys, "stdout", handle)
            monkeypatch.setattr(prc.sys, "__stdout__", handle)
            prc.discard_stdout()
            handle.write("this could never be delivered")
        assert target.read_text(encoding="utf-8") == ""
