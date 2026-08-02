# SPDX-FileCopyrightText: 2026 Sean Whalen
# SPDX-License-Identifier: MIT
"""Tests for text recovery, CMap ordering, and output-path safety."""

from __future__ import annotations

from pathlib import Path
from types import ModuleType

import pytest

SECRET = "742 Evergreen Terrace"


def cmap(pairs: list[tuple[int, int]]) -> bytes:
    """Build a minimal ToUnicode CMap with the given code -> char pairs."""
    body = "\n".join(f"<{src:02X}> <{dst:04X}>" for src, dst in pairs)
    return f"""begincmap
{len(pairs)} beginbfchar
{body}
endbfchar
endcmap
""".encode("ascii")


class TestCMapOrdering:
    """The CMap's own order is evidence, so it must survive parsing."""

    def test_keeps_first_appearance_order(self, prc: ModuleType) -> None:
        data = cmap([(0x01, ord("z")), (0x02, ord("a")), (0x03, ord("m"))])
        assert prc.parse_tounicode(data) == ["z", "a", "m"]

    def test_order_is_not_sorted(self, prc: ModuleType) -> None:
        data = cmap([(0x01, ord("z")), (0x02, ord("a"))])
        parsed = prc.parse_tounicode(data)
        assert parsed != sorted(parsed)

    def test_repeats_collapse_to_first_position(self, prc: ModuleType) -> None:
        data = cmap([(0x01, ord("b")), (0x02, ord("a")), (0x03, ord("b"))])
        assert prc.parse_tounicode(data) == ["b", "a"]

    def test_dedupe_preserves_order(self, prc: ModuleType) -> None:
        assert prc.dedupe(["c", "a", "c", "b", "a"]) == ["c", "a", "b"]


class TestLooksLikeText:
    """The catch-all string sweep must not emit binary values."""

    @pytest.mark.parametrize(
        "value",
        [
            "742 Evergreen Terrace",
            "Jane Doe",
            "Café receipt",
        ],
    )
    def test_accepts_real_text(self, prc: ModuleType, value: str) -> None:
        assert prc._looks_like_text(value)

    @pytest.mark.parametrize(
        "value",
        [
            '„‚b—.�VRc"}…x',  # a PDF /ID value
            "dþFeSg1”M¥˜wùŁ",
            "",
            "  ",
            "ab",  # below the length floor
            "————",  # no alphanumerics
        ],
    )
    def test_rejects_binary_and_noise(self, prc: ModuleType, value: str) -> None:
        assert not prc._looks_like_text(value)


class TestHiddenSegments:
    """Hidden means 'absent from the visible page', per segment."""

    def test_content_stream_is_never_hidden(self, prc: ModuleType) -> None:
        extract = prc.Extract(prc.CONTENT_STREAM, "", "anything at all")
        assert prc.hidden_segments(extract, "") == []

    def test_font_orphans_are_always_hidden(self, prc: ModuleType) -> None:
        extract = prc.Extract(prc.FONT_CHARSET, "page 1", "742E", is_text=False)
        assert prc.hidden_segments(extract, prc.normalize("742E")) == ["742E"]

    def test_reports_only_the_hidden_lines(self, prc: ModuleType) -> None:
        extract = prc.Extract(prc.METADATA, "XMP", "on the page\nnot on the page")
        visible = prc.normalize("on the page")
        assert prc.hidden_segments(extract, visible) == ["not on the page"]

    def test_matching_is_accent_and_case_insensitive(self, prc: ModuleType) -> None:
        extract = prc.Extract(prc.METADATA, "XMP", "Café")
        assert prc.hidden_segments(extract, prc.normalize("the cafe menu")) == []


class TestOutputPathChecks:
    """Recovered text is the secret, so writing it must not clobber."""

    def test_accepts_a_new_file(self, prc: ModuleType, tmp_path: Path) -> None:
        pdf = tmp_path / "doc.pdf"
        pdf.write_bytes(b"%PDF-1.7\n")
        assert prc.check_output_path(tmp_path / "out.txt", pdf, False) is None

    def test_rejects_missing_directory(self, prc: ModuleType, tmp_path: Path) -> None:
        target = tmp_path / "nope" / "out.txt"
        problem = prc.check_output_path(target, tmp_path / "doc.pdf", False)
        assert problem is not None and "does not exist" in problem

    def test_rejects_existing_file_without_force(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        target = tmp_path / "out.txt"
        target.write_text("previous run")
        problem = prc.check_output_path(target, tmp_path / "doc.pdf", False)
        assert problem is not None and "already exists" in problem

    def test_allows_existing_file_with_force(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        target = tmp_path / "out.txt"
        target.write_text("previous run")
        assert prc.check_output_path(target, tmp_path / "doc.pdf", True) is None

    def test_refuses_the_pdf_under_inspection(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        pdf = tmp_path / "doc.pdf"
        pdf.write_bytes(b"%PDF-1.7\n")
        problem = prc.check_output_path(pdf, pdf, True)
        assert problem is not None and "under inspection" in problem

    def test_refuses_a_directory(self, prc: ModuleType, tmp_path: Path) -> None:
        problem = prc.check_output_path(tmp_path, tmp_path / "doc.pdf", True)
        assert problem is not None and "is a directory" in problem

    def test_written_file_is_owner_only(self, prc: ModuleType, tmp_path: Path) -> None:
        target = tmp_path / "out.txt"
        prc.write_output(target, "recovered\n")
        assert target.stat().st_mode & 0o777 == 0o600


class TestFixtures:
    """Each fixture must exercise the check it was built for."""

    def test_tagged_hides_the_secret_from_the_page(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        _, extracts = prc.analyze(fixtures / "tagged.pdf", [], want_extracts=True)
        visible = next(e.text for e in extracts if e.layer == prc.CONTENT_STREAM)
        assert SECRET not in visible

        hidden = prc.select_dump(extracts, visible, "hidden")
        recovered = [e.text for e in hidden if e.layer == prc.STRUCTURE_TREE]
        assert recovered == [SECRET]

    def test_clean_pdf_leaks_no_document_text(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        _, extracts = prc.analyze(fixtures / "clean.pdf", [], want_extracts=True)
        visible = next(e.text for e in extracts if e.layer == prc.CONTENT_STREAM)
        hidden = prc.select_dump(extracts, visible, "hidden")
        # DocInfo is genuinely off-page, so it is expected here; nothing
        # from the document body may appear.
        assert all(e.layer == prc.METADATA for e in hidden)

    def test_orphan_font_reports_cmap_order(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        report, _ = prc.analyze(fixtures / "orphan_font.pdf", [])
        findings = [f for f in report.findings if f.check == prc.FONT_CHARSET]
        assert len(findings) == 1
        # The characters of "742 Evergreen Terrace" that appear nowhere
        # else on the page, in the order the address first used them.
        # 'T' is absent from this list because the page caption mentions
        # ToUnicode, which puts a visible T back on the page.
        assert "'742Evg'" in findings[0].detail
        assert findings[0].severity is prc.Severity.CRITICAL

    def test_orphan_order_is_not_alphabetical(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """Sorting would destroy the evidence the CMap order carries."""
        report, _ = prc.analyze(fixtures / "orphan_font.pdf", [])
        finding = next(f for f in report.findings if f.check == prc.FONT_CHARSET)
        assert "'247Egv'" not in finding.detail

    def test_orphan_font_check_needs_the_stale_cmap(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The fixture must fail without the thing it is testing."""
        report, _ = prc.analyze(fixtures / "clean.pdf", [])
        assert not [f for f in report.findings if f.check == prc.FONT_CHARSET]

    def test_unapplied_redact_annotation_is_critical(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        report, _ = prc.analyze(fixtures / "unapplied.pdf", [])
        details = [f.detail for f in report.findings]
        assert any("unapplied /Redact" in d for d in details)

    def test_secret_search_still_finds_covered_text(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        report, _ = prc.analyze(fixtures / "fake_redacted.pdf", [SECRET])
        layers = {f.check for f in report.findings}
        assert prc.CONTENT_STREAM in layers
        assert report.worst is prc.Severity.CRITICAL

    def test_docinfo_is_reported_without_secrets_or_dump(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        report, _ = prc.analyze(fixtures / "clean.pdf", [])
        assert any(f.detail.startswith("DocInfo") for f in report.findings)
