# SPDX-FileCopyrightText: 2026 Sean Whalen
# SPDX-License-Identifier: MIT
"""Tests for the paths a malformed or hostile document takes.

Broken files are the normal case for this tool, so every parser has to
degrade to "could not read this layer" instead of raising. These build
their inputs in memory rather than in `tests/samples`, because they are
deliberately invalid structures, not documents anyone could produce.
"""

from __future__ import annotations

import os
import zlib
from pathlib import Path
from types import ModuleType

import pikepdf
import pytest


class TestReportModel:
    """Severity ranking, including the empty case."""

    def test_no_findings_has_no_worst(self, prc: ModuleType) -> None:
        assert prc.Report(path=Path("x.pdf")).worst is None

    def test_warning_outranks_info(self, prc: ModuleType) -> None:
        report = prc.Report(path=Path("x.pdf"))
        report.add(prc.Severity.INFO, "a", "detail")
        report.add(prc.Severity.WARNING, "b", "detail")
        assert report.worst is prc.Severity.WARNING

    def test_finding_renders_without_a_location(self, prc: ModuleType) -> None:
        finding = prc.Finding(prc.Severity.INFO, "check", "detail")
        assert "[" not in finding.render()

    def test_finding_renders_with_a_location(self, prc: ModuleType) -> None:
        finding = prc.Finding(prc.Severity.INFO, "check", "detail", "page 1")
        assert "[page 1]" in finding.render()


class TestBrokenPages:
    """A page whose content stream cannot be parsed is skipped."""

    def test_unparsable_content_stream(self, prc: ModuleType, tmp_path: Path) -> None:
        path = tmp_path / "broken_stream.pdf"
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            page.Contents = pdf.make_stream(b"this is not a content stream (((")
            pdf.save(path)
        with pikepdf.open(path) as pdf:
            # The page is skipped rather than raising.
            assert prc.extract_page_text(pdf) == ""

    def test_page_without_resources(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            assert prc.extract_page_text(pdf) == ""

    def test_a_raising_page_is_skipped(self, prc: ModuleType, monkeypatch) -> None:
        def explode(page):
            raise pikepdf.PdfError("bad page")

        monkeypatch.setattr(prc, "_page_text", explode)
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            assert prc.extract_page_text(pdf) == ""

    def test_text_shown_as_an_array(self, prc: ModuleType, tmp_path: Path) -> None:
        """TJ takes an array of strings and kerning numbers."""
        path = tmp_path / "kerned.pdf"
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            page.Resources = pikepdf.Dictionary(
                Font=pikepdf.Dictionary(
                    F1=pdf.make_indirect(
                        pikepdf.Dictionary(
                            Type=pikepdf.Name("/Font"),
                            Subtype=pikepdf.Name("/Type1"),
                            BaseFont=pikepdf.Name("/Helvetica"),
                        )
                    )
                )
            )
            # The quote operator takes two numbers before its string;
            # those operands are neither strings nor arrays.
            page.Contents = pdf.make_stream(
                b'BT /F1 12 Tf 72 720 Td [(Ever) -20 (green)] TJ 1 2 ( Terrace) " ET'
            )
            pdf.save(path)
        with pikepdf.open(path) as pdf:
            assert prc.extract_page_text(pdf) == "Evergreen Terrace"


class TestStructureTree:
    """Tag-tree traversal survives loops, depth, and junk nodes."""

    def test_absent_tree_yields_nothing(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            assert prc.extract_structure_tree(pdf) == []

    def test_empty_tree_yields_nothing(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            pdf.Root["/StructTreeRoot"] = pdf.make_indirect(
                pikepdf.Dictionary(Type=pikepdf.Name("/StructTreeRoot"))
            )
            assert prc.extract_structure_tree(pdf) == []

    def test_a_cycle_terminates(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            node = pdf.make_indirect(
                pikepdf.Dictionary(
                    Type=pikepdf.Name("/StructElem"),
                    ActualText=pikepdf.String("looped"),
                )
            )
            node["/K"] = node  # points at itself
            assert list(prc.walk_struct(node, set())) == ["looped"]

    def test_non_dictionary_nodes_are_ignored(self, prc: ModuleType) -> None:
        assert list(prc.walk_struct(pikepdf.Name("/NotADict"), set())) == []

    def test_depth_limit_stops_traversal(self, prc: ModuleType) -> None:
        node = pikepdf.Dictionary(ActualText=pikepdf.String("deep"))
        assert list(prc.walk_struct(node, set(), depth=65)) == []

    def test_kid_arrays_are_walked(self, prc: ModuleType) -> None:
        node = pikepdf.Dictionary(
            K=[
                pikepdf.Dictionary(ActualText=pikepdf.String("first")),
                pikepdf.Dictionary(Alt=pikepdf.String("second")),
            ]
        )
        assert list(prc.walk_struct(node, set())) == ["first", "second"]

    def test_direct_objects_are_not_memoised(self, prc: ModuleType) -> None:
        """Only indirect objects can form a loop, so only they are recorded."""
        assert prc.already_seen(pikepdf.String("direct"), set()) is False


class TestAnnotationEdges:
    """Annotation arrays can hold things that are not annotations."""

    def test_non_dictionary_annotation_is_skipped(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        path = tmp_path / "junk_annot.pdf"
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            page["/Annots"] = pdf.make_indirect(
                pikepdf.Array([pikepdf.Name("/NotAnAnnotation")])
            )
            pdf.save(path)
        with pikepdf.open(path) as pdf:
            report = prc.Report(path=path)
            prc.check_redact_annotations(pdf, report)
            assert prc.extract_annotations(pdf) == []
            assert report.findings == []

    def test_annotation_without_text_is_skipped(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            page["/Annots"] = pdf.make_indirect(
                pikepdf.Array([pikepdf.Dictionary(Subtype=pikepdf.Name("/Square"))])
            )
            assert prc.extract_annotations(pdf) == []


class TestAttachmentEdges:
    """Name-tree walking tolerates every shape it can meet."""

    def test_tree_that_is_not_a_dictionary(self, prc: ModuleType) -> None:
        assert list(prc._iter_embedded_files(pikepdf.Name("/Nope"))) == []

    def test_tree_without_names_array(self, prc: ModuleType) -> None:
        assert list(prc._iter_embedded_files(pikepdf.Dictionary())) == []

    def test_kids_are_followed(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            leaf = pikepdf.Dictionary(
                Names=[pikepdf.String("nested.txt"), pikepdf.Dictionary()]
            )
            tree = pikepdf.Dictionary(Kids=[leaf])
            names = [label for label, _ in prc._iter_embedded_files(tree)]
            assert names == ["nested.txt"]
            assert pdf is not None

    def test_unnamed_entry_is_labelled(self, prc: ModuleType) -> None:
        tree = pikepdf.Dictionary(
            Names=[pikepdf.Name("/NotAString"), pikepdf.Dictionary()]
        )
        assert [label for label, _ in prc._iter_embedded_files(tree)] == ["(unnamed)"]

    def test_entry_whose_spec_is_not_a_dictionary(self, prc: ModuleType) -> None:
        tree = pikepdf.Dictionary(
            Names=[pikepdf.String("odd.txt"), pikepdf.Name("/NotASpec")]
        )
        assert list(prc._iter_embedded_files(tree)) == [("odd.txt", None)]

    def test_entry_whose_ef_holds_no_stream(self, prc: ModuleType) -> None:
        tree = pikepdf.Dictionary(
            Names=[
                pikepdf.String("empty.txt"),
                pikepdf.Dictionary(EF=pikepdf.Dictionary()),
            ]
        )
        assert list(prc._iter_embedded_files(tree)) == [("empty.txt", None)]

    def test_unreadable_attachment_reports_no_size(
        self, prc: ModuleType, monkeypatch
    ) -> None:
        with pikepdf.new() as pdf:
            stream = pdf.make_stream(b"payload")

            def explode(*args, **kwargs):
                raise zlib.error("corrupt")

            monkeypatch.setattr(type(stream), "read_bytes", explode)
            tree = pikepdf.Dictionary(
                Names=[
                    pikepdf.String("broken.bin"),
                    pikepdf.Dictionary(EF=pikepdf.Dictionary(F=stream)),
                ]
            )
            assert list(prc._iter_embedded_files(tree)) == [("broken.bin", None)]

    def test_document_without_attachments(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            assert prc.extract_attachments(pdf) == []


class TestRawObjectSweep:
    """The byte-level secret sweep skips what it cannot decompress."""

    def test_no_secrets_means_no_work(self, prc: ModuleType, fixtures: Path) -> None:
        with pikepdf.open(fixtures / "clean.pdf") as pdf:
            report = prc.Report(path=Path("clean.pdf"))
            prc.check_raw_objects(pdf, report, [])
            assert report.findings == []

    def test_unreadable_stream_is_skipped(
        self, prc: ModuleType, fixtures: Path, monkeypatch
    ) -> None:
        with pikepdf.open(fixtures / "fake_redacted.pdf") as pdf:
            stream_type = type(pdf.pages[0]["/Contents"])

            def explode(*args, **kwargs):
                raise pikepdf.PdfError("cannot decompress")

            monkeypatch.setattr(stream_type, "read_bytes", explode)
            report = prc.Report(path=Path("x.pdf"))
            # Every stream fails, so nothing is found and nothing raises.
            prc.check_raw_objects(pdf, report, ["Evergreen"])
            assert report.findings == []

    def test_finds_a_secret_in_a_string_object(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        path = tmp_path / "indirect_string.pdf"
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            pdf.Root["/Marker"] = pdf.make_indirect(pikepdf.String("742 Evergreen"))
            pdf.save(path)
        with pikepdf.open(path) as pdf:
            report = prc.Report(path=path)
            prc.check_raw_objects(pdf, report, ["742 Evergreen"])
            assert [f.check for f in report.findings] == ["raw-objects"]


class TestMetadataEdges:
    """Metadata may be absent, empty, or unreadable."""

    def test_document_without_metadata(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            assert prc.extract_metadata(pdf) == []

    def test_unreadable_xmp_is_skipped(self, prc: ModuleType, monkeypatch) -> None:
        with pikepdf.new() as pdf:
            stream = pdf.make_stream(b"<x:xmpmeta/>")
            pdf.Root["/Metadata"] = pdf.make_indirect(stream)

            def explode(*args, **kwargs):
                raise pikepdf.PdfError("cannot read")

            monkeypatch.setattr(type(stream), "read_bytes", explode)
            assert prc.extract_metadata(pdf) == []

    def test_blank_docinfo_values_are_dropped(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            pdf.trailer["/Info"] = pdf.make_indirect(
                pikepdf.Dictionary(Title=pikepdf.String("   "))
            )
            assert prc.extract_metadata(pdf) == []


class TestStringSweepEdges:
    """The catch-all string walk is bounded and filtered."""

    def test_depth_limit_stops_traversal(self, prc: ModuleType) -> None:
        found: list[str] = []
        prc._walk_strings(pikepdf.String("deep"), set(), found, 65)
        assert found == []

    def test_binary_keys_are_never_walked(self, prc: ModuleType) -> None:
        found: list[str] = []
        node = pikepdf.Dictionary(ID=pikepdf.String("binary-ish"))
        prc._walk_strings(node, set(), found, 0)
        assert found == []

    def test_raw_sweep_does_not_repeat_a_dedicated_layer(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        with pikepdf.open(fixtures / "xmp.pdf") as pdf:
            visible = prc.extract_page_text(pdf)
            extracts = prc.collect_extracts(pdf, visible)
        claimed = {e.text for e in extracts if e.layer != prc.RAW_STRINGS}
        swept = {e.text for e in extracts if e.layer == prc.RAW_STRINGS}
        assert not (claimed & swept)

    def test_the_same_value_under_two_keys_is_kept_twice(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """DocInfo /Author and /Creator both say 'anonymous' -- that is
        two facts about the document, not one repeated."""
        with pikepdf.open(fixtures / "clean.pdf") as pdf:
            metadata = prc.extract_metadata(pdf)
        anonymous = [e.location for e in metadata if e.text == "anonymous"]
        assert sorted(anonymous) == ["DocInfo /Author", "DocInfo /Creator"]


class TestOutputPathEdges:
    """Failures while inspecting the output path are reported, not raised."""

    @pytest.mark.skipif(os.geteuid() == 0, reason="root ignores write permissions")
    def test_unwritable_directory(self, prc: ModuleType, tmp_path: Path) -> None:
        locked = tmp_path / "locked"
        locked.mkdir()
        locked.chmod(0o500)
        try:
            problem = prc.check_output_path(
                locked / "out.txt", tmp_path / "d.pdf", False
            )
            assert problem is not None and "not writable" in problem
        finally:
            locked.chmod(0o700)

    def test_samefile_failure_is_reported(
        self, prc: ModuleType, tmp_path: Path, monkeypatch
    ) -> None:
        target = tmp_path / "out.txt"
        target.write_text("x")
        pdf = tmp_path / "doc.pdf"
        pdf.write_bytes(b"%PDF-1.7\n")

        def explode(self, other):
            raise OSError("stat failed")

        monkeypatch.setattr(Path, "samefile", explode)
        problem = prc.check_output_path(target, pdf, True)
        assert problem is not None and "could not inspect" in problem

    def test_bare_filename_uses_the_current_directory(
        self, prc: ModuleType, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        assert prc.check_output_path(Path("out.txt"), Path("doc.pdf"), False) is None
