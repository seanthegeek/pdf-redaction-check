# SPDX-FileCopyrightText: 2026 Sean Whalen
# SPDX-License-Identifier: MIT
"""Tests for the paths a malformed or hostile document takes.

Broken files are the normal case for this tool, so every parser has to
degrade to "could not read this layer" instead of raising. These build
their inputs in memory rather than in `tests/samples`, because they are
deliberately invalid structures, not documents anyone could produce.
"""

from __future__ import annotations

import base64
import os
import zlib
from pathlib import Path
from types import ModuleType
from typing import Any

import pikepdf
import pytest

SECRET = "742 Evergreen Terrace"


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

    def test_a_content_stream_that_will_not_decompress_is_reported(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        """A page whose instructions will not decompress is still said.

        Reading a document from disk is the case this covers, and qpdf
        reports that one as a structural fault. Parsing the same stream
        on its own raises the damaged-data exception instead, which is
        the shape a Form XObject arrives in -- see
        `TestFormXObjects.test_a_form_that_will_not_parse_costs_only_its_own_text`,
        which is where handling both is what keeps the run alive.
        """
        path = tmp_path / "undecompressable.pdf"
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            contents = pdf.make_stream(b"BT /F1 12 Tf (hidden) Tj ET")
            contents["/Filter"] = pikepdf.Name("/FlateDecode")
            page.Contents = pdf.make_indirect(contents)
            pdf.save(path)
        report, _ = prc.analyze(path, [])
        content = [f for f in report.findings if f.check == prc.CONTENT_STREAM]
        assert len(content) == 1
        assert content[0].severity is prc.Severity.WARNING
        assert content[0].location == "page 1"
        assert "content stream could not be parsed" in content[0].detail
        assert prc.verdict_code(report) == prc.EXIT_SUSPICIOUS

    def test_page_without_resources(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            assert prc.extract_page_text(pdf) == ""

    def test_a_raising_page_is_skipped(
        self, prc: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def explode(page):
            raise pikepdf.PdfError("bad page")

        monkeypatch.setattr(prc, "_page_text", explode)
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            assert prc.extract_page_text(pdf) == ""

    def test_a_raising_page_is_reported_when_anyone_is_listening(
        self, prc: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A page nobody could read is not a page with no text on it."""

        def explode(page):
            raise pikepdf.PdfError("bad page")

        monkeypatch.setattr(prc, "_page_text", explode)
        report = prc.Report(path=Path("x.pdf"))
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            assert prc.extract_page_text(pdf, report) == ""
        assert len(report.findings) == 1
        finding = report.findings[0]
        assert finding.severity is prc.Severity.WARNING
        assert finding.check == prc.CONTENT_STREAM
        assert finding.location == "page 1"
        assert "content stream could not be parsed" in finding.detail


class TestInheritedResources:
    """/Resources belongs to the closest ancestor that has one."""

    def test_a_page_uses_its_ancestors_resources(self, prc: ModuleType) -> None:
        """ISO 32000 section 7.7.3.4: a page with none of its own
        inherits the closest ancestor's."""
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            del page.obj["/Resources"]
            pdf.Root["/Pages"]["/Resources"] = pikepdf.Dictionary(
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
            fonts = prc.font_resources(page)
            assert fonts is not None
            assert list(fonts.keys()) == ["/F1"]

    def test_a_page_tree_with_no_resources_anywhere(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            del page.obj["/Resources"]
            assert prc.page_resources(page) is None
            assert prc.font_resources(page) is None

    def test_resources_without_a_font_dictionary(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            assert prc.page_resources(page) is not None
            assert prc.font_resources(page) is None

    def test_a_page_that_is_its_own_parent_terminates(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            del page.obj["/Resources"]
            page.obj["/Parent"] = page.obj
            assert prc.page_resources(page) is None


class TestUndecodableText:
    """Page text this cannot turn into characters is reported, not dropped."""

    def draw(self, prc: ModuleType, tmp_path: Path, contents: bytes) -> tuple[str, Any]:
        """Run one content stream through the text extraction.

        Returns the recovered text and the report it filled in. The
        report's type lives in the module under test, which cannot be
        imported from the repository root, so it is left unnamed here.
        """
        path = tmp_path / "drawn.pdf"
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
            page.Contents = pdf.make_stream(contents)
            pdf.save(path)
        report = prc.Report(path=path)
        with pikepdf.open(path) as pdf:
            text = prc.extract_page_text(pdf, report)
        return text, report

    def test_text_drawn_before_any_font_was_selected(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        text, report = self.draw(prc, tmp_path, b"BT (hidden) Tj ET")
        assert text == ""
        assert len(report.findings) == 1
        assert "before any font was selected" in report.findings[0].detail
        assert "6 byte(s)" in report.findings[0].detail
        assert report.findings[0].location == "page 1"

    def test_a_font_operator_that_names_no_font(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        text, report = self.draw(prc, tmp_path, b"BT 12 12 Tf (hidden) Tj ET")
        assert text == ""
        assert "before any font was selected" in report.findings[0].detail

    def test_a_font_the_page_does_not_define(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        text, report = self.draw(prc, tmp_path, b"BT /FNope 12 Tf (hidden) Tj ET")
        assert text == ""
        assert len(report.findings) == 1
        detail = report.findings[0].detail
        assert "drawn with /FNope" in detail
        assert "resources in effect where it was drawn do not define" in detail

    def test_codes_the_font_maps_to_nothing(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        """Codes 1 and 2 are undefined in Adobe's StandardEncoding.

        The letters around them still come through: a run this cannot
        read costs the characters it covers, not the rest of the page.
        """
        text, report = self.draw(prc, tmp_path, b"BT /F1 12 Tf <41010242> Tj ET")
        assert text == "AB"
        assert len(report.findings) == 1
        detail = report.findings[0].detail
        assert "2 character code(s) drawn with /F1" in detail
        assert "mapped by neither" in detail


class TestFormXObjects:
    """A form is a content stream of its own, and it can draw text.

    The page invokes one with `Do`, and what it draws is on the screen
    like anything else the page draws -- so a reader of the page's own
    content stream that stops at the `Do` is reading a fraction of the
    page and calling it the whole of it.
    """

    def helvetica(self, pdf: pikepdf.Pdf) -> pikepdf.Object:
        """Return a plain base-14 font dictionary."""
        return pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Font"),
                Subtype=pikepdf.Name("/Type1"),
                BaseFont=pikepdf.Name("/Helvetica"),
            )
        )

    def form(
        self,
        pdf: pikepdf.Pdf,
        body: bytes,
        resources: pikepdf.Object | None = None,
    ) -> pikepdf.Object:
        """Return a Form XObject drawing `body`."""
        stream = pdf.make_stream(body)
        stream["/Type"] = pikepdf.Name("/XObject")
        stream["/Subtype"] = pikepdf.Name("/Form")
        stream["/BBox"] = [0, 0, 200, 200]
        if resources is not None:
            stream["/Resources"] = resources
        return pdf.make_indirect(stream)

    def read(
        self,
        prc: ModuleType,
        pdf: pikepdf.Pdf,
        contents: bytes,
        xobjects: pikepdf.Object | None = None,
    ) -> tuple[str, Any]:
        """Read one page that names `xobjects`, returning text and report."""
        page = pdf.add_blank_page()
        resources = pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=self.helvetica(pdf)))
        if xobjects is not None:
            resources["/XObject"] = xobjects
        page.Resources = resources
        page.Contents = pdf.make_stream(contents)
        report = prc.Report(path=Path("x.pdf"))
        return prc.extract_page_text(pdf, report), report

    def test_text_inside_a_form_is_part_of_the_page_text(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            xobjects = pikepdf.Dictionary(
                Fm0=self.form(pdf, b"BT /F1 12 Tf (inside) Tj ET")
            )
            text, report = self.read(
                prc, pdf, b"BT /F1 12 Tf (outside) Tj ET q /Fm0 Do Q", xobjects
            )
        assert text == "outsideinside"
        assert report.findings == []

    def test_a_form_draws_with_the_font_selected_before_it(
        self, prc: ModuleType
    ) -> None:
        """A form inherits the graphics state of whatever drew it.

        The font in effect at the `Do` is the font the form starts
        with, so a form that selects none of its own still draws
        readable text rather than bytes nobody could place.
        """
        with pikepdf.new() as pdf:
            xobjects = pikepdf.Dictionary(Fm0=self.form(pdf, b"BT (inside) Tj ET"))
            text, report = self.read(prc, pdf, b"BT /F1 12 Tf q /Fm0 Do Q ET", xobjects)
        assert text == "inside"
        assert report.findings == []

    def test_a_font_selected_inside_a_form_does_not_leak_out(
        self, prc: ModuleType
    ) -> None:
        """The other direction: the form's state does not outlive it.

        The form selects a font of its own that maps code 65 to z. Back
        on the page, code 65 is an A again, because the page's own font
        is what is in effect there.
        """
        with pikepdf.new() as pdf:
            swapped = pdf.make_indirect(
                pikepdf.Dictionary(
                    Type=pikepdf.Name("/Font"),
                    Subtype=pikepdf.Name("/Type1"),
                    BaseFont=pikepdf.Name("/Helvetica"),
                    Encoding=pikepdf.Dictionary(
                        Type=pikepdf.Name("/Encoding"),
                        Differences=[65, pikepdf.Name("/z")],
                    ),
                )
            )
            xobjects = pikepdf.Dictionary(
                Fm0=self.form(
                    pdf,
                    b"BT /F1 12 Tf <41> Tj ET",
                    pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=swapped)),
                )
            )
            text, report = self.read(
                prc, pdf, b"BT /F1 12 Tf q /Fm0 Do Q <41> Tj ET", xobjects
            )
        assert text == "zA"
        assert report.findings == []

    def test_a_form_that_draws_itself_terminates(self, prc: ModuleType) -> None:
        """A loop stops as soon as the same drawing comes round again.

        A drawing is the form, the font in effect, and the resources it
        was drawn with, so this form is read twice -- once as the page
        draws it, once as it draws itself, where the resources in effect
        are its own. The third time repeats the second, and stops.
        """
        with pikepdf.new() as pdf:
            looped = self.form(pdf, b"BT /F1 12 Tf (once) Tj ET q /Fm0 Do Q")
            looped["/Resources"] = pikepdf.Dictionary(
                XObject=pikepdf.Dictionary(Fm0=looped),
                Font=pikepdf.Dictionary(F1=self.helvetica(pdf)),
            )
            text, report = self.read(
                prc, pdf, b"q /Fm0 Do Q", pikepdf.Dictionary(Fm0=looped)
            )
        assert text == "onceonce"
        assert report.findings == []

    def test_the_same_form_drawn_under_two_fonts_is_read_twice(
        self, prc: ModuleType
    ) -> None:
        """A form draws what the font in effect says it draws.

        The page draws one form twice, under two fonts, so a viewer
        shows six characters. Recording the form alone rather than the
        pair of form and font would lose the second three -- and the
        font-subset check would then report the three characters the
        page really did show as the remnant of a removed passage.
        """
        with pikepdf.new() as pdf:
            swapped = pdf.make_indirect(
                pikepdf.Dictionary(
                    Type=pikepdf.Name("/Font"),
                    Subtype=pikepdf.Name("/Type1"),
                    BaseFont=pikepdf.Name("/Helvetica"),
                    Encoding=pikepdf.Dictionary(
                        Type=pikepdf.Name("/Encoding"),
                        Differences=[65, pikepdf.Name("/x"), pikepdf.Name("/y")],
                    ),
                )
            )
            page = pdf.add_blank_page()
            page.Resources = pikepdf.Dictionary(
                Font=pikepdf.Dictionary(F1=self.helvetica(pdf), F2=swapped),
                XObject=pikepdf.Dictionary(Fm0=self.form(pdf, b"BT <4142> Tj ET")),
            )
            page.Contents = pdf.make_stream(
                b"BT /F1 12 Tf q /Fm0 Do Q /F2 12 Tf q /Fm0 Do Q ET"
            )
            report = prc.Report(path=Path("x.pdf"))
            text = prc.extract_page_text(pdf, report)
        assert text == "ABxy"
        assert report.findings == []

    def test_a_form_that_will_not_parse_costs_only_its_own_text(
        self, prc: ModuleType
    ) -> None:
        """A page is not thrown away over one form it could not read.

        This form says it is compressed and is not, so reading its
        instructions fails where reading its bytes does.
        """
        with pikepdf.new() as pdf:
            broken = self.form(pdf, b"BT /F1 12 Tf (inside) Tj ET")
            broken["/Filter"] = pikepdf.Name("/FlateDecode")
            xobjects = pikepdf.Dictionary(Fm0=broken)
            text, report = self.read(
                prc, pdf, b"BT /F1 12 Tf (outside) Tj ET q /Fm0 Do Q", xobjects
            )
        assert text == "outside"
        assert len(report.findings) == 1
        finding = report.findings[0]
        assert finding.severity is prc.Severity.WARNING
        assert finding.check == prc.CONTENT_STREAM
        assert finding.location == "page 1"
        assert "the form drawn as /Fm0 could not be parsed" in finding.detail

    def test_an_image_drawn_by_the_same_operator_holds_no_text(
        self, prc: ModuleType
    ) -> None:
        """`Do` names either a form or a picture, and only one has text."""
        with pikepdf.new() as pdf:
            image = pdf.make_stream(b"\xff\xd8\xffnot text")
            image["/Type"] = pikepdf.Name("/XObject")
            image["/Subtype"] = pikepdf.Name("/Image")
            text, report = self.read(
                prc,
                pdf,
                b"BT /F1 12 Tf (outside) Tj ET q /Im0 Do Q",
                pikepdf.Dictionary(Im0=pdf.make_indirect(image)),
            )
        assert text == "outside"
        assert report.findings == []

    def test_drawing_something_the_resources_do_not_name_is_reported(
        self, prc: ModuleType
    ) -> None:
        """Something was drawn there, and nothing here could read it."""
        with pikepdf.new() as pdf:
            xobjects = pikepdf.Dictionary(Fm0=self.form(pdf, b"BT (inside) Tj ET"))
            text, report = self.read(
                prc, pdf, b"BT /F1 12 Tf (outside) Tj ET q /Fm9 Do Q", xobjects
            )
        assert text == "outside"
        assert len(report.findings) == 1
        finding = report.findings[0]
        assert finding.severity is prc.Severity.WARNING
        assert finding.check == prc.CONTENT_STREAM
        assert finding.location == "page 1"
        assert "a form was drawn as /Fm9" in finding.detail
        assert "do not define" in finding.detail

    def test_drawing_on_a_page_that_names_no_xobjects_is_reported_too(
        self, prc: ModuleType
    ) -> None:
        with pikepdf.new() as pdf:
            text, report = self.read(
                prc, pdf, b"BT /F1 12 Tf (outside) Tj ET q /Fm0 Do Q"
            )
        assert text == "outside"
        assert [f.check for f in report.findings] == [prc.CONTENT_STREAM]
        assert "a form was drawn as /Fm0" in report.findings[0].detail

    def test_an_operand_that_is_not_a_name_is_skipped(self, prc: ModuleType) -> None:
        """`Do` takes one name; anything else names no resource."""
        with pikepdf.new() as pdf:
            xobjects = pikepdf.Dictionary(Fm0=self.form(pdf, b"BT (inside) Tj ET"))
            text, report = self.read(
                prc, pdf, b"BT /F1 12 Tf (outside) Tj ET q 12 Do Q", xobjects
            )
        assert text == "outside"
        assert report.findings == []

    def test_a_form_finds_a_font_the_page_defines(self, prc: ModuleType) -> None:
        """A form's own resources are the first place to look, not the only.

        ISO 32000 section 8.10.1 asks a form to carry every resource it
        uses, and producers do leave names to the page anyway. A reader
        finds them there and draws the text; a checker that did not
        would report the page's own font as declaring characters the
        page never showed.
        """
        with pikepdf.new() as pdf:
            xobjects = pikepdf.Dictionary(
                Fm0=self.form(
                    pdf,
                    b"BT /F1 12 Tf (inside) Tj ET",
                    pikepdf.Dictionary(XObject=pikepdf.Dictionary()),
                )
            )
            text, report = self.read(prc, pdf, b"q /Fm0 Do Q", xobjects)
        assert text == "inside"
        assert report.findings == []

    def test_a_form_with_no_object_number_is_always_read(self, prc: ModuleType) -> None:
        """A form that is not an indirect object cannot be reached twice.

        Having no identity of its own, it is contained in exactly one
        place, so it cannot be drawn from two of them and cannot draw
        itself -- and there is no object number to record it under.
        """
        drawn: set[tuple[object, ...]] = set()
        direct = pikepdf.Dictionary()
        assert prc.already_drawn(direct, "/F1", None, drawn) is False
        assert prc.already_drawn(direct, "/F1", None, drawn) is False
        assert drawn == set()

    def test_the_depth_limit_stops_the_walk(self, prc: ModuleType) -> None:
        """Forms nest, so the walk is bounded as the tag tree walk is."""
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            page.Contents = pdf.make_stream(b"BT /F1 12 Tf (deep) Tj ET")
            found = prc.PageText()
            prc.draw_content(page, (prc.page_resources(page),), found, depth=65)
        assert found.out == []


class TestResourceGroups:
    """A resource group is only usable when it is a dictionary."""

    def test_a_group_that_is_not_a_dictionary_is_no_group(
        self, prc: ModuleType
    ) -> None:
        resources = pikepdf.Dictionary(XObject=pikepdf.Name("/NotADictionary"))
        assert prc.resource_group(resources, "/XObject") is None

    def test_resources_that_are_not_a_dictionary_have_no_groups(
        self, prc: ModuleType
    ) -> None:
        assert prc.resource_group(pikepdf.Name("/Nope"), "/Font") is None

    def test_the_inner_scope_wins_and_the_outer_one_fills_gaps(
        self, prc: ModuleType
    ) -> None:
        """Both halves of the lookup a form gets.

        A name the form defines is the form's; a name it does not define
        is looked for outwards, which is where a producer that left a
        font to the page put it.
        """
        inner = pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=pikepdf.String("inner")))
        outer = pikepdf.Dictionary(
            Font=pikepdf.Dictionary(
                F1=pikepdf.String("outer"), F2=pikepdf.String("only outside")
            )
        )
        merged = prc.resource_scope((inner, outer), "/Font")
        assert str(merged["/F1"]) == "inner"
        assert str(merged["/F2"]) == "only outside"

    def test_a_scope_with_no_such_group_contributes_nothing(
        self, prc: ModuleType
    ) -> None:
        assert prc.resource_scope((pikepdf.Dictionary(), None), "/Font") == {}


class TestObjectLabels:
    """A finding has to be able to say which object it is about."""

    def test_an_indirect_object_is_named_by_its_number(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            obj = pdf.make_indirect(pikepdf.Dictionary())
            assert prc.object_label(obj) == f"object {obj.objgen[0]} 0"

    def test_a_direct_object_has_no_number_to_give(self, prc: ModuleType) -> None:
        assert prc.object_label(pikepdf.Dictionary()) == "direct object"


class TestProblemNotes:
    """Descriptions of what could not be read go to whoever asked for them."""

    def test_a_collector_receives_the_message(self, prc: ModuleType) -> None:
        problems: list[str] = []
        prc.note(problems, "could not read the thing")
        assert problems == ["could not read the thing"]

    def test_no_collector_means_the_message_is_dropped(self, prc: ModuleType) -> None:
        assert prc.note(None, "could not read the thing") is None

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
        leaf = pikepdf.Dictionary(
            Names=[pikepdf.String("nested.txt"), pikepdf.Dictionary()]
        )
        tree = pikepdf.Dictionary(Kids=[leaf])
        names = [label for label, _ in prc._iter_embedded_files(tree)]
        assert names == ["nested.txt"]

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
        self, prc: ModuleType, monkeypatch: pytest.MonkeyPatch
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
            report = prc.Report(path=Path("x.pdf"))
            prc.check_attachments(pdf, report)
            assert report.findings == []

    @pytest.mark.parametrize(
        "names",
        [
            pikepdf.Array([pikepdf.Name("/EmbeddedFiles")]),
            pikepdf.String("/EmbeddedFiles"),
        ],
    )
    def test_a_name_dictionary_that_is_not_a_dictionary_is_reported(
        self, prc: ModuleType, tmp_path: Path, names: pikepdf.Object
    ) -> None:
        """Hostile input, on the check that runs for every invocation.

        Asking pikepdf whether a key is in an array raises, and whether
        it is in a string raises something else again, so this used to
        end the run in a traceback -- whose exit code, 1, is the one
        that means the document is suspicious.
        """
        path = tmp_path / "bad_names.pdf"
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            pdf.Root["/Names"] = names
            pdf.save(path)
        with pikepdf.open(path) as pdf:
            assert prc.extract_attachments(pdf) == []
        report, _ = prc.analyze(path, [])
        attachments = [f for f in report.findings if f.check == prc.ATTACHMENTS]
        assert len(attachments) == 1
        assert attachments[0].severity is prc.Severity.WARNING
        assert "not a dictionary" in attachments[0].detail
        assert prc.verdict_code(report) == prc.EXIT_SUSPICIOUS

    def test_a_document_with_a_name_tree_and_no_attachments_is_silent(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        """The other half: a name dictionary is not itself a finding."""
        path = tmp_path / "other_names.pdf"
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            pdf.Root["/Names"] = pikepdf.Dictionary(
                Dests=pikepdf.Dictionary(Names=pikepdf.Array())
            )
            pdf.save(path)
        report, _ = prc.analyze(path, [])
        assert [f for f in report.findings if f.check == prc.ATTACHMENTS] == []


class TestStreamFilters:
    """A stream names its filters as one name, several, or nothing."""

    def make(self, pdf: pikepdf.Pdf, value: object) -> pikepdf.Object:
        """Return a stream whose /Filter is `value`, or has none for None."""
        stream = pdf.make_stream(b"data")
        if value is not None:
            stream["/Filter"] = value
        return stream

    def test_one_filter(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            stream = self.make(pdf, pikepdf.Name("/FlateDecode"))
            assert prc.stream_filters(stream) == ["/FlateDecode"]

    def test_a_chain_of_filters(self, prc: ModuleType) -> None:
        """ISO 32000 section 7.3.8.2: filters applied in turn.

        This chain is what the Distiller line of producers writes for a
        JPEG, so it is the one an image exemption has to handle. Naming
        it is not excusing it, though: the four bytes here are not a
        picture, and the same stream is still reported.
        """
        with pikepdf.new() as pdf:
            stream = self.make(
                pdf,
                pikepdf.Array(
                    [pikepdf.Name("/ASCII85Decode"), pikepdf.Name("/DCTDecode")]
                ),
            )
            assert prc.stream_filters(stream) == ["/ASCII85Decode", "/DCTDecode"]
            _, problem = prc.stream_bytes(stream)
            assert problem is not None and "filters could not be undone" in problem

    def test_a_chain_entry_that_is_not_a_name_is_left_out(
        self, prc: ModuleType
    ) -> None:
        with pikepdf.new() as pdf:
            stream = self.make(pdf, pikepdf.Array([pikepdf.Name("/DCTDecode"), 12]))
            assert prc.stream_filters(stream) == ["/DCTDecode"]

    @pytest.mark.parametrize("value", [None, pikepdf.String("/DCTDecode")])
    def test_anything_else_names_no_filter(
        self, prc: ModuleType, value: object
    ) -> None:
        with pikepdf.new() as pdf:
            assert prc.stream_filters(self.make(pdf, value)) == []


class TestImageExemption:
    """What excuses a stream from the unread-stream report is its content.

    pikepdf runs none of the image filters, so every stream that names
    one fails to decode exactly as a stream that lies about being
    compressed does. Telling the two apart by the name on the stream is
    telling them apart by the very claim this tool exists to distrust,
    so the format has to be corroborated: by the signature the bytes
    start with, or -- for the fax formats, which have none -- by the
    stream being an image XObject.
    """

    # A JPEG's start-of-image marker, and the two shapes JPEG 2000 data
    # comes in: the JP2 signature box, and a bare codestream.
    JPEG = b"\xff\xd8\xff"
    JP2_BOX = b"\x00\x00\x00\x0cjP  "
    JP2_CODESTREAM = b"\xff\x4f\xff\x51"

    def store(
        self,
        pdf: pikepdf.Pdf,
        data: bytes,
        filters: object,
        subtype: str | None = None,
    ) -> pikepdf.Object:
        """Return a stream holding `data` byte for byte, under `filters`."""
        stream = pdf.make_stream(data)
        stream["/Filter"] = filters
        if subtype is not None:
            stream["/Subtype"] = pikepdf.Name(subtype)
        return stream

    def armor(self, data: bytes) -> bytes:
        """Spell `data` in ASCII85 the way a PDF stream carries it.

        a85encode's Adobe framing puts `<~` in front, which a PDF stream
        does not have; the closing `~>` is the end-of-data marker of
        ISO 32000 section 7.4.3 and does belong there.
        """
        return base64.a85encode(data, adobe=True)[2:]

    def test_a_jpeg_is_not_reported(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            stream = self.store(
                pdf, self.JPEG + b"body", pikepdf.Name("/DCTDecode"), "/Image"
            )
            assert prc.stream_bytes(stream) == (self.JPEG + b"body", None)

    def test_a_jpeg_written_as_printable_characters_is_not_reported(
        self, prc: ModuleType
    ) -> None:
        """The chain an ordinary scan out of Distiller arrives in.

        The armor is printable characters and no compression, so it is
        undone here -- and what comes back is the picture itself, not
        the spelling of it, which is what the raw sweep then searches.
        """
        with pikepdf.new() as pdf:
            stream = self.store(
                pdf,
                self.armor(self.JPEG + b"body"),
                pikepdf.Array(
                    [pikepdf.Name("/ASCII85Decode"), pikepdf.Name("/DCTDecode")]
                ),
            )
            assert prc.stream_bytes(stream) == (self.JPEG + b"body", None)

    def test_hexadecimal_armor_is_undone_as_well(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            picture = self.JPEG + b"body"
            stream = self.store(
                pdf,
                picture.hex().encode("ascii") + b">",
                pikepdf.Array(
                    [pikepdf.Name("/ASCIIHexDecode"), pikepdf.Name("/DCTDecode")]
                ),
            )
            assert prc.stream_bytes(stream) == (picture, None)

    def test_ascii85_without_its_end_marker_still_decodes(
        self, prc: ModuleType
    ) -> None:
        """Producers do leave the marker off; the picture is still there."""
        with pikepdf.new() as pdf:
            stream = self.store(
                pdf,
                self.armor(self.JPEG + b"body").removesuffix(b"~>"),
                pikepdf.Array(
                    [pikepdf.Name("/ASCII85Decode"), pikepdf.Name("/DCTDecode")]
                ),
            )
            assert prc.stream_bytes(stream) == (self.JPEG + b"body", None)

    def test_armor_that_does_not_decode_is_reported(self, prc: ModuleType) -> None:
        """Bytes ASCII85 cannot spell are bytes nobody read."""
        with pikepdf.new() as pdf:
            stream = self.store(
                pdf,
                b"\xff\xfe\xfd",
                pikepdf.Array(
                    [pikepdf.Name("/ASCII85Decode"), pikepdf.Name("/DCTDecode")]
                ),
            )
            _, problem = prc.stream_bytes(stream)
        assert problem is not None and "filters could not be undone" in problem

    def test_armor_on_its_own_is_not_a_picture(self, prc: ModuleType) -> None:
        """No image filter in the chain, so nothing to be excused by."""
        with pikepdf.new() as pdf:
            stream = self.store(pdf, b"\xff\xfe\xfd", pikepdf.Name("/ASCII85Decode"))
            _, problem = prc.stream_bytes(stream)
        assert problem is not None

    def test_a_stream_that_only_says_it_is_a_picture_is_reported(
        self, prc: ModuleType
    ) -> None:
        """The regression this rule exists for.

        Compressed text under the name of an image filter: pikepdf will
        not run the filter, and the bytes as stored are compressed, so
        the address is in the document and beyond every check here.
        Trusting the name reports that as nothing to find.
        """
        with pikepdf.new() as pdf:
            stream = self.store(
                pdf,
                zlib.compress(f"leak: {SECRET}".encode()),
                pikepdf.Name("/DCTDecode"),
            )
            _, problem = prc.stream_bytes(stream)
        assert problem is not None and "filters could not be undone" in problem

    def test_calling_itself_an_image_xobject_does_not_supply_the_signature(
        self, prc: ModuleType
    ) -> None:
        """Both halves of the corroboration rule meet here.

        /Subtype /Image is another claim the document makes about
        itself. Where the format has a signature, that is what decides,
        so a stream saying it is a JPEG image and not starting like one
        is still reported.
        """
        with pikepdf.new() as pdf:
            stream = self.store(
                pdf,
                zlib.compress(f"leak: {SECRET}".encode()),
                pikepdf.Name("/DCTDecode"),
                "/Image",
            )
            _, problem = prc.stream_bytes(stream)
        assert problem is not None

    def image(
        self,
        pdf: pikepdf.Pdf,
        data: bytes,
        filters: object,
        size: bool = True,
    ) -> pikepdf.Object:
        """Return an image XObject, with or without the size it must declare."""
        stream = self.store(pdf, data, filters, "/Image")
        if size:
            stream["/Width"] = 32
            stream["/Height"] = 32
        return stream

    def test_a_fax_image_xobject_is_not_reported(self, prc: ModuleType) -> None:
        """The formats with no signature are corroborated the other way."""
        with pikepdf.new() as pdf:
            stream = self.image(pdf, b"\x00\x01\x02", pikepdf.Name("/CCITTFaxDecode"))
            assert prc.stream_bytes(stream) == (b"\x00\x01\x02", None)

    def test_a_fax_filter_outside_an_image_xobject_is_reported(
        self, prc: ModuleType
    ) -> None:
        """The other half: without /Subtype /Image there is no picture."""
        with pikepdf.new() as pdf:
            stream = self.store(pdf, b"\x00\x01\x02", pikepdf.Name("/CCITTFaxDecode"))
            _, problem = prc.stream_bytes(stream)
        assert problem is not None

    @pytest.mark.parametrize("missing", ["/Width", "/Height"])
    def test_a_signatureless_filter_needs_the_size_an_image_declares(
        self, prc: ModuleType, missing: str
    ) -> None:
        """The one-key bypass, closed as far as it can be closed.

        /Subtype is another claim the document makes about itself, and
        the fax formats have no signature to check it against. Requiring
        the size every image XObject must declare (ISO 32000 Table 89)
        means a stream has to be shaped like the picture it says it is,
        not merely named one -- which is what the address compressed
        under /JBIG2Decode here is not.
        """
        with pikepdf.new() as pdf:
            stream = self.image(
                pdf,
                zlib.compress(f"leak: {SECRET}".encode()),
                pikepdf.Name("/JBIG2Decode"),
            )
            del stream[missing]
            _, problem = prc.stream_bytes(stream)
        assert problem is not None and "filters could not be undone" in problem

    def test_a_size_that_is_not_a_number_is_no_size(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            stream = self.image(pdf, b"\x00\x01\x02", pikepdf.Name("/JBIG2Decode"))
            stream["/Width"] = pikepdf.Name("/NotANumber")
            _, problem = prc.stream_bytes(stream)
        assert problem is not None

    @pytest.mark.parametrize("signature", [JP2_BOX, JP2_CODESTREAM])
    def test_both_shapes_of_jpeg_2000_are_recognised(
        self, prc: ModuleType, signature: bytes
    ) -> None:
        with pikepdf.new() as pdf:
            stream = self.store(pdf, signature + b"body", pikepdf.Name("/JPXDecode"))
            assert prc.stream_bytes(stream) == (signature + b"body", None)

    def test_the_committed_armored_sample_is_clean(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """An ordinary scanned page must not come back suspicious."""
        report, _ = prc.analyze(fixtures / "armored_image.pdf", [])
        assert [f for f in report.findings if f.check == prc.RAW_OBJECTS] == []
        assert prc.verdict_code(report) == prc.EXIT_CLEAN

    def test_the_committed_armored_sample_is_searched_as_a_picture(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The other half: unreported is not uninspected.

        What the sweep gets for that stream is the JPEG, armor taken
        off, so a secret sitting in the picture's own bytes is in what
        was searched.
        """
        with pikepdf.open(fixtures / "armored_image.pdf") as pdf:
            images = [
                stream
                for stream in pdf.objects
                if isinstance(stream, pikepdf.Stream)
                and str(stream.get("/Subtype", "")) == "/Image"
            ]
            assert len(images) == 1
            payload, problem = prc.stream_bytes(images[0])
        assert problem is None
        assert payload.startswith(self.JPEG)

    def test_the_committed_lying_sample_is_not_clean(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """End to end on the sample built for the silenced-leak case."""
        report, _ = prc.analyze(fixtures / "lying_image.pdf", [])
        raw = [f for f in report.findings if f.check == prc.RAW_OBJECTS]
        assert [f.severity for f in raw] == [prc.Severity.WARNING]
        assert "filters could not be undone" in raw[0].detail
        assert raw[0].location.startswith("object ")
        assert prc.verdict_code(report) == prc.EXIT_SUSPICIOUS


class TestFilterChains:
    """Armour in front of a filter chain is undone here, not reported."""

    def test_armor_before_an_image_filter_is_split_off(self, prc: ModuleType) -> None:
        assert prc.split_ascii_armor(["/ASCII85Decode", "/DCTDecode"]) == (
            ["/ASCII85Decode"],
            ["/DCTDecode"],
        )

    def test_a_chain_of_nothing_but_armor(self, prc: ModuleType) -> None:
        assert prc.split_ascii_armor(["/ASCIIHexDecode"]) == (["/ASCIIHexDecode"], [])

    def test_armor_after_a_compression_is_not_a_prefix(self, prc: ModuleType) -> None:
        """Only the front of the chain is armor this can undo.

        Filters run in the order they are written, so armor listed
        after a compression describes bytes that compression has to
        produce first -- and that is the compression this could not
        undo.
        """
        assert prc.split_ascii_armor(["/FlateDecode", "/ASCII85Decode"]) == (
            [],
            ["/FlateDecode", "/ASCII85Decode"],
        )

    def test_hexadecimal_digits_stop_at_the_end_marker(self, prc: ModuleType) -> None:
        assert prc.undo_asciihex(b"4865 6c6c 6f>trailing junk") == b"Hello"

    def test_an_odd_hexadecimal_digit_is_padded(self, prc: ModuleType) -> None:
        """ISO 32000 section 7.4.2: a missing final digit is a zero."""
        assert prc.undo_asciihex(b"4865c>") == b"He\xc0"

    def test_undoing_nothing_returns_the_bytes_as_they_are(
        self, prc: ModuleType
    ) -> None:
        assert prc.undo_ascii_armor(b"as stored", []) == b"as stored"


class TestRawObjectSweep:
    """The byte-level sweep says what it could not read, secrets or not."""

    def test_a_document_whose_streams_all_read_reports_nothing(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """With no secrets to match, a readable document is silent."""
        with pikepdf.open(fixtures / "clean.pdf") as pdf:
            report = prc.Report(path=Path("clean.pdf"))
            prc.check_raw_objects(pdf, report, [])
            assert report.findings == []

    def test_an_unreadable_stream_is_reported_with_no_secrets_to_match(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The sweep is not only there to match secrets.

        Nobody supplies a secret on a routine run, and that is exactly
        the run in which "this layer could not be read" must be said out
        loud: `cleartext_stream.pdf` holds the address in the clear, and
        a check that only looked when it was told what to look for
        reported the document as having nothing to find.
        """
        with pikepdf.open(fixtures / "cleartext_stream.pdf") as pdf:
            report = prc.Report(path=Path("cleartext_stream.pdf"))
            prc.check_raw_objects(pdf, report, [])
        assert len(report.findings) == 1
        assert report.findings[0].severity is prc.Severity.WARNING
        assert report.findings[0].check == prc.RAW_OBJECTS
        assert "filters could not be undone" in report.findings[0].detail
        assert report.findings[0].location.startswith("object ")

    def test_the_default_run_on_the_cleartext_sample_is_not_clean(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """End to end, with no arguments but the file.

        The whole premise of the tool is that a run that found nothing
        because a check could not run must not look like a run that
        found nothing because the document is clean.
        """
        report, _ = prc.analyze(fixtures / "cleartext_stream.pdf", [])
        assert prc.verdict_code(report) == prc.EXIT_SUSPICIOUS
        assert [
            f.check for f in report.findings if f.severity is prc.Severity.WARNING
        ] == [prc.RAW_OBJECTS]

    def test_every_unreadable_stream_is_reported_once(
        self, prc: ModuleType, fixtures: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A stream nobody could read is not a stream with nothing in it.

        Skipping it quietly is how a document whose every stream is
        unreadable comes back looking exactly like a document with
        nothing to find.
        """
        with pikepdf.open(fixtures / "fake_redacted.pdf") as pdf:
            stream_type = type(pdf.pages[0]["/Contents"])
            streams = [o for o in pdf.objects if isinstance(o, pikepdf.Stream)]
            assert streams, "the fixture must contain streams to fail on"

            def explode(*args, **kwargs):
                raise pikepdf.PdfError("cannot decompress")

            monkeypatch.setattr(stream_type, "read_bytes", explode)
            report = prc.Report(path=Path("x.pdf"))
            prc.check_raw_objects(pdf, report, ["Evergreen"])

        assert len(report.findings) == len(streams)
        assert {f.severity for f in report.findings} == {prc.Severity.WARNING}
        assert {f.check for f in report.findings} == {prc.RAW_OBJECTS}
        # One per object, each naming the object it could not read.
        locations = [f.location for f in report.findings]
        assert len(set(locations)) == len(locations)
        assert all(where.startswith("object ") for where in locations)
        assert all("filters could not be undone" in f.detail for f in report.findings)

    def test_a_stream_that_lies_about_being_compressed_is_not_clean(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The committed sample for the silent-clean case.

        `cleartext_stream.pdf` declares /FlateDecode over plain text, so
        the address is in the file with nothing done to it at all. Two
        things follow, and both are reported: the stream does not
        decompress, and searching it as it is stored finds the address
        anyway.
        """
        report, _ = prc.analyze(fixtures / "cleartext_stream.pdf", [SECRET])
        raw = [f for f in report.findings if f.check == prc.RAW_OBJECTS]
        assert [f.severity for f in raw] == [
            prc.Severity.WARNING,
            prc.Severity.CRITICAL,
        ]
        assert "filters could not be undone" in raw[0].detail
        assert raw[0].location.startswith("object ")
        assert repr(SECRET) in raw[1].detail
        assert prc.verdict_code(report) == prc.EXIT_RECOVERABLE

    def test_an_image_is_not_a_layer_that_could_not_be_read(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """A picture's filter cannot be undone, and that is not a fault.

        `image_stream.pdf` carries a photograph stored under /DCTDecode,
        which pikepdf refuses to decode -- raising exactly what a stream
        that lies about being compressed raises. A scanned document is
        made of these, so calling one a layer that could not be read
        would make every scan suspicious.
        """
        report, _ = prc.analyze(fixtures / "image_stream.pdf", [])
        assert [f for f in report.findings if f.check == prc.RAW_OBJECTS] == []
        assert prc.verdict_code(report) == prc.EXIT_CLEAN

    def test_an_image_stream_is_still_searched_as_it_is_stored(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        """The other half of that claim: unreported is not uninspected.

        The bytes here start with JPEG's own start-of-image marker, so
        this really is the picture it says it is -- and the address
        sitting behind the marker, where a comment segment would be, is
        still found.
        """
        path = tmp_path / "image_with_text.pdf"
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            stream = pdf.make_stream(b"\xff\xd8\xff" + f"comment: {SECRET}".encode())
            stream["/Subtype"] = pikepdf.Name("/Image")
            stream["/Filter"] = pikepdf.Name("/DCTDecode")
            pdf.Root["/Marker"] = pdf.make_indirect(stream)
            pdf.save(path)
        with pikepdf.open(path) as pdf:
            report = prc.Report(path=path)
            prc.check_raw_objects(pdf, report, [SECRET])
        assert [f.severity for f in report.findings] == [prc.Severity.CRITICAL]
        assert repr(SECRET) in report.findings[0].detail

    def test_an_image_filter_after_one_that_did_not_run_is_still_reported(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        """The image exemption covers pictures, not anything named one.

        A stream whose filters are `[/FlateDecode /DCTDecode]` is
        compressed text as far as this can tell: the compression could
        not be undone, so the bytes as stored spell nothing, and the
        secret sitting inside them is found by nobody. Treating it as a
        picture because a picture filter is named would turn a warning
        into silence.
        """
        path = tmp_path / "chained.pdf"
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            stream = pdf.make_stream(zlib.compress(f"leak: {SECRET}".encode()))
            stream["/Filter"] = pikepdf.Array(
                [pikepdf.Name("/FlateDecode"), pikepdf.Name("/DCTDecode")]
            )
            pdf.Root["/Marker"] = pdf.make_indirect(stream)
            pdf.save(path)
        with pikepdf.open(path) as pdf:
            report = prc.Report(path=path)
            prc.check_raw_objects(pdf, report, [SECRET])
        assert [f.severity for f in report.findings] == [prc.Severity.WARNING]
        assert "filters could not be undone" in report.findings[0].detail

    def test_a_stream_that_cannot_be_read_at_all_is_reported(
        self, prc: ModuleType, fixtures: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Neither decoded nor as stored: nothing in it was inspected."""
        with pikepdf.open(fixtures / "clean.pdf") as pdf:
            stream_type = type(pdf.pages[0]["/Contents"])

            def explode(*args, **kwargs):
                raise pikepdf.PdfError("cannot read this stream")

            monkeypatch.setattr(stream_type, "read_bytes", explode)
            monkeypatch.setattr(stream_type, "read_raw_bytes", explode)
            report = prc.Report(path=Path("clean.pdf"))
            prc.check_raw_objects(pdf, report, [SECRET])
        assert report.findings
        assert all(f.severity is prc.Severity.WARNING for f in report.findings)
        assert all("could not be read at all" in f.detail for f in report.findings)

    def test_finds_a_secret_in_a_string_object(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        path = tmp_path / "indirect_string.pdf"
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            marker = pdf.make_indirect(pikepdf.String("742 Evergreen"))
            pdf.Root["/Marker"] = marker
            pdf.save(path)
        with pikepdf.open(path) as pdf:
            report = prc.Report(path=path)
            prc.check_raw_objects(pdf, report, ["742 Evergreen"])
            assert [f.check for f in report.findings] == ["raw-objects"]

    def test_a_secret_in_the_sweep_says_which_object_holds_it(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        """A finding an operator cannot act on is half a finding.

        The sweep reads every object in the document, so "found
        somewhere in this file" leaves the reader to search it again by
        hand.
        """
        path = tmp_path / "located.pdf"
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            pdf.Root["/Marker"] = pdf.make_indirect(pikepdf.String(SECRET))
            pdf.save(path)
        with pikepdf.open(path) as pdf:
            number = pdf.Root["/Marker"].objgen[0]
            report = prc.Report(path=path)
            prc.check_raw_objects(pdf, report, [SECRET])
        assert [f.location for f in report.findings] == [f"object {number} 0"]

    def test_finds_a_secret_stored_as_two_byte_characters(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        """PDF text can be UTF-16 with the high byte first, and often is."""
        path = tmp_path / "utf16be.pdf"
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            pdf.Root["/Marker"] = pdf.make_indirect(
                pdf.make_stream(SECRET.encode("utf-16-be"))
            )
            pdf.save(path)
        with pikepdf.open(path) as pdf:
            report = prc.Report(path=path)
            prc.check_raw_objects(pdf, report, [SECRET])
            assert [f.check for f in report.findings] == [prc.RAW_OBJECTS]

    def test_the_low_byte_first_order_is_not_what_is_read(
        self, prc: ModuleType, tmp_path: Path
    ) -> None:
        """The other half of the claim above.

        Reading the same bytes in the opposite order produces characters
        from a different part of Unicode entirely, so a sweep that got
        the byte order wrong would find nothing here -- and, worse,
        would find nothing in the file above either.
        """
        path = tmp_path / "utf16le.pdf"
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            pdf.Root["/Marker"] = pdf.make_indirect(
                pdf.make_stream(SECRET.encode("utf-16-le"))
            )
            pdf.save(path)
        with pikepdf.open(path) as pdf:
            report = prc.Report(path=path)
            prc.check_raw_objects(pdf, report, [SECRET])
            assert report.findings == []


class TestMetadataEdges:
    """Metadata may be absent, empty, or unreadable."""

    def test_document_without_metadata(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            assert prc.extract_metadata(pdf) == []

    def test_unreadable_xmp_yields_no_extract(
        self, prc: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with pikepdf.new() as pdf:
            stream = pdf.make_stream(b"<x:xmpmeta/>")
            pdf.Root["/Metadata"] = pdf.make_indirect(stream)

            def explode(*args, **kwargs):
                raise pikepdf.PdfError("cannot read")

            monkeypatch.setattr(type(stream), "read_bytes", explode)
            assert prc.extract_metadata(pdf) == []

    @pytest.mark.parametrize("failure", [pikepdf.PdfError, zlib.error])
    def test_unreadable_xmp_is_reported_to_whoever_is_collecting(
        self,
        prc: ModuleType,
        monkeypatch: pytest.MonkeyPatch,
        failure: type[Exception],
    ) -> None:
        """A metadata packet nobody could read is not absent metadata.

        Silence here is the failure this tool is about: a document whose
        whole XMP packet went uninspected reads exactly like a document
        with nothing in it. Both ways a stream refuses -- a structural
        fault and damaged compressed data -- have to say so.
        """
        with pikepdf.new() as pdf:
            stream = pdf.make_stream(b"<x:xmpmeta/>")
            packet = pdf.make_indirect(stream)
            pdf.Root["/Metadata"] = packet
            number = packet.objgen[0]

            def explode(*args, **kwargs):
                raise failure("cannot read")

            monkeypatch.setattr(type(stream), "read_bytes", explode)
            report = prc.Report(path=Path("x.pdf"))
            assert prc.extract_metadata(pdf, report) == []
        assert len(report.findings) == 1
        finding = report.findings[0]
        assert finding.severity is prc.Severity.WARNING
        assert finding.check == prc.METADATA
        assert "XMP metadata packet could not be read" in finding.detail
        assert finding.location == f"object {number} 0"

    def test_a_document_whose_xmp_cannot_be_read_is_not_clean(
        self, prc: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """End to end, on the run nobody passes an argument to."""
        path = tmp_path / "broken_xmp.pdf"
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            stream = pdf.make_stream(b"<x:xmpmeta/>")
            stream["/Type"] = pikepdf.Name("/Metadata")
            pdf.Root["/Metadata"] = pdf.make_indirect(stream)
            pdf.save(path)

        def explode(*args, **kwargs):
            raise pikepdf.DataDecodingError("cannot decode")

        with pikepdf.open(path) as pdf:
            monkeypatch.setattr(type(pdf.Root["/Metadata"]), "read_bytes", explode)
            report, _ = prc.analyze(path, [])
        metadata = [
            f
            for f in report.findings
            if f.check == prc.METADATA and f.severity is prc.Severity.WARNING
        ]
        assert len(metadata) == 1
        assert "XMP metadata packet could not be read" in metadata[0].detail
        assert prc.verdict_code(report) == prc.EXIT_SUSPICIOUS

    def test_a_readable_xmp_packet_is_not_reported_as_a_problem(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The other half: only the unreadable packet earns a warning."""
        report, _ = prc.analyze(fixtures / "xmp.pdf", [])
        assert not [f for f in report.findings if "could not be read" in f.detail]
        assert prc.verdict_code(report) == prc.EXIT_CLEAN

    def test_an_empty_xmp_packet_yields_no_extract(self, prc: ModuleType) -> None:
        """A packet with nothing but spaces in it holds no metadata."""
        with pikepdf.new() as pdf:
            stream = pdf.make_stream(b"   \n")
            pdf.Root["/Metadata"] = pdf.make_indirect(stream)
            report = prc.Report(path=Path("x.pdf"))
            assert prc.extract_metadata(pdf, report) == []
        assert report.findings == []

    def test_blank_docinfo_values_are_dropped(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            pdf.trailer["/Info"] = pdf.make_indirect(
                pikepdf.Dictionary(Title=pikepdf.String("   "))
            )
            assert prc.extract_metadata(pdf) == []

    def test_an_info_entry_that_is_not_a_dictionary_is_reported(
        self, prc: ModuleType
    ) -> None:
        """Document properties nobody could read are not absent properties."""
        with pikepdf.new() as pdf:
            pdf.trailer["/Info"] = pdf.make_indirect(
                pikepdf.String("not a dictionary at all")
            )
            report = prc.Report(path=Path("x.pdf"))
            prc.check_metadata(pdf, report)
            assert prc.extract_metadata(pdf) == []
        assert len(report.findings) == 1
        assert report.findings[0].severity is prc.Severity.WARNING
        assert report.findings[0].check == prc.METADATA
        assert "is not a dictionary" in report.findings[0].detail

    def test_a_normal_info_entry_is_not_reported_as_a_problem(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The other half: only the malformed entry earns a warning."""
        report, _ = prc.analyze(fixtures / "clean.pdf", [])
        assert not [f for f in report.findings if "is not a dictionary" in f.detail]


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

    def test_the_sweep_reports_text_no_other_layer_claims(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """A bookmark title has no dedicated check, so the sweep is it."""
        with pikepdf.open(fixtures / "outline.pdf") as pdf:
            visible = prc.extract_page_text(pdf)
            extracts = prc.collect_extracts(pdf, visible)
        swept = {e.text for e in extracts if e.layer == prc.RAW_STRINGS}
        assert f"Correspondence about {SECRET}" in swept

    def test_raw_sweep_does_not_repeat_a_dedicated_layer(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """Both halves: the sweep found things, and none of them repeat.

        The DocInfo values of `outline.pdf` are string objects like any
        other, so an undeduplicated sweep would report them a second
        time. An empty sweep would satisfy the disjointness on its own,
        which is why the bookmark title has to be in it.
        """
        with pikepdf.open(fixtures / "outline.pdf") as pdf:
            visible = prc.extract_page_text(pdf)
            extracts = prc.collect_extracts(pdf, visible)
        claimed = {e.text for e in extracts if e.layer != prc.RAW_STRINGS}
        swept = {e.text for e in extracts if e.layer == prc.RAW_STRINGS}
        assert "anonymous" in claimed  # DocInfo /Author, a dedicated layer
        assert f"Correspondence about {SECRET}" in swept
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
        self, prc: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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
        self, prc: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        assert prc.check_output_path(Path("out.txt"), Path("doc.pdf"), False) is None
