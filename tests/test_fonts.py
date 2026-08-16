# SPDX-FileCopyrightText: 2026 Sean Whalen
# SPDX-License-Identifier: MIT
"""Tests for reading a font's declared character set.

Every shape of font dictionary lives in the `font_variants.pdf` sample:
/Differences glyph names, /Widths with a simple encoding, a Type 1
/CharSet list, and a Type 0 font whose characters sit on a descendant.
"""

from __future__ import annotations

import string
import unicodedata
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pikepdf
import pytest
from reportlab.pdfbase._fontdata import encodings as reportlab_encodings

SECRET = "742 Evergreen Terrace"

# The three encodings the tool's standard glyph names come from, in the
# order it resolves a name that more than one of them uses.
ENCODING_ORDER = ("StandardEncoding", "WinAnsiEncoding", "MacRomanEncoding")


@pytest.fixture
def fonts(prc: ModuleType, fixtures: Path) -> Iterator[dict[str, pikepdf.Object]]:
    """Every font resource in the font_variants sample, by label."""
    with pikepdf.open(fixtures / "font_variants.pdf") as pdf:
        yield {label: font for label, font in prc.iter_fonts(pdf)}


class TestGlyphNames:
    """Glyph names reach characters by four different routes."""

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("z", "z"),  # already a character
            ("uni0037", "7"),  # uniXXXX
            ("u0034", "4"),  # uXXXX
            # The standard names of ISO 32000 Annex D: the ones a real
            # producer writes for anything that is not a letter.
            ("seven", "7"),
            ("space", " "),
            ("period", "."),
            ("comma", ","),
            ("quoteright", "’"),
            ("bullet", "•"),
            # A Unicode character name, for a glyph outside the three
            # encodings the standard-name table covers.
            ("infinity", "∞"),
        ],
    )
    def test_resolvable_names(self, prc: ModuleType, name: str, expected: str) -> None:
        assert prc.glyph_name_to_char(name) == expected

    @pytest.mark.parametrize(
        "name",
        [
            "notaglyphname",
            "uniZZZZ",
            "u110000",
            # Adobe's convention gives uni exactly four digits. A longer
            # name is groups of four, one character each, so reading the
            # extra digits as part of the first invents a character the
            # font never named: /uni004100 is not U+004100.
            "uni004100",
            "uni00410042",
        ],
    )
    def test_unresolvable_names(self, prc: ModuleType, name: str) -> None:
        assert prc.glyph_name_to_char(name) is None

    def test_the_u_form_is_the_one_that_takes_more_than_four_digits(
        self, prc: ModuleType
    ) -> None:
        """Both halves of the digit rule, on the same code point.

        The u form spells a code point out in four to six digits, so a
        character outside the basic range has a name in that form and no
        legitimate one in the uni form.
        """
        assert prc.glyph_name_to_char("u1F600") == "\U0001f600"
        assert prc.glyph_name_to_char("uni1F600") is None

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("hyphen", "-"),  # not U+2010, the character Unicode calls HYPHEN
            ("tilde", "˜"),  # the accent, not the ASCII squiggle
            ("ring", "˚"),  # the accent, not the piece of jewellery
        ],
    )
    def test_a_standard_name_wins_over_the_unicode_name_of_the_same_word(
        self, prc: ModuleType, name: str, expected: str
    ) -> None:
        """Both halves: the standard names are used, and they differ here.

        These three words name one character in ISO 32000 Annex D and a
        different one in Unicode, so the order the two tables are
        consulted in is observable -- and getting it wrong puts a
        character on the page that the document never drew.
        """
        assert unicodedata.lookup(name.upper()) != expected
        assert prc.glyph_name_to_char(name) == expected

    def test_the_standard_names_are_exactly_the_three_encodings(
        self, prc: ModuleType
    ) -> None:
        """Rebuild the table from the same encodings, named elsewhere.

        The names in `GLYPH_NAMES` were written out by hand, and a
        wrong character in a table of that size is invisible to a
        reader. reportlab carries its own code-to-name list for each of
        the three encodings, so pairing those names with the characters
        this tool's own code-to-character tables put at the same codes
        re-derives the whole mapping. For WinAnsiEncoding and
        MacRomanEncoding those characters come from Python's own codecs,
        which makes this a second source; for StandardEncoding they come
        from the tool's hand-written table, so what is checked there is
        which name sits at which code, not the table itself.

        A name that sits at two codes -- /space, /hyphen, /bullet -- is
        kept from the first encoding that names it, which is the order
        the tool's own comment gives.
        """
        expected: dict[str, str] = {}
        for encoding in ENCODING_ORDER:
            chars = prc.BASE_ENCODINGS[f"/{encoding}"]
            for code, name in enumerate(reportlab_encodings[encoding]):
                char = chars.get(code)
                if name and char is not None:
                    expected.setdefault(name, char)
        assert expected
        assert prc.GLYPH_NAMES == expected

    def test_every_letter_is_its_own_glyph_name(self, prc: ModuleType) -> None:
        assert all(prc.GLYPH_NAMES[letter] == letter for letter in string.ascii_letters)


class TestFontCharsets:
    """Each source of glyph information is read, in document order."""

    def test_differences_array(
        self, prc: ModuleType, fonts: dict[str, pikepdf.Object]
    ) -> None:
        """One name per route, and the unresolvable one contributes none."""
        assert prc.font_charset(fonts["page 1 /FDiff"]) == ["z", "7", "4", "’", "∞"]

    def test_widths_skip_zero_width_codes(
        self, prc: ModuleType, fonts: dict[str, pikepdf.Object]
    ) -> None:
        charset = prc.font_charset(fonts["page 1 /FWidth"])
        # /FirstChar 90 with widths [500, 0, 500] covers Z and backslash;
        # the zero-width code between them draws nothing.
        assert charset == ["Z", "\\"]

    def test_type1_charset_list(
        self, prc: ModuleType, fonts: dict[str, pikepdf.Object]
    ) -> None:
        assert prc.font_charset(fonts["page 1 /FCharSet"]) == ["q", "9"]

    def test_descendant_fonts_are_followed(
        self, prc: ModuleType, fonts: dict[str, pikepdf.Object]
    ) -> None:
        assert prc.font_charset(fonts["page 1 /FType0"]) == ["w"]

    def test_base14_font_declares_nothing(
        self, prc: ModuleType, fonts: dict[str, pikepdf.Object]
    ) -> None:
        assert prc.font_charset(fonts["page 1 /F1"]) == []


class TestWidthsEncodings:
    """/Widths is only meaningful for encodings we can decode."""

    def test_unknown_encoding_yields_nothing(self, prc: ModuleType) -> None:
        font = pikepdf.Dictionary(
            FirstChar=65,
            Widths=[500],
            Encoding=pikepdf.Name("/Identity-H"),
        )
        assert prc.widths_charset(font) == []

    def test_missing_widths_yields_nothing(self, prc: ModuleType) -> None:
        font = pikepdf.Dictionary(Encoding=pikepdf.Name("/WinAnsiEncoding"))
        assert prc.widths_charset(font) == []

    def test_mac_roman_is_decoded(self, prc: ModuleType) -> None:
        font = pikepdf.Dictionary(
            FirstChar=65,
            Widths=[500, 500],
            Encoding=pikepdf.Name("/MacRomanEncoding"),
        )
        assert prc.widths_charset(font) == ["A", "B"]

    def test_undefined_code_points_are_skipped(self, prc: ModuleType) -> None:
        # 0x81 is unassigned in cp1252, so it cannot become a character.
        font = pikepdf.Dictionary(
            FirstChar=0x81,
            Widths=[500],
            Encoding=pikepdf.Name("/WinAnsiEncoding"),
        )
        assert prc.widths_charset(font) == []

    def test_codes_past_the_byte_range_are_skipped(self, prc: ModuleType) -> None:
        font = pikepdf.Dictionary(
            FirstChar=254,
            Widths=[500, 500, 500, 500],
            Encoding=pikepdf.Name("/WinAnsiEncoding"),
        )
        # 254 and 255 decode as thorn and y-diaeresis; 256 and beyond are
        # not byte codes at all.
        assert prc.widths_charset(font) == ["þ", "ÿ"]


class TestDescriptorCharset:
    """A missing or malformed /CharSet is not an error."""

    def test_absent_descriptor(self, prc: ModuleType) -> None:
        assert prc.descriptor_charset(None) == []

    def test_descriptor_without_charset(self, prc: ModuleType) -> None:
        assert prc.descriptor_charset(pikepdf.Dictionary()) == []

    def test_charset_that_is_not_a_string(self, prc: ModuleType) -> None:
        descriptor = pikepdf.Dictionary(CharSet=pikepdf.Name("/q"))
        assert prc.descriptor_charset(descriptor) == []


class TestToUnicodeRanges:
    """bfrange blocks expand into every character they cover."""

    def test_range_expands(self, prc: ModuleType) -> None:
        data = b"beginbfrange <01> <03> <0041> endbfrange"
        assert prc.parse_tounicode(data) == ["A", "B", "C"]

    def test_reversed_range_is_ignored(self, prc: ModuleType) -> None:
        data = b"beginbfrange <05> <01> <0041> endbfrange"
        assert prc.parse_tounicode(data) == []

    def test_absurd_range_is_ignored(self, prc: ModuleType) -> None:
        data = b"beginbfrange <000000> <FFFFFFFF> <0041> endbfrange"
        assert prc.parse_tounicode(data) == []

    def test_ranges_follow_chars_in_order(self, prc: ModuleType) -> None:
        data = (
            b"beginbfchar <01> <007A> endbfchar "
            b"beginbfrange <02> <03> <0041> endbfrange"
        )
        assert prc.parse_tounicode(data) == ["z", "A", "B"]

    def test_odd_length_value_is_padded(self, prc: ModuleType) -> None:
        assert prc.decode_utf16be(b"\x00") == "\x00"

    def test_empty_destination_is_skipped(self, prc: ModuleType) -> None:
        data = b"beginbfrange <01> <02> <> endbfrange"
        assert prc.parse_tounicode(data) == []

    def test_destination_that_decodes_to_nothing(self, prc: ModuleType) -> None:
        # A lone surrogate decodes away entirely under errors="ignore".
        data = b"beginbfrange <01> <02> <D800> endbfrange"
        assert prc.parse_tounicode(data) == []

    def test_codepoints_past_unicode_are_dropped(self, prc: ModuleType) -> None:
        # <DBFF DFFF> is U+10FFFF, the last legal code point, so every
        # later offset in the range falls off the end of Unicode.
        data = b"beginbfrange <01> <03> <DBFFDFFF> endbfrange"
        assert prc.parse_tounicode(data) == ["\U0010ffff"]

    def test_odd_length_destination_is_padded(self, prc: ModuleType) -> None:
        """ISO 32000 section 7.3.4.3: a missing final digit is a zero.

        '041' is three hex digits, so it stands for the bytes 04 10 --
        U+0410, a Cyrillic capital A. Treating it as an error would
        throw away every mapping in the rest of the CMap along with it.
        """
        data = b"beginbfrange <01> <03> <041> endbfrange"
        assert prc.parse_tounicode(data) == ["А", "Б", "В"]

    def test_an_odd_length_source_code_is_padded_too(self, prc: ModuleType) -> None:
        data = b"beginbfchar <4> <0041> endbfchar"
        assert prc.parse_tounicode_map(data).entries == [(0x40, "A")]

    def test_unreadable_tounicode_is_ignored(
        self, prc: ModuleType, fixtures: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with pikepdf.open(fixtures / "orphan_font.pdf") as pdf:
            font = dict(prc.iter_fonts(pdf))["page 1 /F1"]
            stream_type = type(font["/ToUnicode"])

            def explode(*args, **kwargs):
                raise pikepdf.PdfError("cannot read CMap")

            monkeypatch.setattr(stream_type, "read_bytes", explode)
            assert prc.font_charset(font) == []


class TestCMapBrackets:
    """A bfrange may give one destination per code, inside brackets."""

    def test_an_array_gives_one_destination_per_code(self, prc: ModuleType) -> None:
        data = b"beginbfrange <01> <03> [<0041> <005A> <0043>] endbfrange"
        assert prc.parse_tounicode_map(data).entries == [(1, "A"), (2, "Z"), (3, "C")]

    def test_the_brackets_are_what_keep_the_pairing_right(
        self, prc: ModuleType
    ) -> None:
        """The other half of the claim above.

        Reading those same hex strings without regard for the brackets
        pairs the first one with the whole range and counts upwards from
        it, which invents a B nobody mapped and loses the Z.
        """
        data = b"beginbfrange <01> <03> [<0041> <005A> <0043>] endbfrange"
        assert prc.parse_tounicode(data) != ["A", "B", "C"]

    def test_an_array_shorter_than_the_range_stops_where_it_ends(
        self, prc: ModuleType
    ) -> None:
        data = b"beginbfrange <01> <04> [<0041> <0042>] endbfrange"
        assert prc.parse_tounicode_map(data).entries == [(1, "A"), (2, "B")]

    def test_an_empty_entry_in_an_array_maps_nothing(self, prc: ModuleType) -> None:
        data = b"beginbfrange <01> <03> [<0041> <> <0043>] endbfrange"
        assert prc.parse_tounicode_map(data).entries == [(1, "A"), (3, "C")]

    @pytest.mark.parametrize(
        "data",
        [
            b"beginbfchar [<01>] <0041> endbfchar",  # a bracketed code
            b"beginbfchar <01> [<0041>] endbfchar",  # a bracketed destination
            b"beginbfchar <> <0041> endbfchar",  # no code at all
            b"beginbfchar <01> <> endbfchar",  # nothing to map it to
        ],
    )
    def test_a_malformed_bfchar_entry_maps_nothing(
        self, prc: ModuleType, data: bytes
    ) -> None:
        assert prc.parse_tounicode(data) == []

    @pytest.mark.parametrize(
        "data",
        [
            b"beginbfrange [<01>] <03> <0041> endbfrange",  # bracketed low bound
            b"beginbfrange <01> [<03>] <0041> endbfrange",  # bracketed high bound
            b"beginbfrange <> <03> <0041> endbfrange",  # no low bound
            b"beginbfrange <01> <> <0041> endbfrange",  # no high bound
        ],
    )
    def test_a_malformed_bfrange_entry_maps_nothing(
        self, prc: ModuleType, data: bytes
    ) -> None:
        assert prc.parse_tounicode(data) == []

    def test_a_malformed_entry_does_not_take_the_rest_of_the_cmap_with_it(
        self, prc: ModuleType
    ) -> None:
        data = b"beginbfchar <> <0041> endbfchar beginbfchar <02> <007A> endbfchar"
        assert prc.parse_tounicode(data) == ["z"]


class TestDifferencesArrays:
    """/Differences alternates a starting code with the names after it."""

    @pytest.mark.parametrize("value", [None, pikepdf.Name("/WinAnsiEncoding")])
    def test_anything_that_is_not_an_array_maps_nothing(
        self, prc: ModuleType, value: pikepdf.Object | None
    ) -> None:
        assert prc.differences_entries(value) == []

    def test_a_name_that_resolves_to_nothing_still_advances_the_code(
        self, prc: ModuleType
    ) -> None:
        array = pikepdf.Array([65, pikepdf.Name("/notaglyphname"), pikepdf.Name("/B")])
        # /B is the second name after 65, so it belongs at 66, not 65.
        assert prc.differences_entries(array) == [(66, "B")]

    def test_an_entry_that_is_neither_a_code_nor_a_name_stops_the_array(
        self, prc: ModuleType
    ) -> None:
        """Everything after it would be positioned by guesswork."""
        array = pikepdf.Array(
            [
                65,
                pikepdf.Name("/A"),
                pikepdf.String("not a code or a glyph name"),
                pikepdf.Name("/Z"),
            ]
        )
        assert prc.differences_entries(array) == [(65, "A")]


class TestCodeWidths:
    """How many bytes one character code takes depends on the font."""

    def test_a_simple_font_always_uses_one_byte(self, prc: ModuleType) -> None:
        font = pikepdf.Dictionary(Subtype=pikepdf.Name("/Type1"))
        assert prc.font_code_bytes(font, None) == 1

    def test_a_composite_font_reads_its_own_encoding_cmap(
        self, prc: ModuleType
    ) -> None:
        with pikepdf.new() as pdf:
            encoding = pdf.make_stream(
                b"1 begincodespacerange <00> <FF> endcodespacerange"
            )
            font = pikepdf.Dictionary(Subtype=pikepdf.Name("/Type0"), Encoding=encoding)
            assert prc.font_code_bytes(font, None) == 1

    def test_an_encoding_cmap_that_declares_nothing_is_not_believed(
        self, prc: ModuleType
    ) -> None:
        with pikepdf.new() as pdf:
            encoding = pdf.make_stream(b"begincmap endcmap")
            font = pikepdf.Dictionary(Subtype=pikepdf.Name("/Type0"), Encoding=encoding)
            assert prc.font_code_bytes(font, None) == 2

    def test_an_unreadable_encoding_cmap_is_not_fatal(
        self, prc: ModuleType, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        with pikepdf.new() as pdf:
            encoding = pdf.make_stream(b"1 begincodespacerange <00> <FF>")

            def explode(*args, **kwargs):
                raise pikepdf.PdfError("cannot read the CMap")

            monkeypatch.setattr(type(encoding), "read_bytes", explode)
            font = pikepdf.Dictionary(Subtype=pikepdf.Name("/Type0"), Encoding=encoding)
            assert prc.font_code_bytes(font, None) == 2

    def test_identity_h_falls_back_to_the_tounicode_codespace(
        self, prc: ModuleType
    ) -> None:
        cmap = prc.parse_tounicode_map(
            b"1 begincodespacerange <00> <FF> endcodespacerange"
        )
        font = pikepdf.Dictionary(
            Subtype=pikepdf.Name("/Type0"), Encoding=pikepdf.Name("/Identity-H")
        )
        assert prc.font_code_bytes(font, cmap) == 1

    def test_a_composite_font_that_says_nothing_is_read_as_two_bytes(
        self, prc: ModuleType
    ) -> None:
        font = pikepdf.Dictionary(
            Subtype=pikepdf.Name("/Type0"), Encoding=pikepdf.Name("/Identity-H")
        )
        assert prc.font_code_bytes(font, None) == 2

    def test_the_committed_identity_h_sample_uses_two_bytes(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        with pikepdf.open(fixtures / "identity_h.pdf") as pdf:
            fonts = dict(prc.iter_fonts(pdf))
            composite = fonts["page 1 /FCID"]
            assert prc.font_code_bytes(composite, prc.read_tounicode(composite)) == 2
            assert prc.font_code_bytes(fonts["page 1 /F1"], None) == 1


class TestSimpleFontTables:
    """A simple font's /Encoding decides what its codes draw."""

    def test_a_named_base_encoding_is_used(self, prc: ModuleType) -> None:
        font = pikepdf.Dictionary(Encoding=pikepdf.Name("/WinAnsiEncoding"))
        # 0x93 is a left double quotation mark in WinAnsi and undefined
        # in Adobe's StandardEncoding.
        assert prc.simple_font_table(font)[0x93] == "“"

    def test_an_unknown_base_encoding_falls_back_to_standard(
        self, prc: ModuleType
    ) -> None:
        font = pikepdf.Dictionary(Encoding=pikepdf.Name("/Identity-H"))
        table = prc.simple_font_table(font)
        assert table[0x27] == "’"  # StandardEncoding, not an apostrophe
        assert 0x93 not in table

    def test_a_font_with_no_encoding_falls_back_to_standard(
        self, prc: ModuleType
    ) -> None:
        assert prc.simple_font_table(pikepdf.Dictionary())[0x60] == "‘"

    def test_differences_are_applied_over_the_named_base(self, prc: ModuleType) -> None:
        font = pikepdf.Dictionary(
            Encoding=pikepdf.Dictionary(
                BaseEncoding=pikepdf.Name("/WinAnsiEncoding"),
                Differences=[65, pikepdf.Name("/bullet")],
            )
        )
        table = prc.simple_font_table(font)
        assert table[65] == "•"  # the difference
        assert table[0x93] == "“"  # the base underneath it

    def test_differences_are_applied_over_standard_when_no_base_is_named(
        self, prc: ModuleType
    ) -> None:
        font = pikepdf.Dictionary(
            Encoding=pikepdf.Dictionary(Differences=[65, pikepdf.Name("/bullet")])
        )
        table = prc.simple_font_table(font)
        assert table[65] == "•"
        assert table[66] == "B"  # StandardEncoding underneath it
        assert 0x93 not in table


class TestFontDecoder:
    """Character codes become text, or are counted as unreadable."""

    def test_unmapped_codes_contribute_nothing_to_the_text(
        self, prc: ModuleType
    ) -> None:
        """A placeholder would put characters on the page that the page
        never drew, which is what the font-subset check compares
        against."""
        decoder = prc.FontDecoder("/F1", 1, {65: "A"})
        assert decoder.decode(b"A\x01B") == ("A", 2)

    def test_two_byte_codes_are_read_two_bytes_at_a_time(self, prc: ModuleType) -> None:
        decoder = prc.FontDecoder("/FCID", 2, {1: "7", 2: "4"})
        assert decoder.decode(b"\x00\x01\x00\x02") == ("74", 0)


class TestFontOrphans:
    """Orphans are the declared characters that never appear on the page."""

    def test_fonts_declaring_nothing_are_skipped(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        with pikepdf.open(fixtures / "font_variants.pdf") as pdf:
            labels = [label for label, _ in prc.font_orphans(pdf, "")]
        assert "page 1 /F1" not in labels  # base-14, declares nothing

    def test_declared_but_unseen_characters_are_reported(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        with pikepdf.open(fixtures / "font_variants.pdf") as pdf:
            orphans = dict(prc.font_orphans(pdf, "quick"))
        # 'q' is on the page in this call, so only '9' survives as an orphan.
        assert orphans["page 1 /FCharSet"] == ["9"]

    def test_fonts_with_no_orphans_are_not_reported(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        with pikepdf.open(fixtures / "font_variants.pdf") as pdf:
            # /FType0 declares only 'w', which is on the page in this call.
            labels = [label for label, _ in prc.font_orphans(pdf, "w")]
        assert "page 1 /FType0" not in labels

    def test_pages_without_fonts_are_skipped(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            pdf.add_blank_page()
            assert list(prc.iter_fonts(pdf)) == []


class TestFormResourceFonts:
    """Walking into a form's own resources is bounded and does not loop."""

    def test_a_form_that_names_itself_terminates(self, prc: ModuleType) -> None:
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            form = pdf.make_stream(b"BT /FForm 12 Tf (x) Tj ET")
            form["/Type"] = pikepdf.Name("/XObject")
            form["/Subtype"] = pikepdf.Name("/Form")
            form["/BBox"] = [0, 0, 10, 10]
            form = pdf.make_indirect(form)
            form["/Resources"] = pikepdf.Dictionary(
                Font=pikepdf.Dictionary(
                    FForm=pikepdf.Dictionary(
                        Type=pikepdf.Name("/Font"),
                        Subtype=pikepdf.Name("/Type1"),
                        BaseFont=pikepdf.Name("/Helvetica"),
                    )
                ),
                XObject=pikepdf.Dictionary(Fm0=form),
            )
            page.Resources = pikepdf.Dictionary(
                XObject=pikepdf.Dictionary(Fm0=form),
            )
            labels = [label for label, _ in prc.iter_fonts(pdf)]
        assert labels == ["page 1 /Fm0 /FForm"]

    def test_the_depth_limit_stops_the_walk(self, prc: ModuleType) -> None:
        """Forms nest, so this walk is bounded like the others."""
        resources = pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=pikepdf.Dictionary()))
        assert list(prc.resource_fonts(resources, "page 1 ", set(), depth=65)) == []


def font_declaring(pdf: pikepdf.Pdf, name: str, first: int, count: int) -> None:
    """Add a font resource that declares `count` consecutive characters."""
    pdf.pages[0]["/Resources"]["/Font"][name] = pdf.make_indirect(
        pikepdf.Dictionary(
            Type=pikepdf.Name("/Font"),
            Subtype=pikepdf.Name("/TrueType"),
            BaseFont=pikepdf.Name("/Arial"),
            Encoding=pikepdf.Name("/WinAnsiEncoding"),
            FirstChar=first,
            Widths=[500] * count,
        )
    )


class TestOrphanSeverity:
    """How alarming a pile of orphaned characters is depends on its size."""

    def test_a_short_list_is_a_warning_and_a_longer_one_is_critical(
        self, prc: ModuleType
    ) -> None:
        """Both sides of the threshold, in one document.

        A couple of stray characters is weak evidence -- fonts carry
        unused glyphs for innocent reasons. Three or more that the page
        never draws is the shape of a removed passage.
        """
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            page["/Resources"] = pikepdf.Dictionary(Font=pikepdf.Dictionary())
            font_declaring(pdf, "/FTwo", ord("a"), 2)
            font_declaring(pdf, "/FThree", ord("x"), 3)
            report = prc.Report(path=Path("x.pdf"))
            prc.check_fonts(pdf, report, visible_text="")
        by_location = {f.location: f for f in report.findings}
        assert by_location["page 1 /FTwo"].severity is prc.Severity.WARNING
        assert "2 character(s)" in by_location["page 1 /FTwo"].detail
        assert by_location["page 1 /FThree"].severity is prc.Severity.CRITICAL
        assert "3 character(s)" in by_location["page 1 /FThree"].detail

    def test_the_committed_corpus_covers_both_sides(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """A sample for each, so neither side is only ever asserted in
        a document this suite built for itself."""
        warned, _ = prc.analyze(fixtures / "broken_fonts.pdf", [])
        failed, _ = prc.analyze(fixtures / "orphan_font.pdf", [])
        assert prc.verdict_code(warned) == prc.EXIT_SUSPICIOUS
        assert prc.verdict_code(failed) == prc.EXIT_RECOVERABLE


class TestUnreadableFontDictionaries:
    """A font this cannot read all the way says so."""

    def test_the_problems_reach_the_report(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        report, _ = prc.analyze(fixtures / "broken_fonts.pdf", [])
        details = {f.location: f.detail for f in report.findings}
        assert "/FirstChar is not a number" in details["page 1 /FBadFirstChar"]

    def test_an_unreadable_widths_entry_is_named(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        report, _ = prc.analyze(fixtures / "broken_fonts.pdf", [])
        problems = [
            f
            for f in report.findings
            if f.location == "page 1 /FBadWidth" and "/Widths entry" in f.detail
        ]
        assert len(problems) == 1
        assert "entry 1 is not a number" in problems[0].detail
        assert problems[0].severity is prc.Severity.WARNING

    def test_a_font_listed_as_its_own_descendant_terminates(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        with pikepdf.open(fixtures / "broken_fonts.pdf") as pdf:
            looped = dict(prc.iter_fonts(pdf))["page 1 /FLoop"]
            assert prc.font_charset(looped) == []

    def test_a_descendant_that_is_not_a_font_dictionary_is_reported(
        self, prc: ModuleType
    ) -> None:
        """Hostile input: an array holds whatever it was given.

        pikepdf hands a number in an array back as a plain int, which
        has none of the methods a font is read with, so recursing into
        one used to end the run in a traceback.
        """
        font = pikepdf.Dictionary(
            Type=pikepdf.Name("/Font"),
            Subtype=pikepdf.Name("/Type0"),
            BaseFont=pikepdf.Name("/ABCDEF+Song"),
            Encoding=pikepdf.Name("/Identity-H"),
            DescendantFonts=pikepdf.Array([1, pikepdf.String("not a font")]),
        )
        problems: list[str] = []
        assert prc.font_charset(font, problems) == []
        assert len(problems) == 2
        assert all("not a font dictionary" in problem for problem in problems)

    def test_descendant_fonts_that_is_not_an_array_is_reported(
        self, prc: ModuleType
    ) -> None:
        """The entry is required to be an array, so a font that gives
        something else is malformed rather than empty.

        Staying silent here would say "this composite font declares no
        characters", when the truth is that nobody looked.
        """
        font = pikepdf.Dictionary(
            Type=pikepdf.Name("/Font"),
            Subtype=pikepdf.Name("/Type0"),
            BaseFont=pikepdf.Name("/ABCDEF+Song"),
            Encoding=pikepdf.Name("/Identity-H"),
            DescendantFonts=pikepdf.String("not an array"),
        )
        problems: list[str] = []
        assert prc.font_charset(font, problems) == []
        assert len(problems) == 1
        assert "not an array" in problems[0]

    def test_a_font_with_no_descendants_reports_nothing(self, prc: ModuleType) -> None:
        """The negative half: a font that simply omits the entry is not
        malformed, so it must not produce the warning above."""
        font = pikepdf.Dictionary(
            Type=pikepdf.Name("/Font"),
            Subtype=pikepdf.Name("/Type1"),
            BaseFont=pikepdf.Name("/Helvetica"),
        )
        problems: list[str] = []
        assert prc.font_charset(font, problems) == []
        assert problems == []

    def test_a_font_that_could_not_be_read_is_not_reported_as_empty(
        self, prc: ModuleType, fixtures: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A silent empty charset would read as "this font declares
        nothing", which is the opposite of what happened."""
        with pikepdf.open(fixtures / "orphan_font.pdf") as pdf:
            font = dict(prc.iter_fonts(pdf))["page 1 /F1"]
            stream_type = type(font["/ToUnicode"])

            def explode(*args, **kwargs):
                raise pikepdf.PdfError("cannot read CMap")

            monkeypatch.setattr(stream_type, "read_bytes", explode)
            problems: list[str] = []
            assert prc.font_charset(font, problems) == []
        assert len(problems) == 1
        assert "/ToUnicode CMap could not be read" in problems[0]


class TestDecodedPageText:
    """The page's own fonts are what say what its codes spell."""

    def test_a_differences_array_is_what_makes_the_page_legible(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The codes drawn on this page mean nothing without it.

        Read through StandardEncoding they are control characters, so a
        reader that ignored /Differences would recover no address at all
        -- and would then report the font's own characters as orphans.

        The array names the characters the way a producer does, so this
        also proves the standard names resolve: drop them and the digits
        fall out of the recovered address.
        """
        with pikepdf.open(fixtures / "differences.pdf") as pdf:
            font = dict(prc.iter_fonts(pdf))["page 1 /FDiff"]
            named = {
                str(item)
                for item in font["/Encoding"]["/Differences"]
                if isinstance(item, pikepdf.Name)
            }
            assert {"/seven", "/four", "/two", "/space"} <= named
            visible = prc.extract_page_text(pdf)
            assert SECRET in visible
            assert list(prc.font_orphans(pdf, visible)) == []

    def test_two_byte_codes_are_decoded_through_the_composite_font(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        with pikepdf.open(fixtures / "identity_h.pdf") as pdf:
            visible = prc.extract_page_text(pdf)
            assert SECRET in visible
            assert list(prc.font_orphans(pdf, visible)) == []

    def test_text_drawn_inside_a_form_is_not_a_removed_passage(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The false-positive case, on the committed sample.

        `form_xobject.pdf` draws four characters inside a Form XObject,
        through a font the page defines. They are on the screen. A
        reader of the page's own content stream that stops at the `Do`
        sees the font declaring four characters the page never drew, and
        reports a plainly visible document as a failed redaction.
        """
        with pikepdf.open(fixtures / "form_xobject.pdf") as pdf:
            visible = prc.extract_page_text(pdf)
            font = dict(prc.iter_fonts(pdf))["page 1 /FOuter"]
            declared = prc.font_charset(font)
            orphans = dict(prc.font_orphans(pdf, visible))
        assert declared == ["¥", "¦", "§", "¨"]
        assert all(char in visible for char in declared)
        assert "page 1 /FOuter" not in orphans

    def test_a_font_only_a_form_names_is_still_inspected(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The other direction: a form's own resources are searched too.

        /Fm1 brings resources of its own, naming a font the page never
        names. That font declares a character it does not draw, and
        nothing reaches it without following the form.
        """
        report, _ = prc.analyze(fixtures / "form_xobject.pdf", [])
        fonts = [f for f in report.findings if f.check == prc.FONT_CHARSET]
        assert len(fonts) == 1
        assert fonts[0].location == "page 1 /Fm1 /FInner"
        assert fonts[0].severity is prc.Severity.WARNING
        assert "1 character(s)" in fonts[0].detail
        assert repr("¶") in fonts[0].detail
        assert prc.verdict_code(report) == prc.EXIT_SUSPICIOUS

    def test_a_form_without_resources_does_not_repeat_the_pages_fonts(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """/Fm0 draws with the page's fonts, which are already listed."""
        with pikepdf.open(fixtures / "form_xobject.pdf") as pdf:
            labels = [label for label, _ in prc.iter_fonts(pdf)]
        assert "page 1 /FOuter" in labels
        assert "page 1 /Fm1 /FInner" in labels
        assert not [label for label in labels if label.startswith("page 1 /Fm0 ")]
        assert len(labels) == len(set(labels))

    def test_curly_quotes_are_read_as_quotes(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The false-positive case.

        In WinAnsiEncoding the typographic quotes are bytes 0x91 to
        0x94. Decoding the page through the wrong table turns them into
        control characters, and the four quotes the font declares then
        look like leftovers of a removed passage.
        """
        with pikepdf.open(fixtures / "smart_quotes.pdf") as pdf:
            visible = prc.extract_page_text(pdf)
            font = dict(prc.iter_fonts(pdf))["page 1 /F1"]
            assert prc.font_charset(font) == ["‘", "’", "“", "”"]
            assert all(quote in visible for quote in "‘’“”")
            assert list(prc.font_orphans(pdf, visible)) == []
