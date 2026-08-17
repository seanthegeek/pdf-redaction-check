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

    def nested_forms(self, pdf: pikepdf.Pdf, depth: int) -> pikepdf.Object:
        """Return a form `depth` layers of form deep, with a font inside.

        Each layer brings resources of its own, which is what makes the
        walk descend into it, and the font at the bottom is the thing
        that is only reached by walking all the way down.
        """
        stream = pdf.make_stream(b"BT /FDeep 12 Tf (deep) Tj ET")
        stream["/Type"] = pikepdf.Name("/XObject")
        stream["/Subtype"] = pikepdf.Name("/Form")
        stream["/BBox"] = [0, 0, 10, 10]
        stream["/Resources"] = pikepdf.Dictionary(
            Font=pikepdf.Dictionary(
                FDeep=pikepdf.Dictionary(
                    Type=pikepdf.Name("/Font"),
                    Subtype=pikepdf.Name("/Type1"),
                    BaseFont=pikepdf.Name("/Helvetica"),
                )
            )
        )
        inner = pdf.make_indirect(stream)
        for _ in range(depth):
            outer = pdf.make_stream(b"q /Fm Do Q")
            outer["/Type"] = pikepdf.Name("/XObject")
            outer["/Subtype"] = pikepdf.Name("/Form")
            outer["/BBox"] = [0, 0, 10, 10]
            outer["/Resources"] = pikepdf.Dictionary(
                XObject=pikepdf.Dictionary(Fm=inner)
            )
            inner = pdf.make_indirect(outer)
        return inner

    def test_the_depth_limit_stops_the_walk_and_records_it(
        self, prc: ModuleType
    ) -> None:
        """Forms nest, so this walk is bounded like the others.

        A font below the bound is a font whose leftovers nobody looked
        for, so where the walk gave up is recorded rather than passed
        over.
        """
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            page.Resources = pikepdf.Dictionary(
                XObject=pikepdf.Dictionary(
                    Fm0=self.nested_forms(pdf, prc.MAX_DEPTH + 1)
                )
            )
            stops: list[str] = []
            labels = [label for label, _ in prc.iter_fonts(pdf, stops)]
        assert labels == []
        assert len(stops) == 1
        assert stops[0].startswith("object ")

    def test_the_walk_stops_the_same_way_with_nobody_collecting(
        self, prc: ModuleType
    ) -> None:
        """A caller that is not reporting still gets a bounded walk.

        The place it gave up is dropped rather than recorded, exactly as
        an unread font is described only to a caller who asked for the
        descriptions -- but the bound itself is not the collector's job.
        """
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            page.Resources = pikepdf.Dictionary(
                XObject=pikepdf.Dictionary(
                    Fm0=self.nested_forms(pdf, prc.MAX_DEPTH + 1)
                )
            )
            assert list(prc.iter_fonts(pdf)) == []

    def test_a_shallow_nest_is_walked_to_the_bottom(self, prc: ModuleType) -> None:
        """The negative half: the same shape within the limit yields the
        font and records nothing."""
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            page.Resources = pikepdf.Dictionary(
                XObject=pikepdf.Dictionary(Fm0=self.nested_forms(pdf, 2))
            )
            stops: list[str] = []
            labels = [label for label, _ in prc.iter_fonts(pdf, stops)]
        assert labels == ["page 1 /Fm0 /Fm /Fm /FDeep"]
        assert stops == []


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
            prc.check_fonts(pdf, report, "", prc.PageTextCoverage())
        by_location = {f.location: f for f in report.findings}
        assert by_location["page 1 /FTwo"].severity is prc.Severity.WARNING
        assert "2 character(s)" in by_location["page 1 /FTwo"].detail
        assert by_location["page 1 /FThree"].severity is prc.Severity.CRITICAL
        assert "3 character(s)" in by_location["page 1 /FThree"].detail

    def test_a_caller_that_measured_nothing_gets_a_warning_either_way(
        self, prc: ModuleType
    ) -> None:
        """The threshold only applies once the baseline is known to be whole.

        The same two fonts as above, on both sides of the threshold,
        checked against a page text nobody measured: three characters
        absent from a text of unknown extent is not three characters the
        document no longer draws, and neither is two. The test above is
        the control -- same fonts, same empty text, coverage that says
        the pages were read to the end, and a `CRITICAL` for the font
        that declares three.
        """
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            page["/Resources"] = pikepdf.Dictionary(Font=pikepdf.Dictionary())
            font_declaring(pdf, "/FTwo", ord("a"), 2)
            font_declaring(pdf, "/FThree", ord("x"), 3)
            report = prc.Report(path=Path("x.pdf"))
            prc.check_fonts(pdf, report, "", None)
        by_location = {f.location: f for f in report.findings}
        for location in ("page 1 /FTwo", "page 1 /FThree"):
            assert by_location[location].severity is prc.Severity.WARNING
            assert "never measured" in by_location[location].detail
            assert "consistent with text removed" not in by_location[location].detail

    def test_the_committed_corpus_covers_both_sides(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """A sample for each, so neither side is only ever asserted in
        a document this suite built for itself.

        Both sides have to come from a document whose page text was read
        in full, because a page that stopped short takes the threshold
        out of the question entirely -- see
        `TestAPartialBaselineInTheCorpus`. `font_variants.pdf` is such a
        document and carries both sides at once.
        """
        report, _ = prc.analyze(fixtures / "font_variants.pdf", [])
        failed, _ = prc.analyze(fixtures / "orphan_font.pdf", [])
        severities = {
            f.location: f.severity
            for f in report.findings
            if "absent from visible text" in f.detail
        }
        assert severities["page 1 /FCharSet"] is prc.Severity.WARNING
        assert severities["page 1 /FDiff"] is prc.Severity.CRITICAL
        assert prc.verdict_code(failed) == prc.EXIT_RECOVERABLE

    def test_the_short_side_is_a_real_orphan_and_not_just_a_warning(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """What makes `font_variants.pdf` the sample for the short side.

        Its /FCharSet lists ten glyph names and the page draws nine of
        them, so the tenth is a single orphan. The verdict of that
        document is a failure on the strength of its /FDiff alone, which
        is why the finding itself is asserted here: anything later added
        to the sample that happens to draw a 9 would take the one-orphan
        case away without failing a test.
        """
        report, _ = prc.analyze(fixtures / "font_variants.pdf", [])
        orphans = [
            f
            for f in report.findings
            if f.location == "page 1 /FCharSet"
            and "absent from visible text" in f.detail
        ]
        assert len(orphans) == 1
        assert orphans[0].severity is prc.Severity.WARNING
        assert "1 character(s)" in orphans[0].detail
        assert repr("9") in orphans[0].detail


class TestAPartialBaselineInTheCorpus:
    """A committed document whose page text could not be read in full.

    `broken_fonts.pdf` draws two bytes with a /Font resource that is a
    number, so those two bytes are text the page draws that nothing here
    could turn into characters. That makes the page text less than what
    the page draws, and a font's leftovers cannot be told from characters
    this never saw -- so the finding says what it observed instead of
    asserting a removal. The sample is the corpus's fixture for that
    path: with the signal taken out, its /FBadWidth finding goes back to
    claiming a passage was removed from a page it did not finish reading.
    """

    def test_the_finding_fires_and_lists_the_character(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """Weakening the inference is not dropping the finding."""
        report, _ = prc.analyze(fixtures / "broken_fonts.pdf", [])
        orphans = [
            f
            for f in report.findings
            if f.location == "page 1 /FBadWidth"
            and "mapped by the font subset" in f.detail
        ]
        assert len(orphans) == 1
        assert "1 character(s)" in orphans[0].detail
        assert repr("C") in orphans[0].detail

    def test_the_finding_names_the_page_it_could_not_finish(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The observation and the inference, stated apart.

        The strong wording would say the character is absent from the
        visible text, which this run is in no position to claim.
        """
        report, _ = prc.analyze(fixtures / "broken_fonts.pdf", [])
        detail = next(
            f.detail
            for f in report.findings
            if f.location == "page 1 /FBadWidth"
            and "mapped by the font subset" in f.detail
        )
        assert "absent from the page text this could read" in detail
        assert "the text of page 1 could not be read in full" in detail
        assert "absent from visible text" not in detail
        assert "consistent with text removed" not in detail

    def test_the_page_that_could_not_be_read_is_reported_beside_it(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The other half of the pair: the finding it agrees with.

        The two used to contradict each other -- one saying the page
        text could not be read, the other drawing an inference that
        needs it read.
        """
        report, _ = prc.analyze(fixtures / "broken_fonts.pdf", [])
        content = [
            f
            for f in report.findings
            if f.check == prc.CONTENT_STREAM and f.location == "page 1"
        ]
        assert len(content) == 1
        assert "/FScalar" in content[0].detail


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
        """The character code is named, not the position in the array.

        A position would have to say whether it counted from zero, and
        the code is what an operator would go looking for anyway. The
        sample's /FirstChar is 65, and the bad entry is the one after
        it, so the code is 66.
        """
        report, _ = prc.analyze(fixtures / "broken_fonts.pdf", [])
        problems = [
            f
            for f in report.findings
            if f.location == "page 1 /FBadWidth" and "/Widths entry" in f.detail
        ]
        assert len(problems) == 1
        assert "character code 66 is not a number" in problems[0].detail
        assert problems[0].severity is prc.Severity.WARNING

    def test_a_font_listed_as_its_own_descendant_terminates(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        with pikepdf.open(fixtures / "broken_fonts.pdf") as pdf:
            looped = dict(prc.iter_fonts(pdf))["page 1 /FLoop"]
            assert prc.font_charset(looped) == []

    def test_a_chain_of_descendant_fonts_stops_at_the_depth_limit(
        self, prc: ModuleType
    ) -> None:
        """A descendant font is a font, and can name one of its own.

        Nothing but the depth limit bounds that chain -- the memo of
        objects already seen only stops it repeating -- so a file that
        nests it far enough used to end the run in a recursion error,
        printing a traceback where the report belongs.
        """
        stops: list[str] = []
        with pikepdf.new() as pdf:
            font = pdf.make_indirect(
                pikepdf.Dictionary(
                    Type=pikepdf.Name("/Font"),
                    Subtype=pikepdf.Name("/Type1"),
                    BaseFont=pikepdf.Name("/Helvetica"),
                    Encoding=pikepdf.Name("/WinAnsiEncoding"),
                    FirstChar=65,
                    Widths=[500],
                )
            )
            deepest = font
            for _ in range(200):
                font = pdf.make_indirect(
                    pikepdf.Dictionary(
                        Type=pikepdf.Name("/Font"),
                        Subtype=pikepdf.Name("/Type0"),
                        BaseFont=pikepdf.Name("/ABCDEF+Deep"),
                        Encoding=pikepdf.Name("/Identity-H"),
                        DescendantFonts=[font],
                    )
                )
            assert prc.font_charset(font, stops=stops) == []
            assert stops and all(stop.startswith("object ") for stop in stops)
            # The walk gave up above the bottom, which is why the
            # character that font declares is not in the charset.
            assert prc.object_label(deepest) not in stops

    def test_a_chain_within_the_limit_reaches_the_bottom_of_it(
        self, prc: ModuleType
    ) -> None:
        """The negative half: an ordinary composite font is read whole,
        and says nothing about depth."""
        stops: list[str] = []
        with pikepdf.new() as pdf:
            descendant = pdf.make_indirect(
                pikepdf.Dictionary(
                    Type=pikepdf.Name("/Font"),
                    Subtype=pikepdf.Name("/CIDFontType0"),
                    BaseFont=pikepdf.Name("/ABCDEF+Deep"),
                    Encoding=pikepdf.Name("/WinAnsiEncoding"),
                    FirstChar=65,
                    Widths=[500],
                )
            )
            font = pikepdf.Dictionary(
                Type=pikepdf.Name("/Font"),
                Subtype=pikepdf.Name("/Type0"),
                BaseFont=pikepdf.Name("/ABCDEF+Deep"),
                Encoding=pikepdf.Name("/Identity-H"),
                DescendantFonts=[descendant],
            )
            assert prc.font_charset(font, stops=stops) == ["A"]
        assert stops == []

    def test_a_chain_stopped_with_nobody_collecting_still_stops(
        self, prc: ModuleType
    ) -> None:
        """Every path through the tool collects the places it stopped.

        A caller that collects nothing -- which is what reading this
        function on its own is -- drops the place it gave up at, and the
        walk still ends there rather than running on.
        """
        font = pikepdf.Dictionary(
            Type=pikepdf.Name("/Font"),
            Subtype=pikepdf.Name("/Type1"),
            BaseFont=pikepdf.Name("/Helvetica"),
            Encoding=pikepdf.Name("/WinAnsiEncoding"),
            FirstChar=65,
            Widths=[500],
        )
        assert prc.font_charset(font, depth=prc.MAX_DEPTH + 1) == []

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

    @pytest.mark.parametrize("value", [42, 4.5, True, pikepdf.Name("/Helvetica")])
    def test_a_font_resource_that_is_not_a_dictionary_is_reported(
        self, prc: ModuleType, value: object
    ) -> None:
        """Hostile input: a /Font group holds whatever it was given.

        pikepdf hands a number, a real number or a boolean back as the
        plain Python object, none of which has the methods a font is
        read with, so reading one used to end the whole run in a
        traceback -- and a run that ended there printed no findings at
        all, whatever else the document was carrying.
        """
        problems: list[str] = []
        assert prc.font_charset(value, problems) == []
        assert len(problems) == 1
        assert "not a font dictionary" in problems[0]

    @pytest.mark.parametrize(
        "value",
        [42, 4.5, True, pikepdf.Array([1]), pikepdf.Dictionary(Type="/CMap")],
    )
    def test_a_tounicode_that_is_not_a_stream_is_reported(
        self, prc: ModuleType, value: object
    ) -> None:
        """A character map lives in a stream, so anything else is not one.

        The same class of input as above, in the other place a font hands
        one over: /ToUnicode. A value that is not a stream has no bytes
        to parse, and saying so is what keeps it from reading as a font
        that maps nothing.
        """
        font = pikepdf.Dictionary(
            Type=pikepdf.Name("/Font"),
            Subtype=pikepdf.Name("/Type1"),
            BaseFont=pikepdf.Name("/Helvetica"),
            ToUnicode=value,
        )
        problems: list[str] = []
        assert prc.read_tounicode(font, problems) is None
        assert len(problems) == 1
        assert "/ToUnicode" in problems[0] and "not a stream" in problems[0]

    def test_a_font_with_no_tounicode_reports_nothing(self, prc: ModuleType) -> None:
        """The negative half: an absent entry is not a malformed one."""
        font = pikepdf.Dictionary(
            Type=pikepdf.Name("/Font"),
            Subtype=pikepdf.Name("/Type1"),
            BaseFont=pikepdf.Name("/Helvetica"),
        )
        problems: list[str] = []
        assert prc.read_tounicode(font, problems) is None
        assert problems == []

    def test_the_scalar_fonts_of_the_corpus_are_reported(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The same two shapes, in a document on disk.

        `broken_fonts.pdf` draws with both of them, so this also proves
        the run survives them: a font that cannot be read costs the text
        it drew, not the report.
        """
        report, _ = prc.analyze(fixtures / "broken_fonts.pdf", [])
        details = {f.location: f.detail for f in report.findings}
        assert "not a font dictionary" in details["page 1 /FScalar"]
        assert "not a stream" in details["page 1 /FScalarCMap"]
        assert prc.verdict_code(report) == prc.EXIT_SUSPICIOUS

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

    def test_the_font_a_Q_puts_back_is_what_the_page_draws_with(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """Both directions of the defect, on the committed sample.

        `saved_state.pdf` draws three codes after a `Q` has put /FKept
        back in effect. Read through the /FDropped the q ... Q pair
        selected, those codes spell three of the four characters
        /FDropped declares -- so the leftovers that font really carries
        stop looking like leftovers, and the three characters /FKept
        declares and draws go missing from the page text instead.
        """
        report, _ = prc.analyze(fixtures / "saved_state.pdf", [])
        fonts = [f for f in report.findings if f.check == prc.FONT_CHARSET]
        assert [f.location for f in fonts] == ["page 1 /FDropped"]
        assert fonts[0].severity is prc.Severity.CRITICAL
        assert repr("ÙŸŽ") in fonts[0].detail

        with pikepdf.open(fixtures / "saved_state.pdf") as pdf:
            visible = prc.extract_page_text(pdf)
        assert all(char in visible for char in "ÁÉÍ")
        assert not [char for char in "ÙŸŽ" if char in visible]

    def test_saving_more_states_than_the_limit_is_reported(
        self, prc: ModuleType
    ) -> None:
        """A `q` costs two bytes and asks for a saved state.

        Those two bytes compress to almost nothing, so a file of a few
        kilobytes could otherwise ask for as much memory as the machine
        has. Past the limit the state is not kept, and the `Q` that
        would have taken it back has to say so -- keeping the text but
        saying the font it was read through is a guess.
        """
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            deep = prc.MAX_DEPTH + 5
            page.Contents = pdf.make_stream(b"q " * deep + b"Q " * deep)
            problems = prc._page_text(page).problems
        assert len(problems) == 1
        assert "5 Q operator(s)" in problems[0]
        assert str(prc.MAX_DEPTH) in problems[0]

    def test_saving_up_to_the_limit_is_not_reported(self, prc: ModuleType) -> None:
        """The negative half: the limit is not hit one save early.

        Without this, moving the limit down would look like a fix for
        the test above rather than a change in what the tool inspects.
        """
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            page.Contents = pdf.make_stream(
                b"q " * prc.MAX_DEPTH + b"Q " * prc.MAX_DEPTH
            )
            problems = prc._page_text(page).problems
        assert problems == []

    def test_a_restore_past_the_limit_does_not_shift_the_ones_below_it(
        self, prc: ModuleType
    ) -> None:
        """A `Q` pairs with the most recent `q`, kept or not.

        Matching a restore against a saved state that belongs to a
        different depth would leave every restore after it off by one,
        so the states that were dropped have to be counted off first.
        The last `Q` here is the one that pairs with the first `q`, and
        it has to put the original font back.
        """
        with pikepdf.new() as pdf:
            page = pdf.add_blank_page()
            over = prc.MAX_DEPTH + 3
            page.Contents = pdf.make_stream(
                b"/F1 12 Tf " + b"q " * over + b"Q " * over + b"<01> Tj"
            )
            page.Resources = pikepdf.Dictionary(
                Font=pikepdf.Dictionary(
                    F1=pikepdf.Dictionary(
                        Type=pikepdf.Name("/Font"),
                        Subtype=pikepdf.Name("/Type1"),
                        BaseFont=pikepdf.Name("/Helvetica"),
                        Encoding=pikepdf.Dictionary(
                            Type=pikepdf.Name("/Encoding"),
                            Differences=[1, pikepdf.Name("/x")],
                        ),
                    )
                )
            )
            text = prc._page_text(page).text
        assert text == "x"

    def test_a_form_that_rebinds_a_font_name_is_read_through_both_fonts(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """The false-positive case, on the committed sample.

        `rebound_font.pdf` draws one form twice under one resource name,
        which the form's own resources give to a font of its own and the
        page gives to another. Telling the two drawings apart by the
        name alone reads the second as a repeat of the first, so the
        three characters the page's font drew never reach the page text
        -- and that font, which declares exactly those three, is then
        reported as carrying the leftovers of a removed passage.
        """
        with pikepdf.open(fixtures / "rebound_font.pdf") as pdf:
            visible = prc.extract_page_text(pdf)
            fonts = dict(prc.iter_fonts(pdf))
            page_font = prc.font_charset(fonts["page 1 /FRebound"])
            form_font = prc.font_charset(fonts["page 1 /Fm0 /FRebound"])
            orphans = dict(prc.font_orphans(pdf, visible))
        assert page_font == ["Þ", "Ð", "Š"]
        assert form_font == ["Ý", "Ž", "Ø"]
        assert visible.endswith("ÝŽØÞÐŠ")
        assert orphans == {}

    def test_the_rebound_font_sample_reports_nothing_at_all(
        self, prc: ModuleType, fixtures: Path
    ) -> None:
        """A document whose text is all on the screen is a clean run."""
        report, _ = prc.analyze(fixtures / "rebound_font.pdf", [])
        assert [f for f in report.findings if f.severity is not prc.Severity.INFO] == []
        assert prc.verdict_code(report) == prc.EXIT_CLEAN

    def test_the_rebound_font_sample_draws_what_its_glyph_names_say(
        self, prc: ModuleType, maketests: ModuleType
    ) -> None:
        """The generator names glyphs; the tool resolves them."""
        page_font = [prc.GLYPH_NAMES[n] for n in maketests.PAGE_FONT_GLYPH_NAMES]
        form_font = [prc.GLYPH_NAMES[n] for n in maketests.FORM_FONT_GLYPH_NAMES]
        assert page_font == ["Þ", "Ð", "Š"]
        assert form_font == ["Ý", "Ž", "Ø"]

    def test_the_saved_state_sample_draws_what_its_glyph_names_say(
        self, prc: ModuleType, maketests: ModuleType
    ) -> None:
        """The generator names glyphs; the tool resolves them.

        The sample is only evidence of anything if the two agree on
        which characters those names stand for.
        """
        kept = [prc.GLYPH_NAMES[name] for name in maketests.KEPT_GLYPH_NAMES]
        dropped = [prc.GLYPH_NAMES[name] for name in maketests.DROPPED_GLYPH_NAMES]
        assert kept == ["Á", "É", "Í"]
        assert dropped == ["Ò", "Ù", "Ÿ", "Ž"]

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
