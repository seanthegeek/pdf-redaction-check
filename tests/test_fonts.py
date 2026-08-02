# SPDX-FileCopyrightText: 2026 Sean Whalen
# SPDX-License-Identifier: MIT
"""Tests for reading a font's declared character set.

Every shape of font dictionary lives in the `font_variants.pdf` sample:
/Differences glyph names, /Widths with a simple encoding, a Type 1
/CharSet list, and a Type 0 font whose characters sit on a descendant.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pikepdf
import pytest


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
            ("bullet", "•"),  # a Unicode character name
        ],
    )
    def test_resolvable_names(self, prc: ModuleType, name: str, expected: str) -> None:
        assert prc.glyph_name_to_char(name) == expected

    @pytest.mark.parametrize("name", ["notaglyphname", "uniZZZZ", "uni110000"])
    def test_unresolvable_names(self, prc: ModuleType, name: str) -> None:
        assert prc.glyph_name_to_char(name) is None


class TestFontCharsets:
    """Each source of glyph information is read, in document order."""

    def test_differences_array(self, prc: ModuleType, fonts: dict) -> None:
        assert prc.font_charset(fonts["page 1 /FDiff"]) == ["z", "7", "4", "•"]

    def test_widths_skip_zero_width_codes(self, prc: ModuleType, fonts: dict) -> None:
        charset = prc.font_charset(fonts["page 1 /FWidth"])
        # /FirstChar 90 with widths [500, 0, 500] covers Z and backslash;
        # the zero-width code between them draws nothing.
        assert charset == ["Z", "\\"]

    def test_type1_charset_list(self, prc: ModuleType, fonts: dict) -> None:
        assert prc.font_charset(fonts["page 1 /FCharSet"]) == ["q", "9"]

    def test_descendant_fonts_are_followed(self, prc: ModuleType, fonts: dict) -> None:
        assert prc.font_charset(fonts["page 1 /FType0"]) == ["w"]

    def test_base14_font_declares_nothing(self, prc: ModuleType, fonts: dict) -> None:
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
        # 254 and 255 decode; 256 and beyond are not byte codes at all.
        assert len(font_widths := prc.widths_charset(font)) == 2, font_widths


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

    def test_odd_length_destination_is_ignored(self, prc: ModuleType) -> None:
        # '041' is not a whole number of bytes.
        data = b"beginbfrange <01> <03> <041> endbfrange"
        assert prc.parse_tounicode(data) == []

    def test_unreadable_tounicode_is_ignored(
        self, prc: ModuleType, fixtures: Path, monkeypatch
    ) -> None:
        with pikepdf.open(fixtures / "orphan_font.pdf") as pdf:
            font = dict(prc.iter_fonts(pdf))["page 1 /F1"]
            stream_type = type(font["/ToUnicode"])

            def explode(*args, **kwargs):
                raise pikepdf.PdfError("cannot read CMap")

            monkeypatch.setattr(stream_type, "read_bytes", explode)
            assert prc.font_charset(font) == []


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
