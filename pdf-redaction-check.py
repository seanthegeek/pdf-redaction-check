#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sean Whalen
# SPDX-License-Identifier: MIT
"""Verify that a redaction actually removed content from a PDF.

Checks seven layers where text can survive a "redaction" that only looks
correct on screen:

1. Content-stream text (the characters the page draws)
2. Raw object data, decoded where it can be (text outside the text layer)
3. Tagged-PDF structure tree (/ActualText, /Alt, /E, /T, /TU)
4. Annotations and form field values
5. Document metadata (DocInfo + XMP)
6. Embedded file attachments
7. Font subsets and ToUnicode CMaps -- orphaned glyph mappings

Check 7 targets the failure mode documented by the Australian Signals
Directorate: PDF producers build ToUnicode CMaps in order of a
character's first appearance in the text, and post-hoc redaction removes
the visible glyphs without rebuilding the CMap. A character that is
mapped in the font but appears nowhere in the visible text is evidence
that text was removed from the content stream but not from the font
subset.

Every run makes the structural checks above and reports what it could
not read. Two modes go further. Given one or more secrets, the tool
reports whether they survive anywhere. Given --dump-hidden or
--dump-all, it outputs the recoverable text itself, for auditing a
document when you do not know what was redacted.

Usage:
    pdf-redaction-check FILE.pdf
    pdf-redaction-check FILE.pdf --secret "742 Evergreen Terrace"
    pdf-redaction-check FILE.pdf --secret-file secrets.txt --json
    pdf-redaction-check FILE.pdf --dump-hidden
    pdf-redaction-check FILE.pdf --dump-all -o recovered.txt
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import string
import sys
import unicodedata
import zlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Literal, NoReturn, NotRequired, TypedDict

import pikepdf

# Process exit codes. These are public API -- people wire them into
# pre-send hooks and CI gates -- so the meaning of a code may not change
# without a major version bump and a README update in the same commit.
EXIT_CLEAN = 0
EXIT_SUSPICIOUS = 1
EXIT_RECOVERABLE = 2
EXIT_INCOMPLETE = 3
EXIT_USAGE = 4

# Glyph names that carry no evidential weight when orphaned: whitespace
# and layout characters legitimately outlive the text that used them.
IGNORABLE_CHARS: frozenset[str] = frozenset(" \t\r\n\x00\ufeff\xa0")

# The operators that draw text. Everything else in a content stream is
# positioning, graphics state, or drawing.
SHOW_TEXT_OPERATORS: frozenset[str] = frozenset({"Tj", "TJ", "'", '"'})

BFCHAR_RE = re.compile(rb"beginbfchar(.*?)endbfchar", re.DOTALL)
BFRANGE_RE = re.compile(rb"beginbfrange(.*?)endbfrange", re.DOTALL)
CODESPACE_RE = re.compile(
    rb"begincodespacerange(.*?)endcodespacerange",
    re.DOTALL,
)
# One token of a CMap block: a hex string, or a bracket around a list of
# them. The brackets have to be tracked, not skipped over -- see
# `cmap_items`.
CMAP_TOKEN_RE = re.compile(rb"<([0-9A-Fa-f]*)>|(\[)|(\])")
# The two glyph names that spell a character out in hexadecimal. Adobe's
# convention gives uni exactly four digits: a longer name is several
# groups of four, one per character of a sequence, which is not a single
# character and is left unresolved rather than read as a fifth and sixth
# digit of the first. The u form is the one that takes four to six.
UNI_GLYPH_RE = re.compile(r"^uni([0-9A-Fa-f]{4})$")
U_GLYPH_RE = re.compile(r"^u([0-9A-Fa-f]{4,6})$")

# Layer names, shared by findings and dump output.
CONTENT_STREAM = "content-stream"
STRUCTURE_TREE = "structure-tree"
ANNOTATIONS = "annotations"
METADATA = "metadata"
ATTACHMENTS = "attachments"
RAW_STRINGS = "raw-strings"
RAW_OBJECTS = "raw-objects"
FONT_CHARSET = "font-charset"

# How a surviving secret is described, per layer.
SECRET_DETAIL: dict[str, str] = {
    CONTENT_STREAM: "secret text still present in the page text layer",
    STRUCTURE_TREE: "secret survives in the tag tree (invisible to pdftotext)",
    ANNOTATIONS: "secret found in annotation",
    METADATA: "secret found in metadata",
    ATTACHMENTS: "secret found in an attachment name",
    RAW_STRINGS: "secret found in a string object outside the text layer",
}

# Dump output is ordered by how likely a layer is to hold a real leak,
# so the finding is not buried under producer boilerplate.
LAYER_ORDER: tuple[str, ...] = (
    CONTENT_STREAM,
    STRUCTURE_TREE,
    ANNOTATIONS,
    ATTACHMENTS,
    RAW_STRINGS,
    METADATA,
    FONT_CHARSET,
)

# A string object has to look like text before it is worth reporting.
# Binary values decode into plenty of "printable" characters, so the
# test is how much of the value is plain ASCII, not how much of it
# Python is willing to print.
MIN_ASCII_RATIO = 0.7
MIN_TEXT_LENGTH = 3

# Dictionary keys whose string values are binary by definition.
BINARY_KEYS: frozenset[str] = frozenset({"/ID", "/O", "/U", "/OE", "/UE", "/Perms"})

# What pikepdf raises when a stream will not give up its contents: a
# structural problem in the file, a filter it cannot run -- which is a
# separate exception that does not derive from the first -- or damaged
# compressed data. Every place that asks a stream for its bytes has to
# be ready for all three.
UNREADABLE_STREAM: tuple[type[Exception], ...] = (
    pikepdf.PdfError,
    pikepdf.DataDecodingError,
    zlib.error,
)

# What reading a page's drawing instructions can raise. Every way a
# stream can refuse to give up its bytes is one of them, because parsing
# starts by reading the stream; TypeError is what the parser raises for
# an object it cannot make instructions out of; and ValueError covers
# the rest of the walk, which reads fonts and character maps as it goes.
UNPARSABLE_CONTENT: tuple[type[Exception], ...] = (
    *UNREADABLE_STREAM,
    ValueError,
    TypeError,
)

# Filters whose output is picture data rather than anything with a text
# layer in it (ISO 32000 section 7.4). pikepdf will not run them, and a
# scanned page is full of them, so a stream that really does hold a
# picture is not a stream this failed to read -- there was never text in
# the decoded form to look for. Text that was flattened into a picture is
# out of reach of every check here, which the README says under
# "Rasterized pages".
IMAGE_FILTERS: frozenset[str] = frozenset(
    {"/DCTDecode", "/JPXDecode", "/CCITTFaxDecode", "/JBIG2Decode"}
)

# The filters that only respell bytes as printable characters, with no
# compression in them (ISO 32000 sections 7.4.2 and 7.4.3). This undoes
# them itself, so a picture wrapped in one -- which is what the
# Distiller line of producers writes for a JPEG -- is still a picture
# whose bytes were read.
ASCII_ARMOR_FILTERS: frozenset[str] = frozenset({"/ASCII85Decode", "/ASCIIHexDecode"})

# What the picture formats that carry a signature begin with: JPEG's
# start-of-image marker (ISO/IEC 10918-1), and both shapes JPEG 2000
# data comes in -- the JP2 signature box and a bare codestream (ISO/IEC
# 15444-1). /CCITTFaxDecode and /JBIG2Decode data starts with no fixed
# bytes at all, which is why they are absent here and corroborated a
# different way; see `picture_bytes`.
IMAGE_SIGNATURES: dict[str, tuple[bytes, ...]] = {
    "/DCTDecode": (b"\xff\xd8\xff",),
    "/JPXDecode": (b"\x00\x00\x00\x0cjP  ", b"\xff\x4f\xff\x51"),
}

# Adobe StandardEncoding, from ISO 32000 Annex D.2. Python ships no
# codec for it, and it is not MacRoman: the two agree on the ASCII range
# but their upper halves are unrelated, so decoding one as the other
# invents characters (code 0341 is a capital AE ligature in
# StandardEncoding and a middle dot in MacRoman). Codes missing from
# this table are undefined in the encoding, and are left unmapped rather
# than guessed at.
STANDARD_ENCODING: dict[int, str] = {
    **{code: chr(code) for code in range(0x20, 0x7F)},
    # The two places StandardEncoding departs from ASCII.
    0x27: "’",  # quoteright
    0x60: "‘",  # quoteleft
    0xA1: "¡",  # exclamdown
    0xA2: "¢",  # cent
    0xA3: "£",  # sterling
    0xA4: "⁄",  # fraction
    0xA5: "¥",  # yen
    0xA6: "ƒ",  # florin
    0xA7: "§",  # section
    0xA8: "¤",  # currency
    0xA9: "'",  # quotesingle
    0xAA: "“",  # quotedblleft
    0xAB: "«",  # guillemotleft
    0xAC: "‹",  # guilsinglleft
    0xAD: "›",  # guilsinglright
    0xAE: "ﬁ",  # fi
    0xAF: "ﬂ",  # fl
    0xB1: "–",  # endash
    0xB2: "†",  # dagger
    0xB3: "‡",  # daggerdbl
    0xB4: "·",  # periodcentered
    0xB6: "¶",  # paragraph
    0xB7: "•",  # bullet
    0xB8: "‚",  # quotesinglbase
    0xB9: "„",  # quotedblbase
    0xBA: "”",  # quotedblright
    0xBB: "»",  # guillemotright
    0xBC: "…",  # ellipsis
    0xBD: "‰",  # perthousand
    0xBF: "¿",  # questiondown
    0xC1: "`",  # grave
    0xC2: "´",  # acute
    0xC3: "ˆ",  # circumflex
    0xC4: "˜",  # tilde
    0xC5: "¯",  # macron
    0xC6: "˘",  # breve
    0xC7: "˙",  # dotaccent
    0xC8: "¨",  # dieresis
    0xCA: "˚",  # ring
    0xCB: "¸",  # cedilla
    0xCD: "˝",  # hungarumlaut
    0xCE: "˛",  # ogonek
    0xCF: "ˇ",  # caron
    0xD0: "—",  # emdash
    0xE1: "Æ",  # AE
    0xE3: "ª",  # ordfeminine
    0xE8: "Ł",  # Lslash
    0xE9: "Ø",  # Oslash
    0xEA: "Œ",  # OE
    0xEB: "º",  # ordmasculine
    0xF1: "æ",  # ae
    0xF5: "ı",  # dotlessi
    0xF8: "ł",  # lslash
    0xF9: "ø",  # oslash
    0xFA: "œ",  # oe
    0xFB: "ß",  # germandbls
}


class Severity(Enum):
    """How much a finding should worry the operator."""

    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


# The two dump modes. Anything else is not a mode this tool has.
DumpMode = Literal["hidden", "all"]

# One drawing of a Form XObject: the form, the resource name of the font
# in effect, and the resources it was drawn with, each object named by
# its number and generation. See `already_drawn`.
FormDrawing = tuple[tuple[int, int], str, tuple[int, int]]


class FindingJSON(TypedDict):
    """One finding, as emitted by --json."""

    severity: str
    check: str
    detail: str
    location: str


class ExtractJSON(TypedDict):
    """One recovered piece of text, as emitted by --json."""

    layer: str
    location: str
    hidden: bool
    is_text: bool
    text: str


class DumpJSON(TypedDict):
    """The recovered-text section of --json output."""

    mode: DumpMode
    extracts: list[ExtractJSON]


class ReportJSON(TypedDict):
    """Top-level --json payload."""

    file: str
    worst_severity: str | None
    findings: list[FindingJSON]
    dump: NotRequired[DumpJSON]


@dataclass(frozen=True)
class Finding:
    """A single observation about the document."""

    severity: Severity
    check: str
    detail: str
    location: str = ""

    def render(self) -> str:
        """Format the finding as one human-readable line."""
        where = f" [{self.location}]" if self.location else ""
        return f"{self.severity.value:8} {self.check}{where}: {self.detail}"


@dataclass(frozen=True)
class Extract:
    """A piece of text recovered from one layer of the document.

    `is_text` is False for the font-subset layer, which yields a set of
    characters rather than readable text. Consumers must not present
    those characters as recovered wording.
    """

    layer: str
    location: str
    text: str
    is_text: bool = True


@dataclass
class Report:
    """Accumulated findings for one document."""

    path: Path
    findings: list[Finding] = field(default_factory=list)

    def add(
        self,
        severity: Severity,
        check: str,
        detail: str,
        location: str = "",
    ) -> None:
        """Record a finding."""
        self.findings.append(Finding(severity, check, detail, location))

    @property
    def worst(self) -> Severity | None:
        """Return the highest severity present, or None if clean."""
        for level in (Severity.CRITICAL, Severity.WARNING, Severity.INFO):
            if any(f.severity is level for f in self.findings):
                return level
        return None

    def to_dict(self) -> ReportJSON:
        """Serialize the report for --json output."""
        return {
            "file": str(self.path),
            "worst_severity": self.worst.value if self.worst else None,
            "findings": [
                {
                    "severity": f.severity.value,
                    "check": f.check,
                    "detail": f.detail,
                    "location": f.location,
                }
                for f in self.findings
            ],
        }


def note(problems: list[str] | None, message: str) -> None:
    """Record something a check could not read, if anyone is collecting.

    `problems` is None when this caller is not the one collecting the
    descriptions: the page-text path, which reads a font to decode with
    and leaves reporting on that font to the font check, and the tests
    that exercise one reader in isolation. The message is dropped in
    that case, never turned into a silent success.
    """
    if problems is not None:
        problems.append(message)


def object_label(obj: pikepdf.Object) -> str:
    """Name an indirect object by its number, for a finding's location."""
    number, generation = getattr(obj, "objgen", (0, 0))
    if not number:
        return "direct object"
    return f"object {number} {generation}"


def normalize(text: str) -> str:
    """Casefold and strip accents so 'Café' matches 'cafe'."""
    decomposed = unicodedata.normalize("NFKD", text)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return stripped.casefold()


def dedupe(chars: Iterable[str]) -> list[str]:
    """Drop repeats while keeping the order of first appearance."""
    return list(dict.fromkeys(chars))


def byte_encoding_table(codec: str) -> dict[int, str]:
    """Turn a single-byte Python codec into a code -> character table."""
    table: dict[int, str] = {}
    for code in range(256):
        try:
            table[code] = bytes([code]).decode(codec)
        except UnicodeDecodeError:
            continue
    return table


WINANSI_ENCODING: dict[int, str] = byte_encoding_table("cp1252")
# PDF's MacRomanEncoding and the Mac OS Roman codec differ at one code:
# ISO 32000 Annex D.2 gives 0xDB as the currency sign, where the codec
# gives the euro sign.
MACROMAN_ENCODING: dict[int, str] = byte_encoding_table("mac_roman") | {0xDB: "¤"}

# The named base encodings a simple font can ask for by name.
BASE_ENCODINGS: dict[str, dict[int, str]] = {
    "/WinAnsiEncoding": WINANSI_ENCODING,
    "/MacRomanEncoding": MACROMAN_ENCODING,
    "/StandardEncoding": STANDARD_ENCODING,
}


# The standard PostScript glyph names, from ISO 32000 Annex D: every
# name used by StandardEncoding, WinAnsiEncoding, and MacRomanEncoding.
# A glyph name is what a producer writes into an /Encoding /Differences
# array or a Type 1 subset's /CharSet list to say which character a code
# draws, and real producers write these names -- LibreOffice and
# Ghostscript name a digit /seven, not /uni0037 -- so a reader that does
# not know them recovers nothing from exactly the documents the
# Australian Signals Directorate report is about.
#
# Adobe's full glyph list is deliberately not carried here. It is some
# four thousand entries; the three named encodings cover the producers
# this tool meets and stay short enough to check by eye.
#
# A few names sit at more than one code. Each is resolved by the first
# encoding that uses it, taking StandardEncoding first, then
# WinAnsiEncoding, then MacRomanEncoding, which gives each of them its
# ordinary meaning: /space is the space rather than the no-break space
# that WinAnsi and MacRoman also call /space, /hyphen is the hyphen
# rather than the soft hyphen at WinAnsi 0xAD, and /bullet is the bullet
# rather than the six WinAnsi codes Annex D names /bullet only because
# they are unused.
GLYPH_NAMES: dict[str, str] = {
    # A letter's glyph name is the letter itself.
    **{letter: letter for letter in string.ascii_letters},
    "AE": "Æ",  # U+00C6 LATIN CAPITAL LETTER AE
    "Aacute": "Á",  # U+00C1 LATIN CAPITAL LETTER A WITH ACUTE
    "Acircumflex": "Â",  # U+00C2 LATIN CAPITAL LETTER A WITH CIRCUMFLEX
    "Adieresis": "Ä",  # U+00C4 LATIN CAPITAL LETTER A WITH DIAERESIS
    "Agrave": "À",  # U+00C0 LATIN CAPITAL LETTER A WITH GRAVE
    "Aring": "Å",  # U+00C5 LATIN CAPITAL LETTER A WITH RING ABOVE
    "Atilde": "Ã",  # U+00C3 LATIN CAPITAL LETTER A WITH TILDE
    "Ccedilla": "Ç",  # U+00C7 LATIN CAPITAL LETTER C WITH CEDILLA
    "Eacute": "É",  # U+00C9 LATIN CAPITAL LETTER E WITH ACUTE
    "Ecircumflex": "Ê",  # U+00CA LATIN CAPITAL LETTER E WITH CIRCUMFLEX
    "Edieresis": "Ë",  # U+00CB LATIN CAPITAL LETTER E WITH DIAERESIS
    "Egrave": "È",  # U+00C8 LATIN CAPITAL LETTER E WITH GRAVE
    "Eth": "Ð",  # U+00D0 LATIN CAPITAL LETTER ETH
    "Euro": "€",  # U+20AC EURO SIGN
    "Iacute": "Í",  # U+00CD LATIN CAPITAL LETTER I WITH ACUTE
    "Icircumflex": "Î",  # U+00CE LATIN CAPITAL LETTER I WITH CIRCUMFLEX
    "Idieresis": "Ï",  # U+00CF LATIN CAPITAL LETTER I WITH DIAERESIS
    "Igrave": "Ì",  # U+00CC LATIN CAPITAL LETTER I WITH GRAVE
    "Lslash": "Ł",  # U+0141 LATIN CAPITAL LETTER L WITH STROKE
    "Ntilde": "Ñ",  # U+00D1 LATIN CAPITAL LETTER N WITH TILDE
    "OE": "Œ",  # U+0152 LATIN CAPITAL LIGATURE OE
    "Oacute": "Ó",  # U+00D3 LATIN CAPITAL LETTER O WITH ACUTE
    "Ocircumflex": "Ô",  # U+00D4 LATIN CAPITAL LETTER O WITH CIRCUMFLEX
    "Odieresis": "Ö",  # U+00D6 LATIN CAPITAL LETTER O WITH DIAERESIS
    "Ograve": "Ò",  # U+00D2 LATIN CAPITAL LETTER O WITH GRAVE
    "Oslash": "Ø",  # U+00D8 LATIN CAPITAL LETTER O WITH STROKE
    "Otilde": "Õ",  # U+00D5 LATIN CAPITAL LETTER O WITH TILDE
    "Scaron": "Š",  # U+0160 LATIN CAPITAL LETTER S WITH CARON
    "Thorn": "Þ",  # U+00DE LATIN CAPITAL LETTER THORN
    "Uacute": "Ú",  # U+00DA LATIN CAPITAL LETTER U WITH ACUTE
    "Ucircumflex": "Û",  # U+00DB LATIN CAPITAL LETTER U WITH CIRCUMFLEX
    "Udieresis": "Ü",  # U+00DC LATIN CAPITAL LETTER U WITH DIAERESIS
    "Ugrave": "Ù",  # U+00D9 LATIN CAPITAL LETTER U WITH GRAVE
    "Yacute": "Ý",  # U+00DD LATIN CAPITAL LETTER Y WITH ACUTE
    "Ydieresis": "Ÿ",  # U+0178 LATIN CAPITAL LETTER Y WITH DIAERESIS
    "Zcaron": "Ž",  # U+017D LATIN CAPITAL LETTER Z WITH CARON
    "aacute": "á",  # U+00E1 LATIN SMALL LETTER A WITH ACUTE
    "acircumflex": "â",  # U+00E2 LATIN SMALL LETTER A WITH CIRCUMFLEX
    "acute": "´",  # U+00B4 ACUTE ACCENT
    "adieresis": "ä",  # U+00E4 LATIN SMALL LETTER A WITH DIAERESIS
    "ae": "æ",  # U+00E6 LATIN SMALL LETTER AE
    "agrave": "à",  # U+00E0 LATIN SMALL LETTER A WITH GRAVE
    "ampersand": "&",
    "aring": "å",  # U+00E5 LATIN SMALL LETTER A WITH RING ABOVE
    "asciicircum": "^",
    "asciitilde": "~",
    "asterisk": "*",
    "at": "@",
    "atilde": "ã",  # U+00E3 LATIN SMALL LETTER A WITH TILDE
    "backslash": "\\",
    "bar": "|",
    "braceleft": "{",
    "braceright": "}",
    "bracketleft": "[",
    "bracketright": "]",
    "breve": "˘",  # U+02D8 BREVE
    "brokenbar": "¦",  # U+00A6 BROKEN BAR
    "bullet": "•",  # U+2022 BULLET
    "caron": "ˇ",  # U+02C7 CARON
    "ccedilla": "ç",  # U+00E7 LATIN SMALL LETTER C WITH CEDILLA
    "cedilla": "¸",  # U+00B8 CEDILLA
    "cent": "¢",  # U+00A2 CENT SIGN
    "circumflex": "ˆ",  # U+02C6 MODIFIER LETTER CIRCUMFLEX ACCENT
    "colon": ":",
    "comma": ",",
    "copyright": "©",  # U+00A9 COPYRIGHT SIGN
    "currency": "¤",  # U+00A4 CURRENCY SIGN
    "dagger": "†",  # U+2020 DAGGER
    "daggerdbl": "‡",  # U+2021 DOUBLE DAGGER
    "degree": "°",  # U+00B0 DEGREE SIGN
    "dieresis": "¨",  # U+00A8 DIAERESIS
    "divide": "÷",  # U+00F7 DIVISION SIGN
    "dollar": "$",
    "dotaccent": "˙",  # U+02D9 DOT ABOVE
    "dotlessi": "ı",  # U+0131 LATIN SMALL LETTER DOTLESS I
    "eacute": "é",  # U+00E9 LATIN SMALL LETTER E WITH ACUTE
    "ecircumflex": "ê",  # U+00EA LATIN SMALL LETTER E WITH CIRCUMFLEX
    "edieresis": "ë",  # U+00EB LATIN SMALL LETTER E WITH DIAERESIS
    "egrave": "è",  # U+00E8 LATIN SMALL LETTER E WITH GRAVE
    "eight": "8",
    "ellipsis": "…",  # U+2026 HORIZONTAL ELLIPSIS
    "emdash": "—",  # U+2014 EM DASH
    "endash": "–",  # U+2013 EN DASH
    "equal": "=",
    "eth": "ð",  # U+00F0 LATIN SMALL LETTER ETH
    "exclam": "!",
    "exclamdown": "¡",  # U+00A1 INVERTED EXCLAMATION MARK
    "fi": "ﬁ",  # U+FB01 LATIN SMALL LIGATURE FI
    "five": "5",
    "fl": "ﬂ",  # U+FB02 LATIN SMALL LIGATURE FL
    "florin": "ƒ",  # U+0192 LATIN SMALL LETTER F WITH HOOK
    "four": "4",
    "fraction": "⁄",  # U+2044 FRACTION SLASH
    "germandbls": "ß",  # U+00DF LATIN SMALL LETTER SHARP S
    "grave": "`",
    "greater": ">",
    "guillemotleft": "«",  # U+00AB LEFT-POINTING DOUBLE ANGLE QUOTATION MARK
    "guillemotright": "»",  # U+00BB RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK
    "guilsinglleft": "‹",  # U+2039 SINGLE LEFT-POINTING ANGLE QUOTATION MARK
    "guilsinglright": "›",  # U+203A SINGLE RIGHT-POINTING ANGLE QUOTATION MARK
    "hungarumlaut": "˝",  # U+02DD DOUBLE ACUTE ACCENT
    "hyphen": "-",
    "iacute": "í",  # U+00ED LATIN SMALL LETTER I WITH ACUTE
    "icircumflex": "î",  # U+00EE LATIN SMALL LETTER I WITH CIRCUMFLEX
    "idieresis": "ï",  # U+00EF LATIN SMALL LETTER I WITH DIAERESIS
    "igrave": "ì",  # U+00EC LATIN SMALL LETTER I WITH GRAVE
    "less": "<",
    "logicalnot": "¬",  # U+00AC NOT SIGN
    "lslash": "ł",  # U+0142 LATIN SMALL LETTER L WITH STROKE
    "macron": "¯",  # U+00AF MACRON
    "mu": "µ",  # U+00B5 MICRO SIGN
    "multiply": "×",  # U+00D7 MULTIPLICATION SIGN
    "nine": "9",
    "ntilde": "ñ",  # U+00F1 LATIN SMALL LETTER N WITH TILDE
    "numbersign": "#",
    "oacute": "ó",  # U+00F3 LATIN SMALL LETTER O WITH ACUTE
    "ocircumflex": "ô",  # U+00F4 LATIN SMALL LETTER O WITH CIRCUMFLEX
    "odieresis": "ö",  # U+00F6 LATIN SMALL LETTER O WITH DIAERESIS
    "oe": "œ",  # U+0153 LATIN SMALL LIGATURE OE
    "ogonek": "˛",  # U+02DB OGONEK
    "ograve": "ò",  # U+00F2 LATIN SMALL LETTER O WITH GRAVE
    "one": "1",
    "onehalf": "½",  # U+00BD VULGAR FRACTION ONE HALF
    "onequarter": "¼",  # U+00BC VULGAR FRACTION ONE QUARTER
    "onesuperior": "¹",  # U+00B9 SUPERSCRIPT ONE
    "ordfeminine": "ª",  # U+00AA FEMININE ORDINAL INDICATOR
    "ordmasculine": "º",  # U+00BA MASCULINE ORDINAL INDICATOR
    "oslash": "ø",  # U+00F8 LATIN SMALL LETTER O WITH STROKE
    "otilde": "õ",  # U+00F5 LATIN SMALL LETTER O WITH TILDE
    "paragraph": "¶",  # U+00B6 PILCROW SIGN
    "parenleft": "(",
    "parenright": ")",
    "percent": "%",
    "period": ".",
    "periodcentered": "·",  # U+00B7 MIDDLE DOT
    "perthousand": "‰",  # U+2030 PER MILLE SIGN
    "plus": "+",
    "plusminus": "±",  # U+00B1 PLUS-MINUS SIGN
    "question": "?",
    "questiondown": "¿",  # U+00BF INVERTED QUESTION MARK
    "quotedbl": '"',
    "quotedblbase": "„",  # U+201E DOUBLE LOW-9 QUOTATION MARK
    "quotedblleft": "“",  # U+201C LEFT DOUBLE QUOTATION MARK
    "quotedblright": "”",  # U+201D RIGHT DOUBLE QUOTATION MARK
    "quoteleft": "‘",  # U+2018 LEFT SINGLE QUOTATION MARK
    "quoteright": "’",  # U+2019 RIGHT SINGLE QUOTATION MARK
    "quotesinglbase": "‚",  # U+201A SINGLE LOW-9 QUOTATION MARK
    "quotesingle": "'",
    "registered": "®",  # U+00AE REGISTERED SIGN
    "ring": "˚",  # U+02DA RING ABOVE
    "scaron": "š",  # U+0161 LATIN SMALL LETTER S WITH CARON
    "section": "§",  # U+00A7 SECTION SIGN
    "semicolon": ";",
    "seven": "7",
    "six": "6",
    "slash": "/",
    "space": " ",
    "sterling": "£",  # U+00A3 POUND SIGN
    "thorn": "þ",  # U+00FE LATIN SMALL LETTER THORN
    "three": "3",
    "threequarters": "¾",  # U+00BE VULGAR FRACTION THREE QUARTERS
    "threesuperior": "³",  # U+00B3 SUPERSCRIPT THREE
    "tilde": "˜",  # U+02DC SMALL TILDE
    "trademark": "™",  # U+2122 TRADE MARK SIGN
    "two": "2",
    "twosuperior": "²",  # U+00B2 SUPERSCRIPT TWO
    "uacute": "ú",  # U+00FA LATIN SMALL LETTER U WITH ACUTE
    "ucircumflex": "û",  # U+00FB LATIN SMALL LETTER U WITH CIRCUMFLEX
    "udieresis": "ü",  # U+00FC LATIN SMALL LETTER U WITH DIAERESIS
    "ugrave": "ù",  # U+00F9 LATIN SMALL LETTER U WITH GRAVE
    "underscore": "_",
    "yacute": "ý",  # U+00FD LATIN SMALL LETTER Y WITH ACUTE
    "ydieresis": "ÿ",  # U+00FF LATIN SMALL LETTER Y WITH DIAERESIS
    "yen": "¥",  # U+00A5 YEN SIGN
    "zcaron": "ž",  # U+017E LATIN SMALL LETTER Z WITH CARON
    "zero": "0",
}


def glyph_name_to_char(name: str) -> str | None:
    """Map a PostScript glyph name to a character, best effort.

    Four routes, tried in order: a name that is already a single
    character, the uniXXXX and uXXXX forms that spell a code point out
    in hexadecimal, the standard names above, and last the Unicode
    character names, which pick up names from outside the three encodings
    the table covers. Returns None for a name none of them reach.

    The standard names come before the Unicode ones because the two
    disagree: Unicode has a character called HYPHEN, but the glyph a PDF
    calls /hyphen is the ASCII one, and a character called RING, which is
    a ring worn on a finger and not the accent /ring means.
    """
    if len(name) == 1:
        return name
    match = UNI_GLYPH_RE.match(name) or U_GLYPH_RE.match(name)
    if match:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return None
    standard = GLYPH_NAMES.get(name)
    if standard is not None:
        return standard
    try:
        return unicodedata.lookup(name.upper())
    except KeyError:
        return None


def decode_utf16be(raw: bytes) -> str:
    """Decode a ToUnicode destination value, tolerating odd lengths.

    `errors="ignore"` means a malformed value yields a shorter string
    rather than raising, so there is no decode error to handle here.
    """
    if len(raw) % 2:
        raw = raw + b"\x00"
    return raw.decode("utf-16-be", errors="ignore")


def unhex(digits: bytes) -> bytes:
    """Decode the digits of a PDF hex string.

    An odd number of digits is legal. ISO 32000 section 7.3.4.3 says a
    missing final digit is taken as zero, so <041> is the two bytes
    04 10 -- not an error, and not something to throw the rest of the
    CMap away over.
    """
    text = digits.decode("ascii")
    if len(text) % 2:
        text += "0"
    return bytes.fromhex(text)


def cmap_items(block: bytes) -> list[bytes | list[bytes]]:
    """Split a CMap block into hex strings and bracketed lists of them.

    The brackets are the point. ISO 32000 section 9.10.3 allows a
    bfrange to give one destination per code as an array --
    `<0001> <0003> [<0041> <0042> <0043>]` -- and reading the hex
    strings without regard for the brackets pairs them up wrongly,
    inventing characters that were never mapped and missing real ones.
    """
    items: list[bytes | list[bytes]] = []
    group: list[bytes] | None = None
    for match in CMAP_TOKEN_RE.finditer(block):
        digits, opened, closed = match.groups()
        if opened is not None:
            group = []
            items.append(group)
        elif closed is not None:
            group = None
        elif group is not None:
            group.append(unhex(digits))
        else:
            items.append(unhex(digits))
    return items


def codespace_bytes(data: bytes) -> int:
    """Return how many bytes one character code takes, per a CMap.

    Reads the codespace ranges a CMap declares. Returns 0 when the CMap
    declares none, or declares ranges of more than one width -- this
    does not attempt mixed-width codes.
    """
    widths = {
        len(item)
        for block in CODESPACE_RE.findall(data)
        for item in cmap_items(block)
        if isinstance(item, bytes) and item
    }
    return widths.pop() if len(widths) == 1 else 0


@dataclass(frozen=True)
class ToUnicode:
    """A parsed ToUnicode CMap -- a font's own code-to-text table.

    `entries` pairs each character code with the text it stands for, in
    the order the CMap listed them. The order is evidence: producers
    build these tables in order of each character's first appearance in
    the text.

    `code_bytes` is how many bytes one character code takes, or 0 when
    the CMap did not say consistently.
    """

    entries: list[tuple[int, str]]
    code_bytes: int


def bfrange_entries(
    low: int,
    high: int,
    destination: bytes | list[bytes],
) -> list[tuple[int, str]]:
    """Expand one bfrange entry into its code-to-text mappings.

    Two forms, both from ISO 32000 section 9.10.3. An array gives one
    destination per code. A single destination covers the whole range by
    incrementing its *last* character -- incrementing the first would
    walk off into an unrelated part of Unicode for any destination
    longer than one character.
    """
    if isinstance(destination, list):
        return [
            (low + offset, text)
            for offset, raw in enumerate(destination[: high - low + 1])
            if (text := decode_utf16be(raw))
        ]

    text = decode_utf16be(destination)
    if not text:
        return []
    prefix, last = text[:-1], ord(text[-1])
    out: list[tuple[int, str]] = []
    for offset in range(high - low + 1):
        point = last + offset
        if point > 0x10FFFF or 0xD800 <= point <= 0xDFFF:
            continue
        out.append((low + offset, prefix + chr(point)))
    return out


def parse_tounicode_map(data: bytes) -> ToUnicode:
    """Read every code-to-text mapping a ToUnicode CMap declares."""
    entries: list[tuple[int, str]] = []
    source_widths: set[int] = set()

    for block in BFCHAR_RE.findall(data):
        items = cmap_items(block)
        for position in range(0, len(items) - 1, 2):
            source, destination = items[position], items[position + 1]
            if isinstance(source, list) or isinstance(destination, list):
                continue
            if not source:
                continue
            source_widths.add(len(source))
            text = decode_utf16be(destination)
            if text:
                entries.append((int.from_bytes(source, "big"), text))

    for block in BFRANGE_RE.findall(data):
        items = cmap_items(block)
        for position in range(0, len(items) - 2, 3):
            lo, hi = items[position], items[position + 1]
            if isinstance(lo, list) or isinstance(hi, list) or not lo or not hi:
                continue
            source_widths.add(len(lo))
            low = int.from_bytes(lo, "big")
            high = int.from_bytes(hi, "big")
            if high < low or high - low > 0xFFFF:
                continue
            entries += bfrange_entries(low, high, items[position + 2])

    declared = codespace_bytes(data)
    if not declared and len(source_widths) == 1:
        declared = source_widths.pop()
    return ToUnicode(entries, declared)


def parse_tounicode(data: bytes) -> list[str]:
    """Extract every character a ToUnicode CMap can produce.

    The result keeps CMap order rather than sorting. Producers build
    these tables in order of each character's first appearance in the
    text, so the order is a partial record of the wording that was
    removed.
    """
    return dedupe(
        char for _code, text in parse_tounicode_map(data).entries for char in text
    )


def differences_entries(array: pikepdf.Object | None) -> list[tuple[int, str]]:
    """Read an /Encoding /Differences array as code-to-character pairs.

    The array alternates a starting code with the glyph names that
    follow it: `[ 65 /A /B 90 /Z ]` puts A at 65, B at 66 and Z at 90.
    A name that resolves to no character still advances the code, or
    every later entry would be off by one.
    """
    out: list[tuple[int, str]] = []
    if not isinstance(array, pikepdf.Array):
        return out
    code = 0
    for item in array:
        if isinstance(item, pikepdf.Name):
            char = glyph_name_to_char(str(item).lstrip("/"))
            if char is not None:
                out.append((code, char))
            code += 1
            continue
        try:
            code = int(item)
        except TypeError:
            # Neither a code nor a glyph name: the rest of the array
            # cannot be positioned, so stop rather than guess.
            break
    return out


def read_tounicode(
    font: pikepdf.Object,
    problems: list[str] | None = None,
) -> ToUnicode | None:
    """Parse a font's /ToUnicode CMap, or explain why it could not be.

    Returns None both when the font has no /ToUnicode and when the one
    it has could not be read; the two are told apart by whether a
    description was recorded in `problems`.
    """
    tounicode = font.get("/ToUnicode")
    if tounicode is None:
        return None
    try:
        data = tounicode.read_bytes()
    except UNREADABLE_STREAM as exc:
        note(
            problems,
            "the /ToUnicode CMap could not be read, so the characters it "
            f"maps were not inspected: {exc}",
        )
        return None
    return parse_tounicode_map(data)


def iter_fonts(pdf: pikepdf.Pdf) -> Iterator[tuple[str, pikepdf.Object]]:
    """Yield (label, font object) for every font a page's resources reach.

    Fonts that only a Form XObject's own resources name are included: a
    page can draw all of its text inside one, and a font nobody looked
    at is a font whose leftovers nobody would find. The label is the
    path taken to reach it, so `page 1 /Fm0 /F1` is the /F1 of the form
    the page draws as /Fm0.

    Fonts reachable only from somewhere other than a page -- an
    annotation's appearance stream, or the form field defaults in
    /AcroForm -- are not among them, which is the same boundary the
    README draws under "Limitations".
    """
    for index, page in enumerate(pdf.pages, start=1):
        yield from resource_fonts(page_resources(page), f"page {index} ", set())


def resource_fonts(
    resources: pikepdf.Object | None,
    prefix: str,
    seen: set[tuple[int, int]],
    depth: int = 0,
) -> Iterator[tuple[str, pikepdf.Object]]:
    """Yield the fonts of one /Resources dictionary and of the forms in it.

    A Form XObject that carries no resources of its own draws with these
    ones, whose fonts have already been yielded, so only a form that
    brings its own is followed -- otherwise every font of the page would
    be reported a second time under the form's name.
    """
    if depth > 64:
        return
    fonts = resource_group(resources, "/Font")
    if fonts is not None:
        for name, font in fonts.items():
            yield f"{prefix}{name}", font
    xobjects = resource_group(resources, "/XObject")
    if xobjects is None:
        return
    for name, target in xobjects.items():
        if not is_form_xobject(target) or already_seen(target, seen):
            continue
        own = target.get("/Resources")
        if isinstance(own, pikepdf.Dictionary):
            yield from resource_fonts(own, f"{prefix}{name} ", seen, depth + 1)


def page_resources(page: pikepdf.Page) -> pikepdf.Object | None:
    """Find the /Resources dictionary that applies to a page.

    /Resources is inheritable: a page that carries none of its own uses
    the closest ancestor's in the page tree (ISO 32000 section 7.7.3.4).
    Walking up is read-only on purpose -- pikepdf's `page.resources`
    creates the dictionary when it is missing, and this tool never
    writes to the document it is inspecting.
    """
    node: pikepdf.Object | None = page.obj
    seen: set[tuple[int, int]] = set()
    while isinstance(node, pikepdf.Dictionary) and not already_seen(node, seen):
        resources = node.get("/Resources")
        if isinstance(resources, pikepdf.Dictionary):
            return resources
        node = node.get("/Parent")
    return None


def resource_group(resources: pikepdf.Object | None, key: str) -> pikepdf.Object | None:
    """Return one named group of a /Resources dictionary, or None.

    A group that is absent and a group that is not a dictionary come to
    the same thing here: there is nothing in it to look a name up in.
    """
    if not isinstance(resources, pikepdf.Dictionary):
        return None
    group = resources.get(key)
    return group if isinstance(group, pikepdf.Dictionary) else None


def font_resources(page: pikepdf.Page) -> pikepdf.Object | None:
    """Return the /Font resource dictionary a page uses, or None."""
    return resource_group(page_resources(page), "/Font")


def resource_scope(
    scopes: tuple[pikepdf.Object | None, ...],
    key: str,
) -> dict[str, pikepdf.Object]:
    """Merge one resource group across the scopes in effect, inner first.

    `scopes` runs from the innermost outwards: a Form XObject's own
    /Resources, then those of whatever drew it, and so on out to the
    page. ISO 32000 section 8.10.1 has a form carry every resource it
    uses, but producers do leave names to the page and readers do find
    them there, so falling back outwards is what a reader sees -- and a
    name this failed to resolve costs the text it was drawing.
    """
    merged: dict[str, pikepdf.Object] = {}
    for scope in reversed(scopes):
        group = resource_group(scope, key)
        if group is not None:
            merged.update({str(name): value for name, value in group.items()})
    return merged


def is_form_xobject(target: pikepdf.Object) -> bool:
    """Say whether an /XObject resource is a form rather than a picture.

    A Form XObject is a content stream in its own right, drawn by the
    `Do` operator, and it can draw text with fonts of its own (ISO 32000
    section 8.10). Anything else `Do` names -- an image, or the
    PostScript XObject older files carry -- draws no text this can read.
    """
    return (
        isinstance(target, pikepdf.Stream)
        and str(target.get("/Subtype", "")) == "/Form"
    )


def font_charset(
    font: pikepdf.Object,
    problems: list[str] | None = None,
    seen: set[tuple[int, int]] | None = None,
) -> list[str]:
    """Collect every character a font object claims it can render.

    Order is preserved: ToUnicode entries first, in CMap order, then the
    other sources of glyph names. Anything that could not be read is
    described in `problems`, so a font whose CMap is unreadable stays
    distinguishable from a font that declares nothing.
    """
    if seen is None:
        seen = set()
    if already_seen(font, seen):
        return []

    chars: list[str] = []

    cmap = read_tounicode(font, problems)
    if cmap is not None:
        chars += dedupe(char for _code, text in cmap.entries for char in text)

    encoding = font.get("/Encoding")
    if isinstance(encoding, pikepdf.Dictionary):
        chars += [
            char for _code, char in differences_entries(encoding.get("/Differences"))
        ]

    chars += descriptor_charset(font.get("/FontDescriptor"))
    chars += widths_charset(font, problems)

    descendants = font.get("/DescendantFonts")
    if descendants is not None and not isinstance(descendants, pikepdf.Array):
        note(
            problems,
            "/DescendantFonts is not an array, so the characters the fonts "
            "it lists declare were not inspected",
        )
    if isinstance(descendants, pikepdf.Array):
        for descendant in descendants:
            # An array can hold anything, and pikepdf hands a number
            # back as a plain int, which has none of the methods the
            # rest of this reads a font with.
            if not isinstance(descendant, pikepdf.Dictionary):
                note(
                    problems,
                    "a /DescendantFonts entry is not a font dictionary, so "
                    "the characters it declares were not inspected",
                )
                continue
            chars += font_charset(descendant, problems, seen)

    return dedupe(chars)


def descriptor_charset(descriptor: pikepdf.Object | None) -> list[str]:
    """Read the /CharSet glyph list that Type 1 subsets carry."""
    if not isinstance(descriptor, pikepdf.Dictionary):
        return []
    raw = descriptor.get("/CharSet")
    if not isinstance(raw, pikepdf.String):
        return []
    chars: list[str] = []
    for name in str(raw).split("/"):
        char = glyph_name_to_char(name.strip())
        if char:
            chars.append(char)
    return dedupe(chars)


def widths_charset(
    font: pikepdf.Object,
    problems: list[str] | None = None,
) -> list[str]:
    """Infer the encoded code range of a simple font from /Widths.

    A subset font keeps a width entry for every code it can draw. A code
    with a nonzero width that renders nothing in the visible text is the
    same orphan signal as a stale ToUnicode entry.

    An empty result covers two different situations: the font has no
    usable /Widths array, or its /Encoding is not one of the named ones
    this can turn into characters. Neither is reported as a problem,
    because in both cases the font has declared nothing that the visible
    text could be compared against -- an unreadable *entry* inside an
    otherwise usable array is reported, and is a different thing.
    """
    widths = font.get("/Widths")
    first = font.get("/FirstChar")
    if not isinstance(widths, pikepdf.Array) or first is None:
        return []
    table = BASE_ENCODINGS.get(str(font.get("/Encoding", "")))
    if table is None:
        return []
    try:
        start = int(first)
    except TypeError:
        note(problems, "/FirstChar is not a number, so /Widths was not read")
        return []
    chars: list[str] = []
    for offset, width in enumerate(widths):
        try:
            size = float(width)
        except TypeError:
            note(
                problems,
                f"/Widths entry {offset} is not a number, so the code it "
                "describes was not inspected",
            )
            continue
        if size <= 0:
            continue
        char = table.get(start + offset)
        if char is not None:
            chars.append(char)
    return dedupe(chars)


@dataclass(frozen=True)
class FontDecoder:
    """Turns the character codes of one font into the text it draws.

    A show-text operand is a string of character codes, not text. What
    each code draws is decided by the font in effect, so every font
    resource gets its own table: its /ToUnicode CMap where it has one,
    otherwise its /Encoding, with any /Differences applied over the base
    encoding.
    """

    label: str
    code_bytes: int
    table: dict[int, str]

    def decode(self, raw: bytes) -> tuple[str, int]:
        """Return the text `raw` draws, and how many codes had no mapping.

        Unmapped codes contribute nothing to the text. Emitting a
        placeholder would put characters into the "visible text" that
        the page never showed, which is exactly what the font-subset
        check compares against.
        """
        out: list[str] = []
        unmapped = 0
        for position in range(0, len(raw), self.code_bytes):
            code = int.from_bytes(raw[position : position + self.code_bytes], "big")
            text = self.table.get(code)
            if text is None:
                unmapped += 1
            else:
                out.append(text)
        return "".join(out), unmapped


def font_code_bytes(font: pikepdf.Object, cmap: ToUnicode | None) -> int:
    """Return how many bytes one character code takes in a font.

    A simple font (Type 1, TrueType, Type 3) always uses one byte per
    code. A composite font -- Subtype /Type0 -- uses whatever its
    /Encoding CMap defines, which is two bytes for /Identity-H,
    /Identity-V, and the predefined UCS-2 CMaps.
    """
    if str(font.get("/Subtype", "")) != "/Type0":
        return 1
    encoding = font.get("/Encoding")
    if isinstance(encoding, pikepdf.Stream):
        try:
            declared = codespace_bytes(encoding.read_bytes())
        except UNREADABLE_STREAM:
            declared = 0
        if declared:
            return declared
    if cmap is not None and cmap.code_bytes:
        return cmap.code_bytes
    return 2


def simple_font_table(font: pikepdf.Object) -> dict[int, str]:
    """Build the code-to-character table a simple font's /Encoding gives.

    A font with no /Encoding uses the one built into the font program,
    which this cannot read. StandardEncoding is the fallback ISO 32000
    names for that case; it agrees with ASCII except at the two quote
    codes.
    """
    encoding = font.get("/Encoding")
    if isinstance(encoding, pikepdf.Name):
        return dict(BASE_ENCODINGS.get(str(encoding), STANDARD_ENCODING))
    table = dict(STANDARD_ENCODING)
    if isinstance(encoding, pikepdf.Dictionary):
        base = encoding.get("/BaseEncoding")
        if isinstance(base, pikepdf.Name):
            table = dict(BASE_ENCODINGS.get(str(base), STANDARD_ENCODING))
        table.update(differences_entries(encoding.get("/Differences")))
    return table


def font_decoder(label: str, font: pikepdf.Object) -> FontDecoder:
    """Build the code-to-text table for one font resource.

    Most trustworthy source first: the font's own /ToUnicode CMap, which
    exists to say what text a code stands for, then the /Encoding, then
    the base encoding on its own.
    """
    cmap = read_tounicode(font)
    code_bytes = font_code_bytes(font, cmap)
    table: dict[int, str] = {}
    if code_bytes == 1:
        table.update(simple_font_table(font))
    if cmap is not None:
        table.update(cmap.entries)
    return FontDecoder(label, code_bytes, table)


def select_font(
    fonts: dict[str, pikepdf.Object],
    decoders: dict[str, FontDecoder],
    operands: Iterable[pikepdf.Object],
) -> tuple[str, FontDecoder | None]:
    """Resolve the font a Tf operator selects, caching the result.

    `fonts` is the /Font group of the resources in effect, merged across
    the scopes that were in effect where the text was drawn. Returns the
    resource name the operator asked for -- empty if it named none --
    and the decoder for it, or None when none of those resources define
    that font.
    """
    for operand in operands:
        if not isinstance(operand, pikepdf.Name):
            continue
        label = str(operand)
        if label in decoders:
            return label, decoders[label]
        font = fonts.get(label)
        if not isinstance(font, pikepdf.Dictionary):
            return label, None
        decoders[label] = font_decoder(label, font)
        return label, decoders[label]
    return "", None


def show_text_bytes(operands: Iterable[pikepdf.Object]) -> Iterator[bytes]:
    """Yield the raw character codes each show-text operand carries.

    The bytes are taken raw on purpose. Reading a show-text operand as a
    PDF text string applies the wrong rules entirely: a text string is
    PDFDocEncoded (or UTF-16 with a byte-order mark), while these bytes
    are codes in whatever encoding the current font defines.
    """
    for operand in operands:
        if isinstance(operand, pikepdf.String):
            yield bytes(operand)
        elif isinstance(operand, pikepdf.Array):
            for element in operand:
                if isinstance(element, pikepdf.String):
                    yield bytes(element)


def undecoded_note(label: str, count: int) -> str:
    """Describe text this could not read for want of the font that drew it.

    Two ways that happens: the text named a font nothing defines, or it
    named no font at all. The resources that failed to define it are the
    page's own, or a Form XObject's where the text was drawn inside one,
    which is why the wording names neither.
    """
    if not label:
        return (
            f"{count} byte(s) of page text were drawn before any font was "
            "selected, so what they spell could not be worked out"
        )
    return (
        f"{count} byte(s) of page text were drawn with {label}, which the "
        "resources in effect where it was drawn do not define, so what they "
        "spell could not be worked out"
    )


@dataclass
class PageText:
    """What reading one page's drawing instructions has turned up.

    `out` is the text so far, in drawing order. `unresolved` counts the
    bytes drawn with a font resource nothing defined, by the name the
    document asked for; `unmapped` counts the character codes a font had
    no mapping for, by font label. Both are counted rather than
    described one by one, because a font that fails once usually fails
    for every code it draws. `problems` holds anything else that could
    not be read.

    `drawn` records each form already followed, paired with the font
    and the resources it was followed with, so that a form drawn twice
    under two different fonts -- which draws different characters each
    time, because a form inherits the font in effect where it is drawn
    -- is read both times, while a form that draws itself cannot loop.
    Pairing it that way rather than keeping the whole path is also what
    keeps a file whose forms draw one another from costing far more
    work than it has objects.
    """

    out: list[str] = field(default_factory=list)
    unresolved: dict[str, int] = field(default_factory=dict)
    unmapped: dict[str, int] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    drawn: set[FormDrawing] = field(default_factory=set)


def already_drawn(
    form: pikepdf.Object,
    label: str,
    scope: pikepdf.Object | None,
    drawn: set[FormDrawing],
) -> bool:
    """Record one drawing of a form, reporting whether it is a repeat.

    A drawing is the form, the resource name of the font in effect, and
    the innermost resources it was drawn with, because those are what
    decide the characters it produces. Recording the form alone would
    drop the text of every drawing after the first, and a character the
    page showed but nothing recorded is a character the font-subset
    check reports as the remnant of a removed passage.

    A form that is not an indirect object is always drawn: it has no
    object number to record, and having no identity of its own it cannot
    be reached from two places, so it cannot form a loop either.
    """
    objgen = getattr(form, "objgen", (0, 0))
    if objgen == (0, 0):
        return False
    key: FormDrawing = (objgen, label, getattr(scope, "objgen", (0, 0)))
    if key in drawn:
        return True
    drawn.add(key)
    return False


def draw_content(
    content: pikepdf.Object | pikepdf.Page,
    scopes: tuple[pikepdf.Object | None, ...],
    found: PageText,
    current: FontDecoder | None = None,
    label: str = "",
    depth: int = 0,
) -> None:
    """Read the text one content stream draws, following Form XObjects.

    `scopes` is the /Resources dictionaries in effect, innermost first,
    and is never empty: the page's own resources are the last of them,
    and are None when the page has none. `current` and `label` are the
    font in effect where this stream starts.

    A form inherits the graphics state of whatever drew it, so
    text inside one can be drawn with a font selected before the `Do`
    that invoked it; a font selected inside the form does not leak back
    out, which is why both are arguments here rather than kept in
    `found`.
    """
    # `found.drawn` stops a form that draws itself, but only a form that
    # is an object in its own right, which is the only kind a document
    # read from a file can have. The depth limit is what stops the rest.
    if depth > 64:
        return
    fonts = resource_scope(scopes, "/Font")
    xobjects = resource_scope(scopes, "/XObject")
    decoders: dict[str, FontDecoder] = {}

    for instruction in pikepdf.parse_content_stream(content):
        operator = str(instruction.operator)
        if operator == "Tf":
            label, current = select_font(fonts, decoders, instruction.operands)
            continue
        if operator == "Do":
            draw_form(
                xobjects,
                scopes,
                instruction.operands,
                found,
                current,
                label,
                depth,
            )
            continue
        if operator not in SHOW_TEXT_OPERATORS:
            continue
        for raw in show_text_bytes(instruction.operands):
            if current is None:
                found.unresolved[label] = found.unresolved.get(label, 0) + len(raw)
                continue
            text, dropped = current.decode(raw)
            found.out.append(text)
            if dropped:
                found.unmapped[current.label] = (
                    found.unmapped.get(current.label, 0) + dropped
                )


def draw_form(
    xobjects: dict[str, pikepdf.Object],
    scopes: tuple[pikepdf.Object | None, ...],
    operands: Iterable[pikepdf.Object],
    found: PageText,
    current: FontDecoder | None,
    label: str,
    depth: int,
) -> None:
    """Follow a `Do` operator into the Form XObject it names.

    Four things stop it going any further. Two are described in
    `found.problems`, because both are text the page draws that nothing
    here could read: a name the resources in effect do not define, and a
    form whose own instructions will not parse -- the second costing the
    text that one form drew, rather than costing the whole page the way
    letting the failure out would. Two are silent and ordinary: `Do`
    naming something that is not a form, which draws no text at all, and
    a drawing of a form already read, which would only repeat characters
    already counted.
    """
    for operand in operands:
        if not isinstance(operand, pikepdf.Name):
            continue
        name = str(operand)
        target = xobjects.get(name)
        if target is None:
            found.problems.append(
                f"a form was drawn as {name}, which the resources in effect "
                "where it was drawn do not define, so the text it draws was "
                "not inspected"
            )
            return
        if not is_form_xobject(target):
            return
        if already_drawn(target, label, scopes[0], found.drawn):
            return
        try:
            draw_content(
                target,
                (target.get("/Resources"), *scopes),
                found,
                current,
                label,
                depth + 1,
            )
        except UNPARSABLE_CONTENT as exc:
            found.problems.append(
                f"the form drawn as {name} could not be parsed, so the text "
                f"it draws was not inspected: {exc}"
            )
        return


def _page_text(page: pikepdf.Page) -> tuple[str, list[str]]:
    """Decode the text one page draws, through the fonts it draws it with.

    Text drawn inside a Form XObject counts as text the page draws,
    because that is what a reader puts on the screen -- so this follows
    every `Do` that names one. A form the page never draws is a
    different thing, and is not page text.

    Returns the text and a description of every run that could not be
    decoded, so a page that yielded no text stays distinguishable from a
    page whose text could not be read.
    """
    found = PageText()
    draw_content(page, (page_resources(page),), found)

    problems = [undecoded_note(name, count) for name, count in found.unresolved.items()]
    problems += [
        f"{count} character code(s) drawn with {name} are mapped by neither "
        "its /ToUnicode CMap nor its /Encoding, so what they spell could not "
        "be worked out"
        for name, count in found.unmapped.items()
    ]
    return "".join(found.out), problems + found.problems


def extract_page_text(pdf: pikepdf.Pdf, report: Report | None = None) -> str:
    """Return the text the pages draw, decoded through their own fonts.

    This is not `pdftotext`. There is no layout analysis and nothing is
    inserted between runs: the result is the characters the content
    stream draws, in drawing order, one page per line. When `report` is
    given, every page and every run that could not be read is recorded
    there, so a document that yielded no text stays distinguishable from
    one whose text could not be read.
    """
    chunks: list[str] = []
    for index, page in enumerate(pdf.pages, start=1):
        try:
            text, problems = _page_text(page)
        except UNPARSABLE_CONTENT as exc:
            if report is not None:
                report.add(
                    Severity.WARNING,
                    CONTENT_STREAM,
                    "the page content stream could not be parsed, so the "
                    f"text it draws was not inspected: {exc}",
                    f"page {index}",
                )
            continue
        chunks.append(text)
        if report is not None:
            for problem in problems:
                report.add(Severity.WARNING, CONTENT_STREAM, problem, f"page {index}")
    return "\n".join(chunks)


def extract_structure_tree(pdf: pikepdf.Pdf) -> list[Extract]:
    """Pull text out of the tagged-PDF structure tree."""
    root = pdf.Root.get("/StructTreeRoot")
    if root is None:
        return []
    text = "\n".join(walk_struct(root, set()))
    if not text.strip():
        return []
    return [Extract(STRUCTURE_TREE, "/StructTreeRoot", text)]


def already_seen(node: pikepdf.Object, seen: set[tuple[int, int]]) -> bool:
    """Record an indirect object, reporting whether it was already visited.

    Identity has to come from the PDF, not from Python: pikepdf builds a
    fresh wrapper object on every access, so `id()` never repeats and a
    memo keyed on it silently fails to catch loops. Direct objects have
    no object number and cannot form a cycle, so they are always walked.
    """
    objgen = getattr(node, "objgen", (0, 0))
    if objgen == (0, 0):
        return False
    if objgen in seen:
        return True
    seen.add(objgen)
    return False


def walk_struct(
    node: pikepdf.Object,
    seen: set[tuple[int, int]],
    depth: int = 0,
) -> Iterator[str]:
    """Yield text carried by the tagged-PDF structure tree."""
    if depth > 64 or node is None or already_seen(node, seen):
        return

    if isinstance(node, pikepdf.Array):
        for item in node:
            yield from walk_struct(item, seen, depth + 1)
        return
    if not isinstance(node, pikepdf.Dictionary):
        return

    for attr in ("/ActualText", "/Alt", "/E", "/T", "/TU"):
        value = node.get(attr)
        if isinstance(value, pikepdf.String):
            yield str(value)

    kids = node.get("/K")
    if kids is not None:
        yield from walk_struct(kids, seen, depth + 1)


def extract_annotations(pdf: pikepdf.Pdf) -> list[Extract]:
    """Pull text out of annotation contents and form field values."""
    out: list[Extract] = []
    for index, page in enumerate(pdf.pages, start=1):
        for annot in page.get("/Annots") or []:
            if not isinstance(annot, pikepdf.Dictionary):
                continue
            subtype = str(annot.get("/Subtype", "")) or "/Annot"
            parts = [
                str(annot[k])
                for k in ("/Contents", "/V", "/DV", "/RC", "/T")
                if isinstance(annot.get(k), pikepdf.String)
            ]
            text = "\n".join(p for p in parts if p.strip())
            if text:
                out.append(Extract(ANNOTATIONS, f"page {index} {subtype}", text))
    return out


def extract_metadata(pdf: pikepdf.Pdf, report: Report | None = None) -> list[Extract]:
    """Pull DocInfo values and the XMP packet.

    A /Info entry that is not a dictionary is skipped here and reported
    by `check_metadata`, which is where findings about the document go.

    `report` is where an XMP packet that could not be read is recorded.
    None is not "no problem to report": it means this caller is not the
    one reporting, because `check_metadata` runs on every invocation and
    would otherwise say it twice.
    """
    out: list[Extract] = []
    info = pdf.trailer.get("/Info")
    if isinstance(info, pikepdf.Dictionary):
        for key, value in info.items():
            if isinstance(value, pikepdf.String) and str(value).strip():
                out.append(Extract(METADATA, f"DocInfo {key}", str(value)))
    meta = pdf.Root.get("/Metadata")
    if not isinstance(meta, pikepdf.Stream):
        return out
    try:
        xmp = meta.read_bytes().decode("utf-8", errors="ignore")
    except UNREADABLE_STREAM as exc:
        if report is not None:
            report.add(
                Severity.WARNING,
                METADATA,
                "the XMP metadata packet could not be read, so the metadata "
                f"it holds was not inspected: {exc}",
                object_label(meta),
            )
        return out
    if xmp.strip():
        out.append(Extract(METADATA, "XMP", xmp))
    return out


def extract_attachments(pdf: pikepdf.Pdf) -> list[Extract]:
    """List embedded file names and sizes.

    Attachment contents are deliberately not extracted: they are
    untrusted files, and writing them anywhere is a separate decision
    from reading text out of the document.

    A /Names entry that is not a dictionary yields nothing here and is
    reported by `check_attachments`, which is where findings about the
    document go.
    """
    names = pdf.Root.get("/Names")
    if not isinstance(names, pikepdf.Dictionary) or "/EmbeddedFiles" not in names:
        return []
    out: list[Extract] = []
    for label, size in _iter_embedded_files(names["/EmbeddedFiles"]):
        detail = f"{label} ({size} bytes)" if size is not None else label
        out.append(Extract(ATTACHMENTS, "embedded file", detail))
    return out


def _iter_embedded_files(
    tree: pikepdf.Object,
    seen: set[tuple[int, int]] | None = None,
) -> Iterator[tuple[str, int | None]]:
    """Walk a name tree, yielding (filename, size) for each attachment."""
    if seen is None:
        seen = set()
    if not isinstance(tree, pikepdf.Dictionary) or already_seen(tree, seen):
        return
    kids = tree.get("/Kids")
    if isinstance(kids, pikepdf.Array):
        for kid in kids:
            yield from _iter_embedded_files(kid, seen)
    entries = tree.get("/Names")
    if not isinstance(entries, pikepdf.Array):
        return
    # A name tree's /Names array alternates key, value, key, value.
    for position in range(0, len(entries) - 1, 2):
        key = entries[position]
        spec = entries[position + 1]
        label = str(key) if isinstance(key, pikepdf.String) else "(unnamed)"
        size: int | None = None
        if isinstance(spec, pikepdf.Dictionary):
            embedded = spec.get("/EF")
            if isinstance(embedded, pikepdf.Dictionary):
                stream = embedded.get("/F") or embedded.get("/UF")
                if isinstance(stream, pikepdf.Stream):
                    try:
                        size = len(stream.read_bytes())
                    except UNREADABLE_STREAM:
                        size = None
        yield label, size


def extract_raw_strings(pdf: pikepdf.Pdf, known: set[str]) -> list[Extract]:
    """Collect string objects anywhere in the document.

    This is the catch-all for text that lives outside the layers with
    dedicated checks -- outlines, optional content names, private
    dictionaries. Text already reported by a more specific layer is
    skipped so the dump does not repeat itself.
    """
    seen_objects: set[tuple[int, int]] = set()
    found: list[str] = []
    _walk_strings(pdf.trailer, seen_objects, found, 0)

    out: list[Extract] = []
    reported: set[str] = set()
    for text in found:
        if text in reported or text in known or not _looks_like_text(text):
            continue
        reported.add(text)
        out.append(Extract(RAW_STRINGS, "string object", text))
    return out


def _walk_strings(
    node: pikepdf.Object,
    seen: set[tuple[int, int]],
    found: list[str],
    depth: int,
) -> None:
    """Recurse through the object graph, collecting string values."""
    if depth > 64 or node is None or already_seen(node, seen):
        return

    if isinstance(node, pikepdf.String):
        found.append(str(node))
        return
    if isinstance(node, pikepdf.Array):
        for item in node:
            _walk_strings(item, seen, found, depth + 1)
        return
    if isinstance(node, pikepdf.Dictionary):
        for key, value in node.items():
            if str(key) in BINARY_KEYS:
                continue
            _walk_strings(value, seen, found, depth + 1)


def _looks_like_text(text: str) -> bool:
    """Reject binary blobs such as file identifiers and encryption keys.

    Note the trade-off: judging a value by how much of it is plain ASCII
    also rejects genuine text in scripts that use little or none of it.
    The layers with dedicated extraction -- metadata, annotations, the
    structure tree -- are never filtered this way, so this only affects
    the catch-all sweep for strings nothing else claims.
    """
    stripped = text.strip()
    if len(stripped) < MIN_TEXT_LENGTH or not any(c.isalnum() for c in stripped):
        return False
    ascii_text = sum(1 for c in stripped if " " <= c <= "~" or c in "\n\t")
    return ascii_text >= len(stripped) * MIN_ASCII_RATIO


def font_orphans(
    pdf: pikepdf.Pdf,
    visible_text: str,
    report: Report | None = None,
) -> Iterator[tuple[str, list[str]]]:
    """Yield (font label, orphaned characters) in CMap order.

    When `report` is given, anything a font declared that could not be
    read is recorded there first, so a font this could not inspect never
    passes for a font with nothing to declare.
    """
    visible = set(visible_text)
    for label, font in iter_fonts(pdf):
        problems: list[str] = []
        charset = font_charset(font, problems)
        if report is not None:
            for problem in problems:
                report.add(Severity.WARNING, FONT_CHARSET, problem, label)
        if not charset:
            continue
        orphans = [
            c
            for c in charset
            if c not in visible and c not in IGNORABLE_CHARS and c.isprintable()
        ]
        if orphans:
            yield label, orphans


def extract_font_orphans(pdf: pikepdf.Pdf, visible_text: str) -> list[Extract]:
    """Report orphaned glyph mappings as characters, never as text."""
    return [
        Extract(FONT_CHARSET, label, "".join(orphans), is_text=False)
        for label, orphans in font_orphans(pdf, visible_text)
    ]


def collect_extracts(pdf: pikepdf.Pdf, visible_text: str) -> list[Extract]:
    """Gather every recoverable piece of text, layer by layer."""
    specific: list[Extract] = []
    specific += extract_structure_tree(pdf)
    specific += extract_annotations(pdf)
    specific += extract_metadata(pdf)
    specific += extract_attachments(pdf)

    known = {e.text for e in specific}
    known.add(visible_text)

    out: list[Extract] = [Extract(CONTENT_STREAM, "visible page text", visible_text)]
    out += specific
    out += extract_raw_strings(pdf, known)
    out += extract_font_orphans(pdf, visible_text)

    def rank(extract: Extract) -> int:
        return LAYER_ORDER.index(extract.layer) if extract.layer in LAYER_ORDER else 99

    return sorted((e for e in out if e.text.strip()), key=rank)


def hidden_segments(extract: Extract, visible_norm: str) -> list[str]:
    """Return the parts of an extract that are absent from the page.

    The content stream is the baseline the others are compared against,
    so it never contributes hidden text. Font orphans are hidden by
    definition -- being absent from the visible text is what makes them
    orphans.
    """
    if extract.layer == CONTENT_STREAM:
        return []
    if not extract.is_text:
        return [extract.text]
    return [
        line
        for line in extract.text.splitlines()
        if line.strip() and normalize(line) not in visible_norm
    ]


def check_secrets(report: Report, extracts: list[Extract], secrets: list[str]) -> None:
    """Search each extracted layer of readable text for each secret.

    The font-subset layer is the one exception, and is skipped: its
    extract is a bag of characters rather than wording, so a secret
    whose letters all appear there has not been found -- it has only
    been shown that the font can draw those letters. `check_fonts`
    reports that layer on its own terms.
    """
    for extract in extracts:
        if not extract.is_text:
            continue
        haystack = normalize(extract.text)
        for secret in secrets:
            if normalize(secret) in haystack:
                detail = SECRET_DETAIL.get(extract.layer, "secret found")
                report.add(
                    Severity.CRITICAL,
                    extract.layer,
                    f"{detail}: {secret!r}",
                    extract.location,
                )


def stream_filters(stream: pikepdf.Object) -> list[str]:
    """Return the names of the filters a stream says were applied to it.

    /Filter is one name, or an array of them when the data went through
    several filters in turn (ISO 32000 section 7.3.8.2). Anything else
    -- a missing entry, or a value of some other type -- means no filter
    this can name.
    """
    declared = stream.get("/Filter")
    if isinstance(declared, pikepdf.Name):
        return [str(declared)]
    if isinstance(declared, pikepdf.Array):
        return [str(item) for item in declared if isinstance(item, pikepdf.Name)]
    return []


def split_ascii_armor(filters: list[str]) -> tuple[list[str], list[str]]:
    """Split a filter chain into its leading printable armor and the rest.

    A stream's filters are applied in the order they are written (ISO
    32000 section 7.3.8.2), so armor a producer wrapped the data in
    comes first. Everything from the first filter that is not armor
    onwards goes into the second list, armor or not.
    """
    for position, name in enumerate(filters):
        if name not in ASCII_ARMOR_FILTERS:
            return filters[:position], filters[position:]
    return filters, []


def undo_ascii85(data: bytes) -> bytes:
    """Decode ASCII85 data, supplying the end marker when it is missing.

    Raises ValueError when the data is not ASCII85, which is how a
    stream that named the filter but does not hold what it describes
    makes itself known.
    """
    body = data.strip()
    if not body.endswith(b"~>"):
        body += b"~>"
    return base64.a85decode(body, adobe=True)


def undo_asciihex(data: bytes) -> bytes:
    """Decode ASCIIHex data, stopping at the `>` that ends it.

    Raises ValueError when what is there is not hexadecimal digits.
    """
    digits = data.split(b">")[0]
    return unhex(b"".join(digits.split()))


def undo_ascii_armor(data: bytes, filters: list[str]) -> bytes | None:
    """Undo the printable-character filters in front of a stream's data.

    Returns None when the data does not decode -- which means the stream
    does not hold what its /Filter entry says it holds, and is not
    something to wave through.
    """
    for name in filters:
        try:
            data = (
                undo_ascii85(data) if name == "/ASCII85Decode" else undo_asciihex(data)
            )
        except ValueError:
            return None
    return data


def picture_bytes(stream: pikepdf.Object, stored: bytes) -> bytes | None:
    """Return the picture a stream holds, or None when it holds no picture.

    A stream whose filters pikepdf will not run is only excused from
    being reported as unread when it really is a picture, because
    /Filter is a claim the document makes about itself and this tool
    exists to distrust exactly that. A stream that says /DCTDecode and
    holds compressed text would otherwise be waved through in silence,
    which is how a leak nothing could read comes back as nothing to
    find.

    So the name has to be corroborated by something other than itself.
    For the two formats that begin with a signature -- JPEG and JPEG
    2000 -- the bytes have to start with it, which the stream cannot
    talk its way out of.

    The two fax formats begin with no fixed bytes, so there is nothing
    to check them against, and the corroboration there is weaker: the
    stream has to be an image XObject, and to carry the size every image
    XObject is required to declare (ISO 32000 Table 89). A document that
    writes out a whole image dictionary around bytes that are not an
    image defeats that, and the README says so under "Rasterized pages";
    what it catches is the ordinary case, a stream that names a filter
    it does not use.

    Printable-character wrapping in front of the image filter is undone
    here rather than reported. It carries no compression, and the JPEGs
    that Adobe Distiller and the producers descended from it write
    arrive inside it, so what is returned is the picture with the
    wrapping off -- which is what the raw sweep then searches.
    """
    armor, rest = split_ascii_armor(stream_filters(stream))
    if not rest or not set(rest) <= IMAGE_FILTERS:
        return None
    payload = undo_ascii_armor(stored, armor)
    if payload is None:
        return None
    signatures = IMAGE_SIGNATURES.get(rest[0])
    if signatures is not None:
        return payload if payload.startswith(signatures) else None
    return payload if is_image_xobject(stream) else None


def is_image_xobject(stream: pikepdf.Object) -> bool:
    """Say whether a stream is shaped like the image XObject it claims.

    ISO 32000 Table 89 requires an image XObject to declare its width
    and height as numbers, so a stream that says /Subtype /Image without
    them is not an image dictionary any producer wrote.
    """
    if str(stream.get("/Subtype", "")) != "/Image":
        return False
    return all(is_number(stream.get(key)) for key in ("/Width", "/Height"))


def is_number(value: pikepdf.Object | None) -> bool:
    """Say whether a PDF object is a number this can read as one."""
    if value is None:
        return False
    try:
        float(value)
    except TypeError:
        return False
    return True


def stream_bytes(stream: pikepdf.Object) -> tuple[bytes, str | None]:
    """Return what a stream holds, and what stopped it being decoded.

    Undoing the declared filters is the first choice. When that fails,
    the bytes as they are stored are the second: a stream that claims to
    be compressed and is not gives up its text exactly that way, and
    searching what is there beats searching nothing.

    The second value is the description for the report, and is None when
    there is nothing to report. That covers two cases: the stream
    decoded, or it holds a picture, whose filter names the format of the
    bytes rather than a compression this could undo. A page with a
    picture on it is not a document a layer of which could not be read,
    and a scanned document is made of them -- but what makes a stream a
    picture is what is in it, not what it calls itself. `picture_bytes`
    is where that is decided.
    """
    try:
        return stream.read_bytes(), None
    except UNREADABLE_STREAM as undecoded:
        reason = undecoded
    try:
        stored = stream.read_raw_bytes()
    except UNREADABLE_STREAM as exc:
        return b"", (
            "the stream could not be read at all, so nothing it holds was "
            f"inspected: {exc}"
        )
    picture = picture_bytes(stream, stored)
    if picture is not None:
        return picture, None
    return stored, (
        "the stream's filters could not be undone, so it was searched as it "
        f"is stored rather than as the data they describe: {reason}"
    )


def check_raw_objects(pdf: pikepdf.Pdf, report: Report, secrets: list[str]) -> None:
    """Read every stream and string, and search for any secrets given.

    This is a byte-level sweep, separate from the string-object
    extraction used by the dump modes: it catches text embedded in
    places that are not string objects at all, such as an XML island or
    a leftover font program.

    The sweep runs whether or not secrets were named, because the point
    of it is not only the matching. A stream that says it is compressed
    and cannot be decompressed is a layer of this document that nothing
    here could read as the document describes it, and saying so is what
    keeps a run that found nothing distinguishable from a run that could
    not look. Without secrets to match, that report is the whole of the
    check's output.
    """
    needles = [normalize(s) for s in secrets]
    for obj in pdf.objects:
        blob = b""
        where = object_label(obj)
        if isinstance(obj, pikepdf.Stream):
            blob, problem = stream_bytes(obj)
            if problem is not None:
                report.add(Severity.WARNING, RAW_OBJECTS, problem, where)
        elif isinstance(obj, pikepdf.String):
            blob = bytes(obj)
        if not blob or not needles:
            continue
        hay = normalize(blob.decode("utf-8", errors="ignore"))
        hay_16 = normalize(blob.decode("utf-16-be", errors="ignore"))
        for secret, needle in zip(secrets, needles, strict=True):
            if needle in hay or needle in hay_16:
                report.add(
                    Severity.CRITICAL,
                    RAW_OBJECTS,
                    f"secret found in raw object data: {secret!r}",
                    where,
                )


def check_structure_tree(pdf: pikepdf.Pdf, report: Report) -> None:
    """Note whether the document carries a structure tree at all."""
    root = pdf.Root.get("/StructTreeRoot")
    if root is None:
        report.add(
            Severity.INFO,
            STRUCTURE_TREE,
            "document is not tagged; no structure tree to inspect",
        )
        return
    text = "\n".join(walk_struct(root, set()))
    report.add(
        Severity.INFO,
        STRUCTURE_TREE,
        f"tagged PDF: {len(text)} characters of structure text inspected",
    )


def check_redact_annotations(pdf: pikepdf.Pdf, report: Report) -> None:
    """Flag redaction marks that were saved but never applied."""
    for index, page in enumerate(pdf.pages, start=1):
        for annot in page.get("/Annots") or []:
            if not isinstance(annot, pikepdf.Dictionary):
                continue
            if str(annot.get("/Subtype", "")) == "/Redact":
                report.add(
                    Severity.CRITICAL,
                    ANNOTATIONS,
                    "unapplied /Redact annotation -- marks were saved, not applied",
                    f"page {index}",
                )


def check_metadata(pdf: pikepdf.Pdf, report: Report) -> None:
    """Echo DocInfo values, which redaction tools do not clean.

    This re-runs the metadata extraction rather than reusing the dump's
    extracts, so the values are reported on every run and not only when
    a dump mode or a secret asked for extraction. It is also the one
    call that passes the report along, which is what makes an XMP packet
    nobody could read a finding rather than a silent absence.
    """
    info = pdf.trailer.get("/Info")
    if info is not None and not isinstance(info, pikepdf.Dictionary):
        report.add(
            Severity.WARNING,
            METADATA,
            "the document information entry (/Info) is not a dictionary, so "
            "the document properties were not inspected",
            object_label(info),
        )
    for extract in extract_metadata(pdf, report):
        if extract.location.startswith("DocInfo"):
            report.add(
                Severity.INFO,
                METADATA,
                f"{extract.location} = {extract.text!r}",
            )


def check_attachments(pdf: pikepdf.Pdf, report: Report) -> None:
    """Flag embedded files, which travel with the document unredacted.

    The document's list of attachments hangs off /Names, which is a
    dictionary in every document that has one. A document where it is
    something else is not a document with no attachments -- it is one
    whose attachments could not be looked for, and asking pikepdf for a
    key of a value that is not a dictionary raises rather than answering
    no.
    """
    names = pdf.Root.get("/Names")
    if names is None:
        return
    if not isinstance(names, pikepdf.Dictionary):
        report.add(
            Severity.WARNING,
            ATTACHMENTS,
            "the document's name dictionary (/Names) is not a dictionary, so "
            "embedded file attachments were not inspected",
            object_label(names),
        )
        return
    if "/EmbeddedFiles" not in names:
        return
    report.add(
        Severity.WARNING,
        ATTACHMENTS,
        "document contains embedded file attachments; inspect them separately",
    )


def check_fonts(pdf: pikepdf.Pdf, report: Report, visible_text: str) -> None:
    """Detect orphaned glyph mappings left behind by post-hoc redaction."""
    for label, orphans in font_orphans(pdf, visible_text, report):
        sample = "".join(orphans)[:60]
        severity = Severity.WARNING if len(orphans) < 3 else Severity.CRITICAL
        report.add(
            severity,
            FONT_CHARSET,
            (
                f"{len(orphans)} character(s) mapped by the font subset but absent "
                f"from visible text, in CMap order: {sample!r} -- consistent with "
                "text removed from the content stream but not the font subset"
            ),
            label,
        )


def load_secrets(args: argparse.Namespace) -> list[str]:
    """Collect secrets from --secret and --secret-file.

    Raises OSError if the file named by --secret-file cannot be opened,
    and UnicodeDecodeError if it is not UTF-8 text. Both are conditions
    of the invocation, not of the document, and the caller reports them
    as usage errors.
    """
    secrets: list[str] = list(args.secret or [])
    if args.secret_file:
        content = Path(args.secret_file).read_text(encoding="utf-8")
        secrets.extend(line.strip() for line in content.splitlines() if line.strip())
    return secrets


def analyze(
    path: Path,
    secrets: list[str],
    want_extracts: bool = False,
) -> tuple[Report, list[Extract]]:
    """Run every check against one PDF.

    Returns the report and, when `want_extracts` is set, the recovered
    text each layer yielded.
    """
    report = Report(path=path)
    extracts: list[Extract] = []
    with pikepdf.open(path) as pdf:
        visible_text = extract_page_text(pdf, report)
        if want_extracts or secrets:
            extracts = collect_extracts(pdf, visible_text)
        if secrets:
            check_secrets(report, extracts, secrets)
        check_raw_objects(pdf, report, secrets)
        check_structure_tree(pdf, report)
        check_redact_annotations(pdf, report)
        check_metadata(pdf, report)
        check_attachments(pdf, report)
        check_fonts(pdf, report, visible_text)
    return report, extracts if want_extracts else []


def select_dump(
    extracts: list[Extract],
    visible_text: str,
    mode: DumpMode,
) -> list[Extract]:
    """Reduce the extracts to what the chosen dump mode should output."""
    if mode == "all":
        return extracts
    visible_norm = normalize(visible_text)
    out: list[Extract] = []
    for extract in extracts:
        segments = hidden_segments(extract, visible_norm)
        if segments:
            out.append(
                Extract(
                    extract.layer,
                    extract.location,
                    "\n".join(segments),
                    extract.is_text,
                )
            )
    return out


def render_dump(path: Path, mode: DumpMode, extracts: list[Extract]) -> str:
    """Format recovered text for a terminal or a file."""
    label = "hidden text" if mode == "hidden" else "recoverable text"
    lines = [f"=== {label} recovered from {path} ==="]
    if not extracts:
        lines.append("")
        lines.append("(nothing recovered)")
        return "\n".join(lines) + "\n"
    for extract in extracts:
        where = f" [{extract.location}]" if extract.location else ""
        note = "" if extract.is_text else " (characters, not text; CMap order)"
        lines.append("")
        lines.append(f"--- {extract.layer}{where}{note} ---")
        lines.append(extract.text)
    return "\n".join(lines) + "\n"


def dump_to_json(
    mode: DumpMode,
    extracts: list[Extract],
    visible_text: str,
) -> DumpJSON:
    """Serialize recovered text for --json output."""
    visible_norm = normalize(visible_text)
    return {
        "mode": mode,
        "extracts": [
            {
                "layer": e.layer,
                "location": e.location,
                "hidden": bool(hidden_segments(e, visible_norm)),
                "is_text": e.is_text,
                "text": e.text,
            }
            for e in extracts
        ],
    }


def check_output_path(output: Path, pdf: Path, force: bool) -> str | None:
    """Return why `output` is not safe to write, or None when it is safe.

    Recovered text is the sensitive content itself, so this refuses to
    clobber anything by accident -- above all the PDF under inspection.
    """
    parent = output.parent if str(output.parent) else Path(".")
    if not parent.is_dir():
        return f"output directory does not exist: {parent}"
    if not os.access(parent, os.W_OK):
        return f"output directory is not writable: {parent}"
    if output.is_dir():
        return f"output path is a directory: {output}"
    try:
        if output.exists() and pdf.exists() and output.samefile(pdf):
            return f"refusing to overwrite the PDF under inspection: {output}"
    except OSError as exc:
        return f"could not inspect output path {output}: {exc}"
    if output.exists() and not force:
        return f"output file already exists (use --force to overwrite): {output}"
    return None


def write_output(output: Path, text: str) -> None:
    """Write recovered text with owner-only permissions.

    The mode given to `os.open` applies only to a file it creates, so
    overwriting an existing file would otherwise keep that file's
    permissions -- writing recovered secrets into a world-readable file.
    Setting the mode on the open descriptor covers both cases, and does
    it before anything is written.
    """
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        os.fchmod(fd, 0o600)
        handle.write(text)


class UsageErrorParser(argparse.ArgumentParser):
    """An argument parser that exits 4, not 2, on a usage error.

    argparse exits 2 by default, which in this tool means "redacted
    content is recoverable" -- the most alarming verdict it has. A
    mistyped option must never be mistaken for a failed redaction.
    """

    def error(self, message: str) -> NoReturn:
        """Report a bad invocation and exit with the usage-error code."""
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line parser."""
    parser = UsageErrorParser(
        prog="pdf-redaction-check",
        description="Verify that a PDF redaction actually removed the content.",
    )
    parser.add_argument("pdf", type=Path, help="PDF file to inspect")
    parser.add_argument(
        "-s",
        "--secret",
        action="append",
        metavar="TEXT",
        help="text that must NOT appear anywhere (repeatable)",
    )
    parser.add_argument(
        "--secret-file",
        type=Path,
        metavar="PATH",
        help="file with one secret per line",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")

    dump = parser.add_mutually_exclusive_group()
    dump.add_argument(
        "--dump-hidden",
        action="store_true",
        help="output recoverable text that is NOT on the visible page",
    )
    dump.add_argument(
        "--dump-all",
        action="store_true",
        help="output all recoverable text, marking what is not visible",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="PATH",
        help="write recovered text to PATH instead of stdout",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="allow --output to overwrite an existing file",
    )
    return parser


def verdict_code(report: Report) -> int:
    """Map the worst finding in a report to the process exit code."""
    if report.worst is Severity.CRITICAL:
        return EXIT_RECOVERABLE
    if report.worst is Severity.WARNING:
        return EXIT_SUSPICIOUS
    return EXIT_CLEAN


def print_report(payload: ReportJSON, report: Report, as_json: bool) -> None:
    """Print the findings and the verdict to standard output."""
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    print(f"=== redaction check: {report.path} ===")
    for finding in report.findings:
        print(finding.render())
    worst = report.worst
    if worst is Severity.CRITICAL:
        print("\nRESULT: FAILED -- redacted content is still recoverable.")
    elif worst is Severity.WARNING:
        print("\nRESULT: SUSPICIOUS -- review the warnings above.")
    else:
        print("\nRESULT: no evidence of surviving content.")


def warn(message: str) -> None:
    """Print a diagnostic to standard error, whatever state it is in.

    None of these messages is the verdict, so an error stream this
    cannot write to costs the message and nothing else: the exit code is
    still the one the findings earned, which is the same promise the
    report itself makes.

    Three states have to be survived, and only the first is a reader
    that hung up. A stream someone has closed raises ValueError rather
    than an OSError, and both are caught here because the recovery is
    the same one either way -- this is the whole of the recovery path,
    not a guard wrapped around real work. And standard error is None
    when the process was started with that file descriptor closed, where
    `print` would fall back to standard output and put a diagnostic in
    the middle of the report.
    """
    if sys.stderr is None:
        return
    try:
        print(message, file=sys.stderr)
    except (OSError, ValueError):
        pass


def discard_stdout() -> None:
    """Point standard output at the null device.

    Called once the reader on the other end of a pipe has gone. Text
    already buffered can never be delivered, and left alone the
    interpreter tries again while shutting down, fails the same way, and
    replaces this program's exit code with one of its own. Redirecting
    the file descriptor is the idiom the Python documentation gives for
    this ("Note on SIGPIPE").

    It does nothing unless this process owns the real standard output.
    Redirecting a file descriptor is not undoable and not local to this
    function, so a caller that has put something else in front of
    standard output -- a test harness, an embedding application -- keeps
    what it installed.
    """
    if sys.stdout is not sys.__stdout__:
        return
    try:
        fileno = sys.stdout.fileno()
    except (OSError, ValueError):
        return
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, fileno)
    os.close(devnull)


def main(argv: list[str] | None = None) -> int:
    """Run one check and return the process exit code.

    `argv` is the argument list to parse. None is a request to read
    `sys.argv`, which is what the console script wants; a list is used
    by the tests and by anything embedding this.

    The exit codes are public API:

    * 0 -- no evidence of surviving content
    * 1 -- suspicious: the worst finding is a warning
    * 2 -- failed: redacted content is recoverable
    * 3 -- the check could not be completed, because the file could not
      be read, the output path was unusable, or the write failed
    * 4 -- usage error: the arguments were wrong
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    mode: DumpMode | None = None
    if args.dump_hidden:
        mode = "hidden"
    elif args.dump_all:
        mode = "all"
    if args.output is not None and mode is None:
        parser.error("--output requires --dump-hidden or --dump-all")
    if args.force and args.output is None:
        parser.error("--force requires --output")

    if not args.pdf.is_file():
        warn(f"error: no such file: {args.pdf}")
        return EXIT_INCOMPLETE

    if args.output is not None:
        problem = check_output_path(args.output, args.pdf, args.force)
        if problem:
            warn(f"error: {problem}")
            return EXIT_INCOMPLETE

    try:
        secrets = load_secrets(args)
    except OSError as exc:
        warn(f"error: could not read {args.secret_file}: {exc}")
        return EXIT_USAGE
    except UnicodeDecodeError as exc:
        warn(f"error: {args.secret_file} is not UTF-8 text: {exc}")
        return EXIT_USAGE

    try:
        report, extracts = analyze(args.pdf, secrets, want_extracts=bool(mode))
    except pikepdf.PdfError as exc:
        warn(f"error: could not read {args.pdf}: {exc}")
        return EXIT_INCOMPLETE

    visible = next(
        (e.text for e in extracts if e.layer == CONTENT_STREAM),
        "",
    )
    selected = select_dump(extracts, visible, mode) if mode else []

    payload = report.to_dict()
    if mode and args.output is None and args.json:
        payload["dump"] = dump_to_json(mode, selected, visible)

    try:
        print_report(payload, report, args.json)
        if mode and args.output is None and not args.json:
            print()
            print(render_dump(args.pdf, mode, selected), end="")
        # Deliver it here, where a reader that has hung up is still this
        # function's problem. Standard output on a pipe is block
        # buffered, so a report this short is still sitting in the
        # buffer at this point; left to the interpreter to flush while
        # shutting down, the failure lands somewhere that can only
        # complain and replace the exit code with one of its own.
        sys.stdout.flush()
    except BrokenPipeError:  # piped into head/less
        discard_stdout()

    if mode and args.output is not None:
        body = (
            json.dumps(
                dump_to_json(mode, selected, visible),
                indent=2,
                ensure_ascii=False,
            )
            + "\n"
            if args.json
            else render_dump(args.pdf, mode, selected)
        )
        try:
            write_output(args.output, body)
        except OSError as exc:
            warn(f"error: could not write {args.output}: {exc}")
            return EXIT_INCOMPLETE
        warn(f"wrote {len(selected)} recovered block(s) to {args.output}")

    return verdict_code(report)


def run() -> int:
    """Console-script entry point: main() plus a last-resort pipe guard.

    A broken pipe while the report is being printed is handled inside
    `main`, which still knows the verdict. Reaching here means the pipe
    broke before there was one, so the honest answer is that the check
    did not complete.
    """
    try:
        return main()
    except BrokenPipeError:
        discard_stdout()
        return EXIT_INCOMPLETE


if __name__ == "__main__":
    raise SystemExit(run())
