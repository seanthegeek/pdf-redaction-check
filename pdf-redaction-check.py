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
from collections import deque
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Literal, NoReturn, NotRequired, TypedDict

import pikepdf

# qpdf's own content-stream parser, which hands one object over at a
# time. pikepdf's `parse_content_stream` is the documented way in, and
# it builds a list of every instruction in the stream before the first
# one can be looked at, which is what makes a content stream a way to
# spend a machine's memory from a file of a few kilobytes -- see
# `ContentReader`. This name is not exported at the top level and is not
# in pikepdf's documentation, so it may move without notice; it has been
# where it is since pikepdf 8.0, which is the floor pyproject.toml
# declares. A pikepdf that moves it fails here, at import, rather than
# part way through reading somebody's document, and there is deliberately
# nothing to fall back to: falling back to the parser above would put
# the memory cost back without saying so.
from pikepdf._core import StreamParser

# Process exit codes. These are public API -- people wire them into
# pre-send hooks and CI gates -- so the meaning of a code may not change
# without a major version bump and a README update in the same commit.
EXIT_CLEAN = 0
EXIT_SUSPICIOUS = 1
EXIT_RECOVERABLE = 2
EXIT_INCOMPLETE = 3
EXIT_USAGE = 4

# How many levels down any walk of the document goes before it stops.
# Every structure this follows -- the tag tree, the object graph, forms
# drawn inside forms, the resources reached through them, a font's chain
# of descendant fonts, and the name tree the attachments hang off -- can
# be nested as deeply as a file cares to nest it, and a hostile one
# nests it forever. Stopping is the defense; stopping quietly is not
# allowed, so every walk that reaches this limit says where it gave up.
MAX_DEPTH = 64

# How many operands one drawing instruction is read with. The operands
# arrive one at a time and are held until the operator that uses them
# arrives, so a stream that writes nothing but operands would be held
# whole in memory -- and an operand is a byte or two that compresses to
# almost nothing, so a file of a few kilobytes could ask for as much
# memory as the machine has. No operator in ISO 32000 takes more than a
# handful, and the longest run a producer writes is the dictionary of an
# inline image, so a limit this far above either is only ever reached by
# a file built to reach it. Past it the operands written earliest are
# dropped -- an operator uses the ones written last -- and the drop is
# reported: text dropped in silence is the one thing this tool may not
# do.
#
# This bounds how many operands are held, not how large one of them is.
# A single array operand is built whole by the parser before it arrives
# here, so an array of a million empty strings still costs what it costs
# to build; the README says so under "Limitations".
MAX_OPERANDS = 64

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


class UsageError(RuntimeError):
    """The invocation asks for something this cannot act on.

    A condition of the command line rather than of the document, so it
    ends the run with the usage-error exit code and no verdict. It
    subclasses RuntimeError rather than Exception so that a caller
    embedding this can catch it without sweeping in unrelated bugs.
    """


class Severity(Enum):
    """How much a finding should worry the operator."""

    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


# The two dump modes. Anything else is not a mode this tool has.
DumpMode = Literal["hidden", "all"]

# What names the font a drawing was made with: the object number and
# generation of the font dictionary, or -- for a font dictionary written
# out in place, which has no number of its own -- what that font turns
# every character code into. See `font_identity`. The two are different
# shapes, so a font of one kind is never mistaken for one of the other.
FontIdentity = tuple[int, int] | tuple[int, frozenset[tuple[int, str]]]

# One drawing of a Form XObject: the form, the resource name of the font
# in effect, which font that name resolved to, and the content stream
# that drew it. See `already_drawn`.
FormDrawing = tuple[tuple[int, int], str, FontIdentity, tuple[int, int]]


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


def depth_limit_note(what: str, stops: list[str]) -> str:
    """Describe a walk that stopped at the depth limit.

    `what` names the structure that was being walked. `stops` holds the
    place each branch of it gave up at, in the order they were reached,
    so the count says how much went unread and the first says where to
    start looking.

    Raises ValueError when `stops` is empty. A walk that gave up nowhere
    has nothing to describe, and the message this would build for it --
    "0 branch(es) of it below that depth were not inspected" -- reports
    a walk that finished as a walk that stopped short.
    """
    if not stops:
        raise ValueError(
            "depth_limit_note needs the place at least one branch stopped at"
        )
    return (
        f"{what} is nested more than {MAX_DEPTH} levels deep, so "
        f"{len(stops)} branch(es) of it below that depth were not inspected"
    )


def object_label(obj: pikepdf.Object | pikepdf.Page) -> str:
    """Name an indirect object by its number, for a finding's location.

    A page is named the same way as anything else: pikepdf's page
    wrapper carries the object number of the dictionary underneath it.
    """
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

    A character map lives in a stream, so a /ToUnicode that is anything
    else has no bytes to parse. Numbers are the shape that has to be
    checked for rather than caught: pikepdf hands a number back as a
    plain Python object, which raises where a dictionary or an array
    raises a PDF error.
    """
    tounicode = font.get("/ToUnicode")
    if tounicode is None:
        return None
    if not isinstance(tounicode, pikepdf.Stream):
        note(
            problems,
            "the /ToUnicode entry is not a stream, so it is not a character "
            "map and the characters it would have mapped were not inspected",
        )
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


def iter_fonts(
    pdf: pikepdf.Pdf,
    stops: list[str] | None = None,
) -> Iterator[tuple[str, pikepdf.Object]]:
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

    `stops` is where forms nested deeper than the walk follows are
    recorded, for a caller that reports them. None means this caller is
    not the one reporting, and never means there were none: a font
    nobody reached is a font whose leftovers nobody looked for.
    """
    for index, page in enumerate(pdf.pages, start=1):
        yield from resource_fonts(page_resources(page), f"page {index} ", set(), stops)


def resource_fonts(
    resources: pikepdf.Object | None,
    prefix: str,
    seen: set[tuple[int, int]],
    stops: list[str] | None = None,
    depth: int = 0,
) -> Iterator[tuple[str, pikepdf.Object]]:
    """Yield the fonts of one /Resources dictionary and of the forms in it.

    A Form XObject that carries no resources of its own draws with these
    ones, whose fonts have already been yielded, so only a form that
    brings its own is followed -- otherwise every font of the page would
    be reported a second time under the form's name.

    Forms nest, so the walk is bounded, and each form it stopped short
    of is recorded in `stops`.
    """
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
        if not isinstance(own, pikepdf.Dictionary):
            continue
        if depth >= MAX_DEPTH:
            if stops is not None:
                stops.append(object_label(target))
            continue
        yield from resource_fonts(own, f"{prefix}{name} ", seen, stops, depth + 1)


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
    stops: list[str] | None = None,
    depth: int = 0,
) -> list[str]:
    """Collect every character a font object claims it can render.

    Order is preserved: ToUnicode entries first, in CMap order, then the
    other sources of glyph names. Anything that could not be read is
    described in `problems`, so a font whose CMap is unreadable stays
    distinguishable from a font that declares nothing.

    A font is a dictionary, and a /Font resource group can name anything
    at all: pikepdf hands a number back as a plain Python object, which
    has none of the methods the rest of this reads a font with. Such a
    resource is not a font that declares no characters -- it is a font
    nobody could read, and is reported as one.

    A composite font's characters are declared by the descendant font it
    lists, which is a font in its own right and can list a descendant of
    its own, so the walk down that chain is bounded like every other
    here. `stops` is where the places it gave up at are recorded, one
    per branch that went deeper than the limit. Every path through the
    tool passes a list; None is for a caller collecting nothing, which
    is what a test reading this on its own wants, and never means there
    was nothing to record.
    """
    if depth > MAX_DEPTH:
        if stops is not None:
            stops.append(object_label(font))
        return []
    if not isinstance(font, pikepdf.Dictionary):
        note(
            problems,
            "the font resource is not a font dictionary, so the characters "
            "it declares were not inspected",
        )
        return []
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
            chars += font_charset(descendant, problems, seen, stops, depth + 1)

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
                f"the /Widths entry for character code {start + offset} is "
                "not a number, so that code was not inspected",
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

    `identity` names the font this was built from, and is what tells two
    fonts apart that a document selects by the same resource name; see
    `font_identity` and `already_drawn`.
    """

    label: str
    code_bytes: int
    table: dict[int, str]
    identity: FontIdentity = (0, 0)

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


def font_identity(
    font: pikepdf.Object, code_bytes: int, table: dict[int, str]
) -> FontIdentity:
    """Name the font a drawing was made with, for `already_drawn`.

    A font dictionary that is an indirect object is named by its number
    and generation, which is exact and costs nothing to compare.

    A font dictionary written out in place has no number to give, and
    naming every such font the same thing would make two of them under
    one resource name look like one font -- which drops the second
    drawing's text, and leaves the font that really drew it looking like
    it declares characters the page never showed. What stands in for the
    number is how the font reads a run of bytes: how many bytes it takes
    per character code, and what each code turns into. Both matter. Two
    fonts can agree on every code and still draw different text, because
    one reads the bytes a code at a time and the other two at a time --
    so the width has to be part of the name, or a one-byte font and a
    two-byte font with the same table look like one font and the second
    drawing's text is dropped.

    A width paired with a table cannot collide with a number and
    generation: the second half of one is a set, of the other an int.
    """
    objgen = getattr(font, "objgen", (0, 0))
    if objgen != (0, 0):
        return objgen
    return (code_bytes, frozenset(table.items()))


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
    return FontDecoder(label, code_bytes, table, font_identity(font, code_bytes, table))


@dataclass(frozen=True)
class FontState:
    """The font a content stream is drawing with.

    `label` is the resource name the last Tf operator asked for, and is
    empty when no font has been selected yet. `decoder` is what that
    name resolved to, and is None when nothing usable came back.

    `defined` says whether the resources in effect name that resource at
    all. It is what tells a name nothing defines apart from a name
    defined as something other than a font dictionary: both leave text
    nobody could read, but they are two different faults in the
    document, and only one of them is a resource that is missing.
    """

    label: str = ""
    decoder: FontDecoder | None = None
    defined: bool = False

    @property
    def identity(self) -> FontIdentity:
        """Name the font in effect, for the record of a drawing.

        (0, 0) is the answer for a name that resolved to nothing: no
        font dictionary was reached, so there is none to name. No font
        this could read ever answers with it -- an indirect object's
        number is never zero, and a font written out in place is named
        by what it decodes to instead. See `font_identity`.
        """
        return self.decoder.identity if self.decoder is not None else (0, 0)


# The font in effect before any Tf operator has selected one. A content
# stream starts here, and so does a form that is drawn before the stream
# drawing it has selected a font.
NO_FONT = FontState()


def select_font(
    fonts: dict[str, pikepdf.Object],
    decoders: dict[str, FontDecoder],
    operands: Iterable[pikepdf.Object],
) -> FontState:
    """Resolve the font a Tf operator selects, caching the result.

    `fonts` is the /Font group of the resources in effect, merged across
    the scopes that were in effect where the text was drawn. Returns the
    font now in effect: the resource name the operator asked for --
    empty if it named none -- what that name resolved to, and whether
    those resources define the name at all.

    A name they define as something other than a font dictionary
    resolves to nothing, the same as a name they do not define, and the
    two are kept apart: pikepdf hands a number back as a plain Python
    object, and reporting a resource that is there as one that is
    missing sends whoever reads the report to the wrong place.
    """
    for operand in operands:
        if not isinstance(operand, pikepdf.Name):
            continue
        label = str(operand)
        if label in decoders:
            return FontState(label, decoders[label], True)
        font = fonts.get(label)
        if font is None:
            return FontState(label, None, False)
        if not isinstance(font, pikepdf.Dictionary):
            return FontState(label, None, True)
        decoders[label] = font_decoder(label, font)
        return FontState(label, decoders[label], True)
    return NO_FONT


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


def unusable_font_note(label: str, count: int) -> str:
    """Describe text drawn with a resource that is not a font dictionary.

    The name was defined where the text was drawn -- this is not a
    missing resource -- but what it was defined as is not something a
    character code can be looked up in. pikepdf hands a number back as a
    plain Python object, which has none of the methods a font is read
    with, so the font-subset check reports the same resource separately
    as a font it could not inspect.
    """
    return (
        f"{count} byte(s) of page text were drawn with {label}, which the "
        "resources in effect where it was drawn define as something other "
        "than a font dictionary, so what they spell could not be worked out"
    )


def undefined_form_note(name: str, count: int) -> str:
    """Describe a form drawn by a name nothing defines.

    Something was drawn there and nothing here could read it: the `Do`
    operator names a resource, and the resources in effect where it was
    written -- a Form XObject's own, where it was written inside one,
    out to the page's -- define no such thing. What that name would have
    drawn is not known, which is why the count is of drawings rather
    than of anything the page showed.
    """
    return (
        f"a form was drawn {count} time(s) as {name}, which the resources in "
        "effect where it was drawn do not define, so the text it draws was "
        "not inspected"
    )


@dataclass
class PageText:
    """What reading one page's drawing instructions has turned up.

    `out` is the text so far, in drawing order. `unresolved` counts the
    bytes drawn with a font resource nothing defined, by the name the
    document asked for; `unusable` counts the bytes drawn with a name
    that was defined as something other than a font dictionary, by that
    name; `unmapped` counts the character codes a font had no mapping
    for, by font label; and `undefined_forms` counts the drawings of a
    form by a name nothing defines, by that name. All four are counted
    rather than described one by one, because a stream that fails once
    usually fails again and again -- a font that cannot read one
    character code cannot read the rest, and a name the resources do not
    define is still not defined the next time something is drawn with
    it. Counting is also what keeps a stream that draws two million
    undefined forms, which costs a few kilobytes of file, from costing a
    line of report each. `problems` holds anything else that could not
    be read, and `stops` the place each chain of forms that went deeper
    than the walk follows gave up at.

    `drawn` records each form already followed, together with the font
    in effect and the stream that drew it, so that a form drawn twice
    under two different fonts -- which draws different characters each
    time, because a form inherits the font in effect where it is drawn
    -- is read both times, while a form that draws itself cannot loop.
    Recording those three rather than the whole path taken to the form
    is also what keeps a file whose forms draw one another from costing
    far more work than it has objects. See `already_drawn`.
    """

    out: list[str] = field(default_factory=list)
    unresolved: dict[str, int] = field(default_factory=dict)
    unusable: dict[str, int] = field(default_factory=dict)
    unmapped: dict[str, int] = field(default_factory=dict)
    undefined_forms: dict[str, int] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    stops: list[str] = field(default_factory=list)
    drawn: set[FormDrawing] = field(default_factory=set)


def already_drawn(
    form: pikepdf.Object,
    font: FontState,
    container: pikepdf.Object | pikepdf.Page,
    drawn: set[FormDrawing],
) -> bool:
    """Record one drawing of a form, reporting whether it is a repeat.

    A drawing is the form, the font in effect where it was drawn -- both
    the resource name and which font that name resolved to, as
    `font_identity` names it -- and the content stream that drew it.
    Recording the form alone would drop the text of every drawing after
    the first, and a character the page showed but nothing recorded is a
    character the font-subset check reports as the remnant of a removed
    passage.

    The font is recorded as the pair rather than as the name alone
    because one name means different fonts in different places: a form
    whose own /Resources rebind a name the page also uses draws that
    form's font inside itself and the page's font outside, both under
    the one name. Recording the name alone loses the second drawing, and
    with it the characters the page's own font really did show.

    What a drawing produces really depends on the whole chain of
    resources in effect, which is a path rather than a place: keeping
    paths would cost a file whose forms draw one another far more work
    than it has objects, and would stop a form that draws itself from
    ever repeating a drawing, so the walk would only end at the depth
    limit. These three stand in for the chain instead, and what they
    miss is a drawing that differs further out than they reach: a form
    drawn from two places draws a second form of its own, and the two
    records of that inner drawing agree -- one form, one font in effect,
    one stream drawing it -- while the resources further out, which
    decide what it draws, do not. The second reading is dropped and its
    text with it; the README says so under "Limitations".

    A form that is not an indirect object is always drawn: it has no
    object number to record, and having no identity of its own it cannot
    be reached from two places, so it cannot form a loop either.
    """
    objgen = getattr(form, "objgen", (0, 0))
    if objgen == (0, 0):
        return False
    key: FormDrawing = (
        objgen,
        font.label,
        font.identity,
        getattr(container, "objgen", (0, 0)),
    )
    if key in drawn:
        return True
    drawn.add(key)
    return False


class ContentReader(StreamParser):
    """Read the text one content stream draws, as qpdf parses it.

    qpdf hands over one object of the stream at a time -- the operands
    of an instruction, and then the operator that uses them -- and this
    puts them back together. Reading a stream that way is the whole
    point of the class: pikepdf's `parse_content_stream` builds a list
    of every instruction in the stream before the first one can be
    looked at, and a `q` is two bytes that compress to almost nothing
    and cost a few hundred bytes of memory once parsed, so a file of a
    few kilobytes could ask for as much memory as the machine has.
    Nothing here holds more than one instruction at a time. That bounds
    what the number of instructions costs, not what one instruction
    costs -- see `MAX_OPERANDS`.

    The operands wait for their operator, and no more than
    `MAX_OPERANDS` of them do: a stream of nothing but operands would
    otherwise rebuild exactly the list this exists to avoid. Past that
    many, it is the operands written earliest that are dropped. An
    instruction is its operands and then the operator that uses them
    (ISO 32000 section 7.8.2), and an operator takes the operands
    nearest it, so the ones written last are the ones a reader draws
    with. The drop is counted and reported, because dropping text in
    silence is what this tool exists to catch other software doing.

    The font in effect is part of the graphics state that `q` saves and
    `Q` restores (ISO 32000 section 8.4.2), so those two are tracked
    here: text drawn after a `Q` is read through the font that was in
    effect at the matching `q`. A `Q` with nothing left to restore is
    malformed. Readers leave the graphics state alone when they meet
    one, and so does this, which leaves the font in effect unchanged. It
    is reported rather than passed over, because from there on the text
    is read on the assumption that a reader would do the same.

    The saved states are kept only to the same depth as everything else
    here, and for the same reason the operands are bounded. Past the
    limit the state is not kept, and a `Q` that would have taken one
    back leaves the font where it stands -- the same thing that happens
    to a `Q` with no `q` at all.

    An inline image can neither be mistaken for text nor throw the
    grouping out. qpdf writes one as the `BI` operator, the entries of
    the image's dictionary, `ID`, the image data as a single object of
    its own, and `EI`. None of those three operators is one this acts
    on, and the data arrives as an inline image rather than as a string,
    so an inline image yields no text here -- which is right, because it
    is a picture.
    """

    def __init__(
        self,
        content: pikepdf.Object | pikepdf.Page,
        scopes: tuple[pikepdf.Object | None, ...],
        found: PageText,
        font: FontState,
        depth: int,
    ) -> None:
        """Set up to read one stream. See `draw_content` for the arguments."""
        super().__init__()
        self.content = content
        self.scopes = scopes
        self.found = found
        self.font = font
        self.depth = depth
        self.fonts = resource_scope(scopes, "/Font")
        self.xobjects = resource_scope(scopes, "/XObject")
        self.decoders: dict[str, FontDecoder] = {}
        # Bounded by its own length, and from the end an operator uses:
        # appending to a full deque drops the operand written earliest.
        self.operands: deque[pikepdf.Object] = deque(maxlen=MAX_OPERANDS)
        self.saved: list[FontState] = []
        self.dropped = 0
        self.unkept = 0
        self.unkept_restores = 0
        self.unrestored = 0

    def handle_object(self, obj: pikepdf.Object, offset: int, length: int) -> None:
        """Take one object of the stream: an operand, or an operator.

        `offset` and `length` say where in the stream the object was
        written, which nothing here has any use for.

        An operand is anything that is not an operator, and only a
        pikepdf object carries the type code that tells the two apart:
        an operand that is a number arrives as a plain Python value, an
        integer or a Decimal, which carries no such code at all. So the
        code is asked for rather than reached for, and an object that
        has none is an operand.

        An operand written when as many are already waiting for an
        operator as this holds pushes out the one written earliest,
        which is counted so that the drop can be reported.
        """
        if getattr(obj, "_type_code", None) != pikepdf.ObjectType.operator:
            if len(self.operands) == MAX_OPERANDS:
                self.dropped += 1
            self.operands.append(obj)
            return
        operands = list(self.operands)
        self.operands.clear()
        self.draw(str(obj), operands)

    def handle_eof(self) -> None:
        """Take the end of the stream.

        Operands written after the last operator belong to no
        instruction, so they draw nothing and there is nothing left to
        do with them. The parser calls this whether or not a stream ends
        that way, and requires it to be here.
        """

    def draw(self, operator: str, operands: list[pikepdf.Object]) -> None:
        """Act on one instruction: an operator and what it was given."""
        if operator == "q":
            if len(self.saved) < MAX_DEPTH:
                self.saved.append(self.font)
            else:
                self.unkept += 1
        elif operator == "Q":
            self.restore()
        elif operator == "Tf":
            self.font = select_font(self.fonts, self.decoders, operands)
        elif operator == "Do":
            draw_form(
                self.xobjects,
                self.scopes,
                operands,
                self.found,
                self.font,
                self.depth,
                self.content,
            )
        elif operator in SHOW_TEXT_OPERATORS:
            self.show_text(operands)

    def restore(self) -> None:
        """Put the font back that the `Q` now being read asks for.

        A Q pairs with the most recent q, kept or not, so the ones that
        went unkept are counted off first. Taking a state from the stack
        for one of them would restore a font from the wrong depth and
        leave every later restore off by one.
        """
        if self.unkept:
            self.unkept -= 1
            self.unkept_restores += 1
        elif self.saved:
            self.font = self.saved.pop()
        else:
            self.unrestored += 1

    def forget_state(self) -> None:
        """Drop the graphics state, for a join this could not read across.

        Only `draw_page_entries` calls this, and only for an entry of a
        /Contents array that would not read. Everything this holds
        describes a state that the unread entry may have changed: the
        font in effect, because that entry may have selected another
        one; the saved states, because it may have saved or restored;
        and the operands still waiting for an operator, because the
        operator that would have used them was in it.

        Carrying any of that past the entry would read the text after it
        through a state this cannot know the document was in -- which
        puts characters into the page text that the page may never have
        drawn, and a character invented here can land on a font mapping
        that really was orphaned and hide a leak. ISO 32000 section
        9.3.1 gives the font no initial value and requires a Tf before
        any text is shown, so text after the unread entry that a reader
        would draw at all brings its own font with it; what is forgotten
        here costs the reading nothing it could soundly have recovered.

        The counts stay where they are. What was already dropped or left
        unrestored is still something that happened, and the entry that
        would not read is reported by object in its own right, so
        nothing goes unsaid by forgetting the state it left behind.
        """
        self.font = NO_FONT
        self.saved.clear()
        # Cleared with the stack it counts against: a `q` whose state
        # went unkept pairs with a later `Q`, and past this point there
        # is no telling which `Q` that is. A `Q` after this has nothing
        # left to restore from, and is reported as one.
        self.unkept = 0
        self.operands.clear()

    def show_text(self, operands: list[pikepdf.Object]) -> None:
        """Read what one show-text instruction draws, through its font."""
        font = self.font
        found = self.found
        for raw in show_text_bytes(operands):
            if font.decoder is None:
                counted = found.unusable if font.defined else found.unresolved
                counted[font.label] = counted.get(font.label, 0) + len(raw)
                continue
            text, dropped = font.decoder.decode(raw)
            found.out.append(text)
            if dropped:
                found.unmapped[font.decoder.label] = (
                    found.unmapped.get(font.decoder.label, 0) + dropped
                )

    def note_problems(self) -> None:
        """Record what reading this stream could not work out.

        The counts are what a stream did, not what one instruction did:
        a stream that gets one of these wrong usually gets it wrong
        again and again, and one line saying how often is worth more
        than a thousand saying where.
        """
        if self.unrestored:
            self.found.problems.append(
                f"{self.unrestored} Q operator(s) had no q left to restore a "
                "graphics state from, which leaves the font in effect where a "
                "reader would leave it, so what the text after them spells "
                "could only be worked out on that assumption"
            )
        if self.unkept_restores:
            self.found.problems.append(
                f"{self.unkept_restores} Q operator(s) asked for a graphics "
                f"state saved more than {MAX_DEPTH} q operators deep, which is "
                "further than this keeps them, so the font in effect was left "
                "where it stood and the text after them was read on that "
                "assumption"
            )
        if self.dropped:
            self.found.problems.append(
                f"{self.dropped} operand(s) were passed over, each of them "
                f"written when {MAX_OPERANDS} were already waiting for an "
                "operator, which is more operands than any instruction a "
                "reader draws with; what is kept is the operands written "
                "last, because those are the ones an operator would use, so "
                "any text the others carried was not read"
            )


def draw_content(
    content: pikepdf.Object | pikepdf.Page,
    scopes: tuple[pikepdf.Object | None, ...],
    found: PageText,
    font: FontState = NO_FONT,
    depth: int = 0,
) -> None:
    """Read the text one content stream draws, following Form XObjects.

    `scopes` is the /Resources dictionaries in effect, innermost first,
    and is never empty: the page's own resources are the last of them,
    and are None when the page has none. `font` is the font in effect
    where this stream starts.

    A form inherits the graphics state of whatever drew it, so
    text inside one can be drawn with a font selected before the `Do`
    that invoked it; a font selected inside the form does not leak back
    out, which is why the font is an argument here rather than kept in
    `found`.

    A form's content is drawn inside a save of its own (ISO 32000
    section 8.10.1), so the stack of saved graphics states starts empty
    in each call and goes away with it -- neither half of a `q` and `Q`
    pair can cross the boundary of a form. `ContentReader` does the
    reading, and is where the graphics states and the operands it holds
    while doing it are bounded.

    A page's drawing instructions and a form's are parsed by two
    different calls: the first coalesces a /Contents array into one
    stream, as a reader does, and the second is what parses a stream
    that is not a page's. Both go to the same parser underneath.
    """
    # `found.drawn` stops a form that draws itself, but only a form that
    # is an object in its own right, which is the only kind a document
    # read from a file can have. The depth limit is what stops the rest.
    if depth > MAX_DEPTH:
        found.stops.append(object_label(content))
        return
    reader = ContentReader(content, scopes, found, font, depth)
    try:
        if isinstance(content, pikepdf.Page):
            content.parse_contents(reader)
        else:
            # Private, like the parser class itself, and undocumented
            # for the same reason: pikepdf points a caller at the
            # list-building parser instead. It takes the stream as an
            # argument rather than being called on it.
            pikepdf.Object._parse_stream(content, reader)
    finally:
        # What the reader counted before a failure is still worth
        # saying, and the counts live on the reader rather than in
        # `found`, so this is what carries them over when a stream stops
        # part way through. The text needs no such help -- it goes into
        # `found` as it is read, and `found` belongs to whatever drew
        # this stream. Either way the caller that reports the failure
        # says only what went unread from the point it stopped at, which
        # is half of what happened and the wrong half to leave standing
        # on its own.
        reader.note_problems()


def draw_form(
    xobjects: dict[str, pikepdf.Object],
    scopes: tuple[pikepdf.Object | None, ...],
    operands: Iterable[pikepdf.Object],
    found: PageText,
    font: FontState,
    depth: int,
    container: pikepdf.Object | pikepdf.Page,
) -> None:
    """Follow a `Do` operator into the Form XObject it names.

    `container` is the content stream this `Do` was written in -- the
    page, or the form drawing this one -- which `already_drawn` needs to
    tell two drawings of the same form apart.

    Four things stop it going any further. Two are reported, because
    both are text the page draws that nothing here could read: a name
    the resources in effect do not define, which is counted by that name
    in `found.undefined_forms` and described once however often it is
    drawn, and a form whose own instructions will not parse -- the
    second costing the text that form had left to draw, rather than
    costing the rest of the page the way letting the failure out would.
    What the form drew before it stopped is in `found` already and stays
    there, which is the same bargain `_page_text` makes for the page's
    own instructions. Two are silent and ordinary: `Do` naming something
    that is not a form, which draws no text at all, and a drawing of a
    form already read, which would only repeat characters already
    counted.
    """
    for operand in operands:
        if not isinstance(operand, pikepdf.Name):
            continue
        name = str(operand)
        target = xobjects.get(name)
        if target is None:
            found.undefined_forms[name] = found.undefined_forms.get(name, 0) + 1
            return
        if not is_form_xobject(target):
            return
        if already_drawn(target, font, container, found.drawn):
            return
        try:
            draw_content(
                target,
                (target.get("/Resources"), *scopes),
                found,
                font,
                depth + 1,
            )
        except UNPARSABLE_CONTENT as exc:
            found.problems.append(
                f"the form drawn as {name} could not be parsed all the way "
                "through, so the text it draws from the point it stopped at "
                f"was not inspected: {exc}"
            )
        return


def content_problems(page: pikepdf.Page) -> list[str]:
    """Describe a /Contents entry that is not drawing instructions.

    A page's /Contents is a content stream, or an array of them that a
    reader treats as one (ISO 32000 Table 30). A page carrying none
    draws nothing, which is ordinary and is not reported.

    Anything else draws nothing here either. Handed a page of a
    document read from a file whose /Contents is a number or a
    dictionary, pikepdf's content parser answers with no instructions at
    all rather than refusing, and it passes over an array entry that is
    not a stream the same way. Either one reads exactly like a page that
    draws nothing, so what the parser passes over in silence is said
    here. (The same page of a document still being built in memory
    raises instead, which `_page_text` reports as a content stream it
    could not parse all the way through.)
    """
    contents = page.get("/Contents")
    if contents is None or isinstance(contents, pikepdf.Stream):
        return []
    if not isinstance(contents, pikepdf.Array):
        neither = (
            "the page's drawing instructions (/Contents) are neither a content "
            "stream nor an array of them, so the text the page draws was not "
            "inspected"
        )
        return [neither]
    return [
        f"entry {position} of the page's drawing instructions (/Contents) array "
        "is not a content stream, so the text it draws was not inspected"
        for position, item in enumerate(contents, start=1)
        if not isinstance(item, pikepdf.Stream)
    ]


def content_entries(page: pikepdf.Page) -> list[pikepdf.Object] | None:
    """Return the entries of a page's /Contents array, or None.

    None is a page whose /Contents is a single content stream, is
    missing, or is something else entirely -- none of which is an array
    with entries to read apart. The entries are returned as they stand,
    whatever they are, so that the position of one in the list is the
    position a reader would count it at; `content_problems` reports the
    ones that are not content streams.
    """
    contents = page.get("/Contents")
    if not isinstance(contents, pikepdf.Array):
        return None
    return list(contents)


def joined_parse_note(entries: int, exc: Exception) -> str:
    """Describe an array of content streams that would not read as one.

    `entries` is how many the array holds, counting the ones that are
    not content streams, so that the number agrees with the positions
    the entries are reported by. `exc` is what the joined parse stopped
    on.

    It says what was tried, what stopped, what was done instead, and
    what that leaves unknown, because the second attempt recovers text
    the first lost and an operator has no other way to tell which
    reading the page text in front of them came from.
    """
    return (
        f"the page's drawing instructions (/Contents) are {entries} content "
        "stream(s) in an array, which a reader joins into one before parsing, "
        f"and read as one stream they stopped: {exc}; each entry was read on "
        "its own instead, carrying the font in effect and the saved graphics "
        "states across every join that could be read across, so what the "
        "entries that could be read draw was inspected -- but an instruction "
        "written across a join beside an entry that could not be read is "
        "split between the two, and the state such an entry would have left "
        "behind is not known, so from there on the text was read as text "
        "drawn with no font selected rather than guessed at"
    )


def draw_page_entries(
    page: pikepdf.Page,
    entries: list[pikepdf.Object],
    scopes: tuple[pikepdf.Object | None, ...],
    found: PageText,
) -> list[str]:
    """Read a page's drawing instructions one array entry at a time.

    ISO 32000 section 7.8.2 makes an array of content streams one
    stream, divided only at the boundaries between tokens, so a reader
    joins them before parsing and so does the parser underneath this.
    Joining them is also what makes one unreadable entry cost the text
    of every other: the parse of the joined stream hands over no objects
    at all. This is what reads the rest of them, and it runs only after
    that joined parse has already failed.

    One reader takes every entry, which is what carries the graphics
    state across the joins it can read across: the font in effect, the
    stack of saved states that `q` and `Q` work on, and the operands
    still waiting for an operator. Reading each entry with a state of
    its own would decode the text after a join through the wrong font,
    putting characters into the page text that the page never drew --
    and a character invented here can land on a mapping that really was
    orphaned and hide a leak, which is worse than losing the text
    outright. The entries are one stream; only the reading of them is
    split.

    A join this could not read across is the other half of the same
    rule: an entry that would not read may have changed any of that
    state, so it is forgotten rather than carried past, which is what
    `forget_state` is for.

    Returns a description of each entry that could not be read on its
    own either. An entry that is not a content stream is passed over
    rather than handed to the parser: `content_problems` reports those,
    and reporting them here as well would say the same thing twice.
    """
    reader = ContentReader(page, scopes, found, NO_FONT, 0)
    failures: list[str] = []
    try:
        for position, entry in enumerate(entries, start=1):
            if not isinstance(entry, pikepdf.Stream):
                continue
            try:
                pikepdf.Object._parse_stream(entry, reader)
            except UNPARSABLE_CONTENT as exc:
                failures.append(
                    f"entry {position} of the page's drawing instructions "
                    f"(/Contents), {object_label(entry)}, could not be read on "
                    "its own either, so the text it draws from the point it "
                    "stopped at was not inspected, and the state it would have "
                    "left the following entries in is not known: "
                    f"{exc}"
                )
                reader.forget_state()
    finally:
        # The same bargain `draw_content` makes: what the reader counted
        # before anything went wrong is still worth saying, and the
        # counts live on the reader rather than in `found`.
        reader.note_problems()
    return failures


def _page_text(page: pikepdf.Page) -> tuple[str, list[str], list[str]]:
    """Decode the text one page draws, through the fonts it draws it with.

    Text drawn inside a Form XObject counts as text the page draws,
    because that is what a reader puts on the screen -- so this follows
    every `Do` that names one. A form the page never draws is a
    different thing, and is not page text.

    Returns the text, a description of every run that could not be
    decoded -- so a page that yielded no text stays distinguishable from
    a page whose text could not be read -- and the place each chain of
    forms that went deeper than the walk follows gave up at, which the
    caller reports as one finding rather than one per branch.

    Instructions that will not parse end the reading rather than the
    page. A stream is read as it is parsed, so one that stops part way
    through has already produced text this decoded, counts this took,
    and chains of forms this gave up on -- and page text is what the
    font-subset check compares a font's characters against, so throwing
    the page away because its instructions stopped leaves its fonts
    reported as holding the leftovers of a passage the page is still
    showing. What was read is returned, and the failure is described
    among the problems: the same bargain `draw_form` makes for a form
    that stops part way through.

    A page whose /Contents is an array gets a second attempt. The
    entries of one are joined into a single stream before parsing, as a
    reader joins them, so one entry that will not decode costs the text
    of every other -- and that text is on the page in front of the
    operator. When the joined parse stops, the entries are read one at a
    time instead; see `draw_page_entries`. The second pass starts on a
    fresh accumulator, because it is a reading of the whole array from
    the beginning rather than a continuation of the first, and adding it
    to what the first pass had already read would count that text and
    those problems twice.

    A /Contents entry that is not drawing instructions is not described
    here: that is a reading of the entry rather than of the instructions
    in it, and the caller makes it; see `content_problems`.
    """
    found = PageText()
    problems: list[str] = []
    scopes = (page_resources(page),)
    try:
        draw_content(page, scopes, found)
    except UNPARSABLE_CONTENT as exc:
        entries = content_entries(page)
        if entries is None:
            problems.append(
                "the page content stream could not be parsed all the way "
                "through, so the text it draws from the point it stopped at was "
                f"not inspected: {exc}"
            )
        else:
            problems.append(joined_parse_note(len(entries), exc))
            found = PageText()
            problems += draw_page_entries(page, entries, scopes, found)

    problems += [
        undecoded_note(name, count) for name, count in found.unresolved.items()
    ]
    problems += [
        unusable_font_note(name, count) for name, count in found.unusable.items()
    ]
    problems += [
        f"{count} character code(s) drawn with {name} are mapped by neither "
        "its /ToUnicode CMap nor its /Encoding, so what they spell could not "
        "be worked out"
        for name, count in found.unmapped.items()
    ]
    problems += [
        undefined_form_note(name, count)
        for name, count in found.undefined_forms.items()
    ]
    return "".join(found.out), problems + found.problems, found.stops


def extract_page_text(
    pdf: pikepdf.Pdf,
    report: Report | None = None,
    partial: list[int] | None = None,
) -> str:
    """Return the text the pages draw, decoded through their own fonts.

    This is not `pdftotext`. There is no layout analysis and nothing is
    inserted between runs: the result is the characters the content
    stream draws, in drawing order, one page per line. When `report` is
    given, every page and every run that could not be read is recorded
    there, so a document that yielded no text stays distinguishable from
    one whose text could not be read.

    Those findings are located by page. The one for forms drawn inside
    one another past the depth limit names the form the walk gave up at
    instead, as the other walks do: it counts branches rather than
    listing them, so an object to point at is the only thing that says
    where to start looking.

    `partial` is the list the number of every page whose text could not
    be read in full is appended to, in page order, for a caller that
    needs to know how much of the page text it is holding --
    `check_fonts` does, because comparing a font against the page text
    only says something about the document when the page text is all of
    it. None means this caller is not collecting the page numbers, which
    is what a test reading this layer on its own wants, and never means
    every page was read in full.

    A page counts as read in full exactly when nothing about it was
    reported. That is the same test the findings are built from, on
    purpose: anything this could not read is text the page may draw and
    this did not see, and deriving both from the one list is what stops
    the report and the font check contradicting each other.
    """
    chunks: list[str] = []
    for index, page in enumerate(pdf.pages, start=1):
        # Read what /Contents is before trying to read what it draws:
        # an entry of it that nobody could read is still worth saying
        # when reading the rest of it fails as well.
        problems = content_problems(page)
        text, decoded, stops = _page_text(page)
        chunks.append(text)
        problems += decoded
        if partial is not None and (problems or stops):
            partial.append(index)
        if report is not None:
            for problem in problems:
                report.add(Severity.WARNING, CONTENT_STREAM, problem, f"page {index}")
            if stops:
                report.add(
                    Severity.WARNING,
                    CONTENT_STREAM,
                    depth_limit_note(
                        "the chain of forms drawn inside one another", stops
                    ),
                    stops[0],
                )
    return "\n".join(chunks)


def extract_structure_tree(pdf: pikepdf.Pdf) -> list[Extract]:
    """Pull text out of the tagged-PDF structure tree.

    A tree nested deeper than the walk follows is reported by
    `check_structure_tree`, which runs on every invocation, rather than
    here, where it would be said a second time.
    """
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
    stops: list[str] | None = None,
) -> Iterator[str]:
    """Yield text carried by the tagged-PDF structure tree.

    `stops` is where the places this gave up at are recorded, one per
    branch that went deeper than the limit. None means this caller is
    not the one reporting them -- `check_structure_tree` runs on every
    invocation and would otherwise say it twice -- and never means there
    was nothing to report.
    """
    if depth > MAX_DEPTH:
        if stops is not None:
            stops.append(object_label(node))
        return
    if node is None or already_seen(node, seen):
        return

    if isinstance(node, pikepdf.Array):
        for item in node:
            yield from walk_struct(item, seen, depth + 1, stops)
        return
    if not isinstance(node, pikepdf.Dictionary):
        return

    for attr in ("/ActualText", "/Alt", "/E", "/T", "/TU"):
        value = node.get(attr)
        if isinstance(value, pikepdf.String):
            yield str(value)

    kids = node.get("/K")
    if kids is not None:
        yield from walk_struct(kids, seen, depth + 1, stops)


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


def extract_attachments(
    pdf: pikepdf.Pdf, report: Report | None = None
) -> list[Extract]:
    """List embedded file names and sizes.

    Attachment contents are deliberately not extracted: they are
    untrusted files, and writing them anywhere is a separate decision
    from reading text out of the document.

    A /Names entry that is not a dictionary yields nothing here and is
    reported by `check_attachments`, which is where findings about the
    document go.

    `report` is where a name tree nested deeper than the walk follows is
    recorded. None means this caller is not the one reporting it, not
    that there is nothing to report: an attachment below the limit is an
    attachment nobody listed, and a file that was never looked for must
    not read as a file that is not there.
    """
    names = pdf.Root.get("/Names")
    if not isinstance(names, pikepdf.Dictionary) or "/EmbeddedFiles" not in names:
        return []
    out: list[Extract] = []
    stops: list[str] = []
    for label, size in _iter_embedded_files(names["/EmbeddedFiles"], stops=stops):
        detail = f"{label} ({size} bytes)" if size is not None else label
        out.append(Extract(ATTACHMENTS, "embedded file", detail))
    if stops and report is not None:
        report.add(
            Severity.WARNING,
            ATTACHMENTS,
            depth_limit_note("the tree of embedded file names", stops),
            stops[0],
        )
    return out


def _iter_embedded_files(
    tree: pikepdf.Object,
    seen: set[tuple[int, int]] | None = None,
    stops: list[str] | None = None,
    depth: int = 0,
) -> Iterator[tuple[str, int | None]]:
    """Walk a name tree, yielding (filename, size) for each attachment.

    The tree's /Kids arrays nest, so the walk is bounded like every
    other here. `stops` is where the places it gave up at are recorded,
    one per branch that went deeper than the limit. Every path through
    the tool passes a list; None is for a caller collecting nothing,
    which is what a test reading this on its own wants, and never means
    there was nothing to record.
    """
    if depth > MAX_DEPTH:
        if stops is not None:
            stops.append(object_label(tree))
        return
    if seen is None:
        seen = set()
    if not isinstance(tree, pikepdf.Dictionary) or already_seen(tree, seen):
        return
    kids = tree.get("/Kids")
    if isinstance(kids, pikepdf.Array):
        for kid in kids:
            yield from _iter_embedded_files(kid, seen, stops, depth + 1)
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
                # Asking whether a pikepdf object is truthy is not the
                # same question as asking whether it is there: older
                # pikepdf raises rather than answer it for a stream.
                # The type is what this wants to know anyway.
                stream = embedded.get("/F")
                if not isinstance(stream, pikepdf.Stream):
                    stream = embedded.get("/UF")
                if isinstance(stream, pikepdf.Stream):
                    try:
                        size = len(stream.read_bytes())
                    except UNREADABLE_STREAM:
                        size = None
        yield label, size


def extract_raw_strings(
    pdf: pikepdf.Pdf,
    known: set[str],
    report: Report | None = None,
) -> list[Extract]:
    """Collect string objects anywhere in the document.

    This is the catch-all for text that lives outside the layers with
    dedicated checks -- outlines, optional content names, private
    dictionaries. Text already reported by a more specific layer is
    skipped so the dump does not repeat itself.

    `report` is where a graph nested deeper than the walk follows is
    recorded. None means this caller is not the one reporting it, not
    that there is nothing to report: strings below the limit are strings
    nobody swept, and a secret that was never looked for must not read
    as a secret that was not found.
    """
    seen_objects: set[tuple[int, int]] = set()
    found: list[str] = []
    stops: list[str] = []
    _walk_strings(pdf.trailer, seen_objects, found, 0, stops)
    if stops and report is not None:
        report.add(
            Severity.WARNING,
            RAW_STRINGS,
            depth_limit_note("the document's object graph", stops),
            stops[0],
        )

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
    stops: list[str] | None = None,
) -> None:
    """Recurse through the object graph, collecting string values.

    `stops` is where the places this gave up at are recorded, one per
    branch that went deeper than the limit. None means this caller is
    not the one reporting them, and never means there were none.
    """
    if depth > MAX_DEPTH:
        if stops is not None:
            stops.append(object_label(node))
        return
    if node is None or already_seen(node, seen):
        return

    if isinstance(node, pikepdf.String):
        found.append(str(node))
        return
    if isinstance(node, pikepdf.Array):
        for item in node:
            _walk_strings(item, seen, found, depth + 1, stops)
        return
    if isinstance(node, pikepdf.Dictionary):
        for key, value in node.items():
            if str(key) in BINARY_KEYS:
                continue
            _walk_strings(value, seen, found, depth + 1, stops)


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
    passes for a font with nothing to declare. The two walks that can
    run out of depth before they run out of document -- the forms the
    fonts are reached through, and a font's chain of descendant fonts --
    are recorded there too, once the walks are done, for the same
    reason.
    """
    visible = set(visible_text)
    form_stops: list[str] = []
    charset_stops: list[str] = []
    for label, font in iter_fonts(pdf, form_stops):
        problems: list[str] = []
        charset = font_charset(font, problems, stops=charset_stops)
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
    if report is None:
        return
    if charset_stops:
        report.add(
            Severity.WARNING,
            FONT_CHARSET,
            depth_limit_note("a font's chain of descendant fonts", charset_stops),
            charset_stops[0],
        )
    if form_stops:
        report.add(
            Severity.WARNING,
            FONT_CHARSET,
            # Named for the walk rather than for the structure: the page
            # text is read through a second walk of the same forms, and
            # two findings that read alike would look like one said
            # twice rather than two walks that each stopped.
            depth_limit_note(
                "the chain of forms the fonts are reached through", form_stops
            ),
            form_stops[0],
        )


def extract_font_orphans(pdf: pikepdf.Pdf, visible_text: str) -> list[Extract]:
    """Report orphaned glyph mappings as characters, never as text."""
    return [
        Extract(FONT_CHARSET, label, "".join(orphans), is_text=False)
        for label, orphans in font_orphans(pdf, visible_text)
    ]


def collect_extracts(
    pdf: pikepdf.Pdf,
    visible_text: str,
    report: Report | None = None,
) -> list[Extract]:
    """Gather every recoverable piece of text, layer by layer.

    `report` is passed on to the two layers here that can run out of
    depth before they run out of document: the catch-all string sweep,
    and the tree the embedded file names hang off. None means this
    caller is not collecting findings, which is what a test reading one
    layer in isolation wants.
    """
    specific: list[Extract] = []
    specific += extract_structure_tree(pdf)
    specific += extract_annotations(pdf)
    specific += extract_metadata(pdf)
    specific += extract_attachments(pdf, report)

    known = {e.text for e in specific}
    known.add(visible_text)

    out: list[Extract] = [Extract(CONTENT_STREAM, "visible page text", visible_text)]
    out += specific
    out += extract_raw_strings(pdf, known, report)
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
    """Note whether the document carries a structure tree at all.

    A tree that goes deeper than the walk follows is reported first: the
    count of characters below would otherwise read as the whole of the
    tree, and a document whose tags nobody could reach would look like a
    document with nothing in its tags.
    """
    root = pdf.Root.get("/StructTreeRoot")
    if root is None:
        report.add(
            Severity.INFO,
            STRUCTURE_TREE,
            "document is not tagged; no structure tree to inspect",
        )
        return
    stops: list[str] = []
    text = "\n".join(walk_struct(root, set(), stops=stops))
    if stops:
        report.add(
            Severity.WARNING,
            STRUCTURE_TREE,
            depth_limit_note("the tagged-PDF structure tree", stops),
            stops[0],
        )
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


def partial_pages_note(pages: Sequence[int]) -> str:
    """Name the pages whose text could not be read in full.

    One page is named outright. More are counted and the first named, as
    every other count here is: an operator needs to know how much went
    unread and where to start looking, and a document built to stop on
    every page would otherwise put a page number on the report for each
    of them.

    Raises ValueError when `pages` is empty. There is no such thing as a
    note about no pages, and the caller decides which of two findings to
    build by whether any page went unread, so an empty list here means
    the strong finding was built as the weak one.
    """
    if not pages:
        raise ValueError("partial_pages_note needs at least one page number")
    if len(pages) == 1:
        return f"page {pages[0]}"
    return f"{len(pages)} pages, the first of them page {pages[0]}"


def check_fonts(
    pdf: pikepdf.Pdf,
    report: Report,
    visible_text: str,
    partial_pages: Sequence[int] = (),
) -> None:
    """Detect orphaned glyph mappings left behind by post-hoc redaction.

    `partial_pages` is the pages whose text could not be read in full,
    from `extract_page_text`. A character this cannot account for is
    only evidence of a removed passage when the text it was compared
    against is the whole of the page text -- so when any page went
    unread, the finding says what it observed, that the characters are
    absent from the text this could read, and names the pages that make
    that less than the page text. The characters are still listed and
    the finding is still made: what changes is the inference drawn from
    it, and with it the severity, because the evidence for "the content
    is recoverable" is what went missing along with the page text.

    That reaches every font, not only the fonts of the pages that went
    unread. The text a font is compared against is every page's joined
    together, so a page this could not finish leaves characters out of
    the comparison whatever page the font was reached through -- and
    fonts are shared between pages, so the missing characters are often
    exactly the ones the font in hand declares.
    """
    for label, orphans in font_orphans(pdf, visible_text, report):
        sample = "".join(orphans)[:60]
        if partial_pages:
            report.add(
                Severity.WARNING,
                FONT_CHARSET,
                (
                    f"{len(orphans)} character(s) mapped by the font subset but "
                    "absent from the page text this could read, in CMap order: "
                    f"{sample!r} -- the text of {partial_pages_note(partial_pages)} "
                    "could not be read in full, so these may be characters the "
                    "document still shows that this run never saw, rather than "
                    "characters removed from the content stream"
                ),
                label,
            )
            continue
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


def reject_blank_secrets(secrets: list[str]) -> None:
    """Refuse a secret with nothing in it, whoever supplied it.

    Text with nothing in it is in every document ever written: matching
    it convicts every document, and dropping it silently checks none of
    them while looking like it did. Neither is an answer, so it is
    refused rather than guessed at.

    The message names --secret as the usual way one arrives without
    telling a caller of `analyze` that it used a command-line option it
    never saw.

    Raises UsageError, which is a condition of the invocation rather
    than of the document, so the caller ends the run with the
    usage-error exit code and no verdict.
    """
    if any(not secret.strip() for secret in secrets):
        raise UsageError(
            "a secret with nothing in it was given, and every document "
            "contains that; name the text that must not survive, or drop "
            "the --secret whose value went missing"
        )


def load_secrets(args: argparse.Namespace) -> list[str]:
    """Collect secrets from --secret and --secret-file.

    The two sources treat a blank differently on purpose. A file holds
    one secret per line, so a line with nothing on it is formatting and
    is dropped. A --secret is a statement that this text must not
    survive anywhere, so a blank one is refused: the shape it arrives in
    is a CI gate running --secret "$NAME" with the variable unset.

    Raises UsageError for a blank --secret, OSError if the file named by
    --secret-file cannot be opened, and UnicodeDecodeError if that file
    is not UTF-8 text. All three are conditions of the invocation rather
    than of the document, and the caller reports them as usage errors.
    """
    secrets: list[str] = list(args.secret or [])
    reject_blank_secrets(secrets)
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

    `secrets` is the text that must not survive anywhere, and is empty
    for a run that only makes the structural checks. Returns the report
    and, when `want_extracts` is set, the recovered text each layer
    yielded.

    Raises UsageError when a secret has nothing in it, and pikepdf's
    PdfError when the file cannot be read at all. The blank secret is
    refused here as well as in `load_secrets`, so that the guard belongs
    to this function rather than to the command line: every document
    contains text with nothing in it, so searching for it would report
    every document as a failed redaction.
    """
    reject_blank_secrets(secrets)
    report = Report(path=path)
    extracts: list[Extract] = []
    # The pages whose text could not be read in full. `check_fonts`
    # compares what a font declares against the page text, so it has to
    # know when the page text is less than what the pages draw.
    partial_pages: list[int] = []
    with pikepdf.open(path) as pdf:
        visible_text = extract_page_text(pdf, report, partial_pages)
        if want_extracts or secrets:
            extracts = collect_extracts(pdf, visible_text, report)
        if secrets:
            check_secrets(report, extracts, secrets)
        check_raw_objects(pdf, report, secrets)
        check_structure_tree(pdf, report)
        check_redact_annotations(pdf, report)
        check_metadata(pdf, report)
        check_attachments(pdf, report)
        check_fonts(pdf, report, visible_text, partial_pages)
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
    except UsageError as exc:
        warn(f"error: {exc}")
        return EXIT_USAGE
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
