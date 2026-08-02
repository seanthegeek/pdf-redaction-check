#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sean Whalen
# SPDX-License-Identifier: MIT
"""Verify that a redaction actually removed content from a PDF.

Checks every layer where text can survive a "redaction" that only looks
correct on screen:

1. Content-stream text (what pdftotext sees)
2. Raw decompressed object data (catches text outside the text layer)
3. Tagged-PDF structure tree (/ActualText, /Alt, /E, /TU)
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

Two modes are available. Given one or more secrets, the tool reports
whether they survive anywhere. Given --dump-hidden or --dump-all, it
outputs the recoverable text itself, for auditing a document when you do
not know what was redacted.

Usage:
    pdf-redaction-check FILE.pdf
    pdf-redaction-check FILE.pdf --secret "742 Evergreen Terrace"
    pdf-redaction-check FILE.pdf --secret-file secrets.txt --json
    pdf-redaction-check FILE.pdf --dump-hidden
    pdf-redaction-check FILE.pdf --dump-all -o recovered.txt
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import NotRequired, TypedDict

import pikepdf

# Glyph names that carry no evidential weight when orphaned: whitespace
# and layout characters legitimately outlive the text that used them.
IGNORABLE_CHARS: frozenset[str] = frozenset(" \t\r\n\x00\ufeff\xa0")

BFCHAR_RE = re.compile(rb"beginbfchar(.*?)endbfchar", re.DOTALL)
BFRANGE_RE = re.compile(rb"beginbfrange(.*?)endbfrange", re.DOTALL)
HEX_PAIR_RE = re.compile(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>")
HEX_TRIPLE_RE = re.compile(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>")
UNI_GLYPH_RE = re.compile(r"^uni([0-9A-Fa-f]{4,6})$")
U_GLYPH_RE = re.compile(r"^u([0-9A-Fa-f]{4,6})$")

# Layer names, shared by findings and dump output.
CONTENT_STREAM = "content-stream"
STRUCTURE_TREE = "structure-tree"
ANNOTATIONS = "annotations"
METADATA = "metadata"
ATTACHMENTS = "attachments"
RAW_STRINGS = "raw-strings"
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


class Severity(Enum):
    """How much a finding should worry the operator."""

    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


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

    mode: str
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


def normalize(text: str) -> str:
    """Casefold and strip accents so 'Café' matches 'cafe'."""
    decomposed = unicodedata.normalize("NFKD", text)
    stripped = "".join(c for c in decomposed if not unicodedata.combining(c))
    return stripped.casefold()


def dedupe(chars: Iterator[str] | list[str]) -> list[str]:
    """Drop repeats while keeping the order of first appearance."""
    return list(dict.fromkeys(chars))


def glyph_name_to_char(name: str) -> str | None:
    """Map a PostScript glyph name to a character, best effort."""
    if len(name) == 1:
        return name
    match = UNI_GLYPH_RE.match(name) or U_GLYPH_RE.match(name)
    if match:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return None
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


def parse_tounicode(data: bytes) -> list[str]:
    """Extract every character a ToUnicode CMap can produce.

    The result keeps CMap order rather than sorting. Producers build
    these tables in order of each character's first appearance in the
    text, so the order is a partial record of the wording that was
    removed.
    """
    chars: list[str] = []

    for block in BFCHAR_RE.findall(data):
        for _src, dst in HEX_PAIR_RE.findall(block):
            chars.extend(decode_utf16be(bytes.fromhex(dst.decode("ascii"))))

    for block in BFRANGE_RE.findall(data):
        for lo, hi, dst in HEX_TRIPLE_RE.findall(block):
            try:
                low = int(lo, 16)
                high = int(hi, 16)
                start = bytes.fromhex(dst.decode("ascii"))
            except ValueError:
                continue
            if high < low or high - low > 0xFFFF:
                continue
            text = decode_utf16be(start)
            if not text:
                continue
            base = ord(text[0])
            for offset in range(high - low + 1):
                code = base + offset
                if 0 <= code <= 0x10FFFF:
                    chars.append(chr(code))
    return dedupe(chars)


def iter_fonts(pdf: pikepdf.Pdf) -> Iterator[tuple[str, pikepdf.Object]]:
    """Yield (page label, font object) for every font resource."""
    for index, page in enumerate(pdf.pages, start=1):
        resources = page.get("/Resources")
        if resources is None or "/Font" not in resources:
            continue
        for name, font in resources["/Font"].items():
            yield f"page {index} {name}", font


def font_charset(font: pikepdf.Object) -> list[str]:
    """Collect every character a font object claims it can render.

    Order is preserved: ToUnicode entries first, in CMap order, then the
    other sources of glyph names.
    """
    chars: list[str] = []

    tounicode = font.get("/ToUnicode")
    if tounicode is not None:
        try:
            chars += parse_tounicode(bytes(tounicode.read_bytes()))
        except (pikepdf.PdfError, ValueError):
            pass

    encoding = font.get("/Encoding")
    if isinstance(encoding, pikepdf.Dictionary) and "/Differences" in encoding:
        for item in encoding["/Differences"]:
            if isinstance(item, pikepdf.Name):
                char = glyph_name_to_char(str(item).lstrip("/"))
                if char:
                    chars.append(char)

    chars += descriptor_charset(font.get("/FontDescriptor"))
    chars += widths_charset(font)

    for descendant in font.get("/DescendantFonts") or []:
        chars += font_charset(descendant)

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


def widths_charset(font: pikepdf.Object) -> list[str]:
    """Infer the encoded code range of a simple font from /Widths.

    A subset font keeps a width entry for every code it can draw. A code
    with a nonzero width that renders nothing in the visible text is the
    same orphan signal as a stale ToUnicode entry.
    """
    widths = font.get("/Widths")
    first = font.get("/FirstChar")
    if not isinstance(widths, pikepdf.Array) or first is None:
        return []
    encoding = str(font.get("/Encoding", ""))
    if encoding not in {"/WinAnsiEncoding", "/MacRomanEncoding", "/StandardEncoding"}:
        return []
    codec = "cp1252" if encoding == "/WinAnsiEncoding" else "mac_roman"
    chars: list[str] = []
    for offset, width in enumerate(widths):
        if float(width) <= 0:
            continue
        code = int(first) + offset
        if not 0 <= code <= 0xFF:
            continue
        try:
            chars.append(bytes([code]).decode(codec))
        except (UnicodeDecodeError, ValueError):
            continue
    return dedupe(chars)


def extract_page_text(pdf: pikepdf.Pdf) -> str:
    """Return all visible text, using pdftotext semantics where possible."""
    chunks: list[str] = []
    for page in pdf.pages:
        try:
            chunks.append(_page_text(page))
        except (pikepdf.PdfError, ValueError, TypeError):
            continue
    return "\n".join(chunks)


def _page_text(page: pikepdf.Page) -> str:
    """Pull show-text operands out of a page content stream."""
    out: list[str] = []
    for operands, operator in pikepdf.parse_content_stream(page):
        if str(operator) not in {"Tj", "TJ", "'", '"'}:
            continue
        for operand in operands:
            if isinstance(operand, pikepdf.String):
                out.append(str(operand))
            elif isinstance(operand, pikepdf.Array):
                for element in operand:
                    if isinstance(element, pikepdf.String):
                        out.append(str(element))
    return "".join(out)


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


def extract_metadata(pdf: pikepdf.Pdf) -> list[Extract]:
    """Pull DocInfo values and the XMP packet."""
    out: list[Extract] = []
    if pdf.trailer.get("/Info") is not None:
        for key, value in pdf.trailer["/Info"].items():
            if isinstance(value, pikepdf.String) and str(value).strip():
                out.append(Extract(METADATA, f"DocInfo {key}", str(value)))
    meta = pdf.Root.get("/Metadata")
    if isinstance(meta, pikepdf.Stream):
        try:
            xmp = meta.read_bytes().decode("utf-8", errors="ignore")
        except pikepdf.PdfError:
            xmp = ""
        if xmp.strip():
            out.append(Extract(METADATA, "XMP", xmp))
    return out


def extract_attachments(pdf: pikepdf.Pdf) -> list[Extract]:
    """List embedded file names and sizes.

    Attachment contents are deliberately not extracted: they are
    untrusted files, and writing them anywhere is a separate decision
    from reading text out of the document.
    """
    names = pdf.Root.get("/Names")
    if names is None or "/EmbeddedFiles" not in names:
        return []
    out: list[Extract] = []
    for label, size in _iter_embedded_files(names["/EmbeddedFiles"]):
        detail = f"{label} ({size} bytes)" if size is not None else label
        out.append(Extract(ATTACHMENTS, "embedded file", detail))
    return out


def _iter_embedded_files(tree: pikepdf.Object) -> Iterator[tuple[str, int | None]]:
    """Walk a name tree, yielding (filename, size) for each attachment."""
    if not isinstance(tree, pikepdf.Dictionary):
        return
    for kid in tree.get("/Kids") or []:
        yield from _iter_embedded_files(kid)
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
                    except (pikepdf.PdfError, zlib.error):
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
    pdf: pikepdf.Pdf, visible_text: str
) -> Iterator[tuple[str, list[str]]]:
    """Yield (font label, orphaned characters) in CMap order."""
    visible = set(visible_text)
    for label, font in iter_fonts(pdf):
        charset = font_charset(font)
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
    """Search every extracted layer for each secret."""
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


def check_raw_objects(pdf: pikepdf.Pdf, report: Report, secrets: list[str]) -> None:
    """Search every decompressed stream for a secret.

    This is a byte-level sweep, separate from the string-object
    extraction used by the dump modes: it catches text embedded in
    places that are not string objects at all, such as an XML island or
    a leftover font program.
    """
    if not secrets:
        return
    needles = [normalize(s) for s in secrets]
    for obj in pdf.objects:
        blob = b""
        if isinstance(obj, pikepdf.Stream):
            try:
                blob = obj.read_bytes()
            except (pikepdf.PdfError, zlib.error):
                continue
        elif isinstance(obj, pikepdf.String):
            blob = bytes(obj)
        if not blob:
            continue
        hay = normalize(blob.decode("utf-8", errors="ignore"))
        hay_16 = normalize(blob.decode("utf-16-be", errors="ignore"))
        for secret, needle in zip(secrets, needles, strict=True):
            if needle in hay or needle in hay_16:
                report.add(
                    Severity.CRITICAL,
                    "raw-objects",
                    f"secret found in raw object data: {secret!r}",
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
    a dump mode or a secret asked for extraction.
    """
    for extract in extract_metadata(pdf):
        if extract.location.startswith("DocInfo"):
            report.add(
                Severity.INFO,
                METADATA,
                f"{extract.location} = {extract.text!r}",
            )


def check_attachments(pdf: pikepdf.Pdf, report: Report) -> None:
    """Flag embedded files, which travel with the document unredacted."""
    names = pdf.Root.get("/Names")
    if names is None or "/EmbeddedFiles" not in names:
        return
    report.add(
        Severity.WARNING,
        ATTACHMENTS,
        "document contains embedded file attachments; inspect them separately",
    )


def check_fonts(pdf: pikepdf.Pdf, report: Report, visible_text: str) -> None:
    """Detect orphaned glyph mappings left behind by post-hoc redaction."""
    for label, orphans in font_orphans(pdf, visible_text):
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
    """Collect secrets from --secret and --secret-file."""
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
        visible_text = extract_page_text(pdf)
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


def select_dump(extracts: list[Extract], visible_text: str, mode: str) -> list[Extract]:
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


def render_dump(path: Path, mode: str, extracts: list[Extract]) -> str:
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
    mode: str,
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
    """Return an error message if `output` is not safe to write.

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
    """Write recovered text with owner-only permissions."""
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)


def build_parser() -> argparse.ArgumentParser:
    """Construct the command-line parser."""
    parser = argparse.ArgumentParser(
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


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns 2 on CRITICAL, 1 on WARNING, 0 otherwise."""
    parser = build_parser()
    args = parser.parse_args(argv)

    mode = "hidden" if args.dump_hidden else "all" if args.dump_all else None
    if args.output is not None and mode is None:
        parser.error("--output requires --dump-hidden or --dump-all")
    if args.force and args.output is None:
        parser.error("--force requires --output")

    if not args.pdf.is_file():
        print(f"error: no such file: {args.pdf}", file=sys.stderr)
        return 3

    if args.output is not None:
        problem = check_output_path(args.output, args.pdf, args.force)
        if problem:
            print(f"error: {problem}", file=sys.stderr)
            return 3

    try:
        report, extracts = analyze(
            args.pdf, load_secrets(args), want_extracts=bool(mode)
        )
    except pikepdf.PdfError as exc:
        print(f"error: could not read {args.pdf}: {exc}", file=sys.stderr)
        return 3

    visible = next(
        (e.text for e in extracts if e.layer == CONTENT_STREAM),
        "",
    )
    selected = select_dump(extracts, visible, mode) if mode else []

    payload = report.to_dict()
    if mode and args.output is None and args.json:
        payload["dump"] = dump_to_json(mode, selected, visible)

    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"=== redaction check: {args.pdf} ===")
        for finding in report.findings:
            print(finding.render())
        worst = report.worst
        if worst is Severity.CRITICAL:
            print("\nRESULT: FAILED -- redacted content is still recoverable.")
        elif worst is Severity.WARNING:
            print("\nRESULT: SUSPICIOUS -- review the warnings above.")
        else:
            print("\nRESULT: no evidence of surviving content.")

    if mode:
        if args.output is not None:
            body = (
                json.dumps(
                    dump_to_json(mode, selected, visible), indent=2, ensure_ascii=False
                )
                + "\n"
                if args.json
                else render_dump(args.pdf, mode, selected)
            )
            try:
                write_output(args.output, body)
            except OSError as exc:
                print(f"error: could not write {args.output}: {exc}", file=sys.stderr)
                return 3
            print(
                f"wrote {len(selected)} recovered block(s) to {args.output}",
                file=sys.stderr,
            )
        elif not args.json:
            print()
            print(render_dump(args.pdf, mode, selected), end="")

    worst = report.worst
    if worst is Severity.CRITICAL:
        return 2
    if worst is Severity.WARNING:
        return 1
    return 0


def run() -> int:
    """Console-script entry point: main() plus broken-pipe handling."""
    try:
        return main()
    except BrokenPipeError:  # piped into head/less
        sys.stderr.close()
        return 0


if __name__ == "__main__":
    raise SystemExit(run())
