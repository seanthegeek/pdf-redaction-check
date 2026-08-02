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

Usage:
    pdf-redaction-check FILE.pdf
    pdf-redaction-check FILE.pdf --secret "742 Evergreen Terrace"
    pdf-redaction-check FILE.pdf --secret-file secrets.txt --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

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


class Severity(Enum):
    """How much a finding should worry the operator."""

    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


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

    def to_dict(self) -> dict[str, object]:
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
    """Decode a ToUnicode destination value, tolerating odd lengths."""
    if len(raw) % 2:
        raw = raw + b"\x00"
    try:
        return raw.decode("utf-16-be", errors="ignore")
    except UnicodeDecodeError:
        return ""


def parse_tounicode(data: bytes) -> set[str]:
    """Extract every character a ToUnicode CMap can produce."""
    chars: set[str] = set()

    for block in BFCHAR_RE.findall(data):
        for _src, dst in HEX_PAIR_RE.findall(block):
            chars.update(decode_utf16be(bytes.fromhex(dst.decode("ascii"))))

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
                    chars.add(chr(code))
    return chars


def iter_fonts(pdf: pikepdf.Pdf) -> Iterator[tuple[str, pikepdf.Object]]:
    """Yield (page label, font object) for every font resource."""
    for index, page in enumerate(pdf.pages, start=1):
        resources = page.get("/Resources")
        if resources is None or "/Font" not in resources:
            continue
        for name, font in resources["/Font"].items():
            yield f"page {index} {name}", font


def font_charset(font: pikepdf.Object) -> set[str]:
    """Collect every character a font object claims it can render."""
    chars: set[str] = set()

    tounicode = font.get("/ToUnicode")
    if tounicode is not None:
        try:
            chars |= parse_tounicode(bytes(tounicode.read_bytes()))
        except (pikepdf.PdfError, ValueError):
            pass

    encoding = font.get("/Encoding")
    if isinstance(encoding, pikepdf.Dictionary) and "/Differences" in encoding:
        for item in encoding["/Differences"]:
            if isinstance(item, pikepdf.Name):
                char = glyph_name_to_char(str(item).lstrip("/"))
                if char:
                    chars.add(char)

    chars |= descriptor_charset(font.get("/FontDescriptor"))
    chars |= widths_charset(font)

    for descendant in font.get("/DescendantFonts") or []:
        chars |= font_charset(descendant)

    return chars


def descriptor_charset(descriptor: pikepdf.Object | None) -> set[str]:
    """Read the /CharSet glyph list that Type 1 subsets carry."""
    if not isinstance(descriptor, pikepdf.Dictionary):
        return set()
    raw = descriptor.get("/CharSet")
    if not isinstance(raw, pikepdf.String):
        return set()
    chars: set[str] = set()
    for name in str(raw).split("/"):
        char = glyph_name_to_char(name.strip())
        if char:
            chars.add(char)
    return chars


def widths_charset(font: pikepdf.Object) -> set[str]:
    """Infer the encoded code range of a simple font from /Widths.

    A subset font keeps a width entry for every code it can draw. A code
    with a nonzero width that renders nothing in the visible text is the
    same orphan signal as a stale ToUnicode entry.
    """
    widths = font.get("/Widths")
    first = font.get("/FirstChar")
    if not isinstance(widths, pikepdf.Array) or first is None:
        return set()
    encoding = str(font.get("/Encoding", ""))
    if encoding not in {"/WinAnsiEncoding", "/MacRomanEncoding", "/StandardEncoding"}:
        return set()
    codec = "cp1252" if encoding == "/WinAnsiEncoding" else "mac_roman"
    chars: set[str] = set()
    for offset, width in enumerate(widths):
        if float(width) <= 0:
            continue
        code = int(first) + offset
        if not 0 <= code <= 0xFF:
            continue
        try:
            chars.add(bytes([code]).decode(codec))
        except (UnicodeDecodeError, ValueError):
            continue
    return chars


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


def check_content_text(pdf: pikepdf.Pdf, report: Report, secrets: list[str]) -> str:
    """Search the visible text layer for each secret."""
    text = extract_page_text(pdf)
    haystack = normalize(text)
    for secret in secrets:
        if normalize(secret) in haystack:
            report.add(
                Severity.CRITICAL,
                "content-stream",
                f"secret text still present in the page text layer: {secret!r}",
            )
    return text


def check_raw_objects(pdf: pikepdf.Pdf, report: Report, secrets: list[str]) -> None:
    """Search every decompressed stream and string object."""
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


def walk_struct(node: pikepdf.Object, seen: set[int], depth: int = 0) -> Iterator[str]:
    """Yield text carried by the tagged-PDF structure tree."""
    if depth > 64 or node is None:
        return
    key = id(node)
    if key in seen:
        return
    seen.add(key)

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


def check_structure_tree(pdf: pikepdf.Pdf, report: Report, secrets: list[str]) -> None:
    """Search the tagged-PDF structure tree, which pdftotext ignores."""
    root = pdf.Root.get("/StructTreeRoot")
    if root is None:
        report.add(
            Severity.INFO,
            "structure-tree",
            "document is not tagged; no structure tree to inspect",
        )
        return

    text = "\n".join(walk_struct(root, set()))
    report.add(
        Severity.INFO,
        "structure-tree",
        f"tagged PDF: {len(text)} characters of structure text inspected",
    )
    hay = normalize(text)
    for secret in secrets:
        if normalize(secret) in hay:
            report.add(
                Severity.CRITICAL,
                "structure-tree",
                f"secret survives in the tag tree (invisible to pdftotext): {secret!r}",
            )


def check_annotations(pdf: pikepdf.Pdf, report: Report, secrets: list[str]) -> None:
    """Search annotation contents and form field values."""
    for index, page in enumerate(pdf.pages, start=1):
        for annot in page.get("/Annots") or []:
            if not isinstance(annot, pikepdf.Dictionary):
                continue
            subtype = str(annot.get("/Subtype", ""))
            if subtype == "/Redact":
                report.add(
                    Severity.CRITICAL,
                    "annotations",
                    "unapplied /Redact annotation -- marks were saved, not applied",
                    f"page {index}",
                )
            parts = [
                str(annot[k])
                for k in ("/Contents", "/V", "/DV", "/RC", "/T")
                if isinstance(annot.get(k), pikepdf.String)
            ]
            hay = normalize(" ".join(parts))
            for secret in secrets:
                if normalize(secret) in hay:
                    report.add(
                        Severity.CRITICAL,
                        "annotations",
                        f"secret found in annotation {subtype}: {secret!r}",
                        f"page {index}",
                    )


def check_metadata(pdf: pikepdf.Pdf, report: Report, secrets: list[str]) -> None:
    """Search DocInfo and XMP, neither of which redaction tools clean."""
    blobs: list[tuple[str, str]] = []
    if pdf.trailer.get("/Info") is not None:
        for key, value in pdf.trailer["/Info"].items():
            if isinstance(value, pikepdf.String):
                blobs.append((f"DocInfo {key}", str(value)))
    meta = pdf.Root.get("/Metadata")
    if isinstance(meta, pikepdf.Stream):
        try:
            blobs.append(("XMP", meta.read_bytes().decode("utf-8", errors="ignore")))
        except pikepdf.PdfError:
            pass

    for label, blob in blobs:
        hay = normalize(blob)
        for secret in secrets:
            if normalize(secret) in hay:
                report.add(
                    Severity.CRITICAL,
                    "metadata",
                    f"secret found in metadata: {secret!r}",
                    label,
                )
        if label.startswith("DocInfo") and blob.strip():
            report.add(Severity.INFO, "metadata", f"{label} = {blob!r}")


def check_attachments(pdf: pikepdf.Pdf, report: Report) -> None:
    """Flag embedded files, which travel with the document unredacted."""
    names = pdf.Root.get("/Names")
    if names is None or "/EmbeddedFiles" not in names:
        return
    report.add(
        Severity.WARNING,
        "attachments",
        "document contains embedded file attachments; inspect them separately",
    )


def check_fonts(pdf: pikepdf.Pdf, report: Report, visible_text: str) -> None:
    """Detect orphaned glyph mappings left behind by post-hoc redaction."""
    visible = set(visible_text)
    for label, font in iter_fonts(pdf):
        charset = font_charset(font)
        if not charset:
            continue
        orphans = {
            c for c in charset - visible if c not in IGNORABLE_CHARS and c.isprintable()
        }
        if not orphans:
            continue
        sample = "".join(sorted(orphans))[:60]
        severity = Severity.WARNING if len(orphans) < 3 else Severity.CRITICAL
        report.add(
            severity,
            "font-charset",
            (
                f"{len(orphans)} character(s) mapped by the font subset but absent "
                f"from visible text: {sample!r} -- consistent with text removed from "
                "the content stream but not the font subset"
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


def analyze(path: Path, secrets: list[str]) -> Report:
    """Run every check against one PDF."""
    report = Report(path=path)
    with pikepdf.open(path) as pdf:
        visible_text = check_content_text(pdf, report, secrets)
        check_raw_objects(pdf, report, secrets)
        check_structure_tree(pdf, report, secrets)
        check_annotations(pdf, report, secrets)
        check_metadata(pdf, report, secrets)
        check_attachments(pdf, report)
        check_fonts(pdf, report, visible_text)
    return report


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
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns 2 on CRITICAL, 1 on WARNING, 0 otherwise."""
    args = build_parser().parse_args(argv)

    if not args.pdf.is_file():
        print(f"error: no such file: {args.pdf}", file=sys.stderr)
        return 3

    try:
        report = analyze(args.pdf, load_secrets(args))
    except pikepdf.PdfError as exc:
        print(f"error: could not read {args.pdf}: {exc}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
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
