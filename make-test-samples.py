#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sean Whalen
# SPDX-License-Identifier: MIT
"""Rebuild the sample PDFs in tests/samples, one per failure mode.

The samples are committed, so the tests do not run this script and do
not need reportlab. Run it by hand when adding a fixture or changing an
existing one, and commit the result. Keeping the generator alongside the
binaries is the point: a committed PDF in a security tool should never
be a blob nobody can reproduce or audit.

Every fixture uses a fictional address so the files are safe to commit
and safe to paste into a bug report.

    clean.pdf           nothing to find
    fake_redacted.pdf   black box drawn over live text
    orphan_font.pdf     stale ToUnicode CMap left by a post-hoc redaction
    tagged.pdf          secret survives in the tag tree, not on the page
    unapplied.pdf       /Redact annotation saved but never applied
"""

from __future__ import annotations

from pathlib import Path

import pikepdf
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

SECRET = "742 Evergreen Terrace"

SAMPLES = Path(__file__).resolve().parent / "tests" / "samples"

BODY = [
    "Dear Sir or Madam,",
    "Please find enclosed the requested documents.",
    "Sincerely, A. Person",
]


def letter_pdf(name: str, include_secret: bool = True, cover: bool = False) -> None:
    """Write a one-page letter, optionally with the secret drawn on it."""
    c = canvas.Canvas(str(SAMPLES / name), pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(72, 720, BODY[0])
    if include_secret:
        c.drawString(72, 700, SECRET)
    c.drawString(72, 680, BODY[1])
    c.drawString(72, 660, BODY[2])
    if cover:
        c.setFillColorRGB(0, 0, 0)
        c.rect(70, 694, 200, 16, fill=1, stroke=0)
    c.save()


def build_cmap(text: str) -> bytes:
    """Build a ToUnicode CMap in order of each character's first use.

    This is how real producers build the table, and it is why a stale
    CMap leaks the wording that was removed: the order of the entries
    follows the order of the original text.
    """
    chars = list(dict.fromkeys(c for c in text if 32 <= ord(c) < 127))
    entries = "\n".join(f"<{ord(c):02X}> <{ord(c):04X}>" for c in chars)
    return f"""/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CMapName /Stale-UCS2 def
/CMapType 2 def
1 begincodespacerange
<00> <FF>
endcodespacerange
{len(chars)} beginbfchar
{entries}
endbfchar
endcmap
CMapName currentdict /CMap defineresource pop
end
end
""".encode("ascii")


def build_orphan_font() -> None:
    """A page whose text is clean but whose font still maps the secret.

    The visible text is drawn without the secret. The font then gets a
    ToUnicode CMap built from the text as it was *before* redaction, so
    the CMap maps characters that appear nowhere on the page -- the
    remnant the Australian Signals Directorate documented.
    """
    letter_pdf("orphan_font.pdf", include_secret=False)
    original = BODY[0] + SECRET + BODY[1] + BODY[2]
    with pikepdf.open(SAMPLES / "orphan_font.pdf", allow_overwriting_input=True) as pdf:
        fonts = pdf.pages[0]["/Resources"]["/Font"]
        for name in list(fonts.keys()):
            fonts[name]["/ToUnicode"] = pdf.make_stream(build_cmap(original))
        pdf.save(SAMPLES / "orphan_font.pdf")


def build_tagged() -> None:
    """A page whose text is clean but whose tag tree keeps the secret."""
    letter_pdf("tagged.pdf", include_secret=False)
    with pikepdf.open(SAMPLES / "tagged.pdf", allow_overwriting_input=True) as pdf:
        span = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/StructElem"),
                S=pikepdf.Name("/Span"),
                ActualText=pikepdf.String(SECRET),
            )
        )
        pdf.Root["/StructTreeRoot"] = pdf.make_indirect(
            pikepdf.Dictionary(Type=pikepdf.Name("/StructTreeRoot"), K=span)
        )
        pdf.Root["/MarkInfo"] = pikepdf.Dictionary(Marked=True)
        pdf.save(SAMPLES / "tagged.pdf")


def build_unapplied() -> None:
    """A page carrying redaction marks that were saved but never applied."""
    letter_pdf("unapplied.pdf", include_secret=True)
    with pikepdf.open(SAMPLES / "unapplied.pdf", allow_overwriting_input=True) as pdf:
        page = pdf.pages[0]
        annot = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Annot"),
                Subtype=pikepdf.Name("/Redact"),
                Rect=[70, 694, 270, 710],
                Contents=pikepdf.String(SECRET),
            )
        )
        page["/Annots"] = pdf.make_indirect(pikepdf.Array([annot]))
        pdf.save(SAMPLES / "unapplied.pdf")


def build_annotated() -> None:
    """A clean page carrying the secret in a comment and a form field."""
    letter_pdf("annotated.pdf", include_secret=False)
    with pikepdf.open(SAMPLES / "annotated.pdf", allow_overwriting_input=True) as pdf:
        comment = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Annot"),
                Subtype=pikepdf.Name("/FreeText"),
                Rect=[300, 690, 500, 710],
                Contents=pikepdf.String(f"reviewer note: {SECRET}"),
            )
        )
        field = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Annot"),
                Subtype=pikepdf.Name("/Widget"),
                FT=pikepdf.Name("/Tx"),
                Rect=[300, 650, 500, 670],
                T=pikepdf.String("address"),
                V=pikepdf.String(SECRET),
            )
        )
        pdf.pages[0]["/Annots"] = pdf.make_indirect(pikepdf.Array([comment, field]))
        # A widget annotation has to be reachable from /AcroForm, or the
        # form is malformed and readers may not display the field.
        pdf.Root["/AcroForm"] = pdf.make_indirect(
            pikepdf.Dictionary(Fields=[field], NeedAppearances=True)
        )
        pdf.save(SAMPLES / "annotated.pdf")


def build_attachments() -> None:
    """A clean page dragging an unredacted file along with it."""
    letter_pdf("attachments.pdf", include_secret=False)
    with pikepdf.open(SAMPLES / "attachments.pdf", allow_overwriting_input=True) as pdf:
        spec = pikepdf.AttachedFileSpec(
            pdf,
            f"resident: {SECRET}\n".encode(),
            filename="original_address.txt",
            description="pre-redaction source",
            mime_type="text/plain",
            creation_date="",
            mod_date="",
        )
        pdf.attachments["original_address.txt"] = spec
        pdf.save(SAMPLES / "attachments.pdf")


def build_xmp() -> None:
    """A clean page whose XMP packet still names the secret."""
    letter_pdf("xmp.pdf", include_secret=False)
    packet = f"""<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/">
   <dc:title>Letter concerning {SECRET}</dc:title>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>""".encode()
    with pikepdf.open(SAMPLES / "xmp.pdf", allow_overwriting_input=True) as pdf:
        stream = pdf.make_stream(packet)
        stream["/Type"] = pikepdf.Name("/Metadata")
        stream["/Subtype"] = pikepdf.Name("/XML")
        pdf.Root["/Metadata"] = pdf.make_indirect(stream)
        pdf.save(SAMPLES / "xmp.pdf")


def build_font_variants() -> None:
    """Every shape of font dictionary the charset reader understands.

    One document covering /Differences glyph names, /Widths with a
    simple encoding, a Type 1 /CharSet list, and a Type 0 font whose
    characters live on a descendant. The fonts are never drawn with --
    the point is the metadata, not the rendering.
    """
    letter_pdf("font_variants.pdf", include_secret=False)
    with pikepdf.open(
        SAMPLES / "font_variants.pdf", allow_overwriting_input=True
    ) as pdf:
        fonts = pdf.pages[0]["/Resources"]["/Font"]

        # Glyph names: a bare character, uniXXXX, uXXXX, a Unicode name,
        # and one that resolves to nothing at all.
        fonts["/FDiff"] = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Font"),
                Subtype=pikepdf.Name("/Type1"),
                BaseFont=pikepdf.Name("/Helvetica"),
                Encoding=pikepdf.Dictionary(
                    Type=pikepdf.Name("/Encoding"),
                    Differences=[
                        0,
                        pikepdf.Name("/z"),
                        pikepdf.Name("/uni0037"),
                        pikepdf.Name("/u0034"),
                        pikepdf.Name("/bullet"),
                        pikepdf.Name("/notaglyphname"),
                    ],
                ),
            )
        )

        # /Widths: codes 90..92, with a zero width in the middle that
        # must be skipped.
        fonts["/FWidth"] = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Font"),
                Subtype=pikepdf.Name("/TrueType"),
                BaseFont=pikepdf.Name("/Arial"),
                Encoding=pikepdf.Name("/WinAnsiEncoding"),
                FirstChar=90,
                Widths=[500, 0, 500],
            )
        )

        # A Type 1 subset's /CharSet glyph list.
        fonts["/FCharSet"] = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Font"),
                Subtype=pikepdf.Name("/Type1"),
                BaseFont=pikepdf.Name("/ABCDEF+Times"),
                FontDescriptor=pikepdf.Dictionary(
                    Type=pikepdf.Name("/FontDescriptor"),
                    FontName=pikepdf.Name("/ABCDEF+Times"),
                    CharSet=pikepdf.String("/q/uni0039/notaglyphname"),
                ),
            )
        )

        # A Type 0 font whose characters are declared by its descendant.
        descendant = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Font"),
                Subtype=pikepdf.Name("/CIDFontType0"),
                BaseFont=pikepdf.Name("/ABCDEF+Song"),
                FontDescriptor=pikepdf.Dictionary(
                    Type=pikepdf.Name("/FontDescriptor"),
                    FontName=pikepdf.Name("/ABCDEF+Song"),
                    CharSet=pikepdf.String("/w"),
                ),
            )
        )
        fonts["/FType0"] = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Font"),
                Subtype=pikepdf.Name("/Type0"),
                BaseFont=pikepdf.Name("/ABCDEF+Song"),
                Encoding=pikepdf.Name("/Identity-H"),
                DescendantFonts=[descendant],
            )
        )
        pdf.save(SAMPLES / "font_variants.pdf")


def main() -> None:
    """Rewrite every fixture in tests/samples."""
    SAMPLES.mkdir(parents=True, exist_ok=True)
    letter_pdf("clean.pdf", include_secret=False)
    letter_pdf("fake_redacted.pdf", include_secret=True, cover=True)
    build_orphan_font()
    build_tagged()
    build_unapplied()
    build_annotated()
    build_attachments()
    build_xmp()
    build_font_variants()
    print(f"wrote 9 sample PDFs to {SAMPLES}")


if __name__ == "__main__":
    main()
