#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sean Whalen
# SPDX-License-Identifier: MIT
"""Rebuild the sample PDFs in tests/samples.

One per failure mode, plus the clean controls -- an ordinary picture,
curly quotes, a plain letter -- that prove a check does not fire on a
document with nothing to find.

The samples are committed, so almost nothing in the suite runs this
script: the tests read the checked-in binaries, which keeps a run
deterministic. The one sanctioned exception is `tests/test_generator.py`,
which rebuilds the corpus into a temporary directory and compares what
the tool finds in each copy -- otherwise nothing would notice this file
being edited without the samples being regenerated. That test is why
reportlab is a development dependency and why `pytest` needs it
installed.

Run this by hand when adding a fixture or changing an existing one, and
commit the result. Keeping the generator alongside the binaries is the
point: a committed PDF in a security tool should never be a blob nobody
can reproduce or audit.

Every fixture uses a fictional address so the files are safe to commit
and safe to paste into a bug report.

    clean.pdf            nothing to find
    fake_redacted.pdf    black box drawn over live text
    orphan_font.pdf      stale ToUnicode CMap left by a post-hoc redaction
    tagged.pdf           secret survives in the tag tree, not on the page
    unapplied.pdf        /Redact annotation saved but never applied
    annotated.pdf        secret in a comment and a form field value
    attachments.pdf      secret in an embedded file, and in its name
    xmp.pdf              secret in the XMP metadata packet
    outline.pdf          secret in a bookmark title
    font_variants.pdf    every shape of font dictionary the tool reads
    differences.pdf      secret drawn through an /Encoding /Differences array
    identity_h.pdf       secret drawn with a two-byte Identity-H subset
    cleartext_stream.pdf a stream that claims FlateDecode and is not compressed
    image_stream.pdf     a JPEG, whose filter is not one that can be undone
    armored_image.pdf    the same JPEG, written as printable characters
    lying_image.pdf      compressed text under the name of an image filter
    smart_quotes.pdf     WinAnsi curly quotes, and nothing hidden
    broken_fonts.pdf     font dictionaries that cannot be read
    form_xobject.pdf     page text drawn inside a Form XObject
    saved_state.pdf      the font a q saved and a Q put back
    deep_nesting.pdf     structures nested deeper than any walk follows

Most of these render identically -- a leak that showed on screen would
not be a leak -- so each page carries a caption naming itself and what
it hides. See CAPTIONS below.
"""

from __future__ import annotations

import base64
import io
import zlib
from pathlib import Path

import pikepdf
import reportlab

# Pillow is reportlab's own dependency, so a checkout able to run this
# generator already has it. It is here to make one real JPEG.
from PIL import Image
from reportlab.lib.pagesizes import letter
from reportlab.pdfbase.ttfonts import TTFontFile
from reportlab.pdfgen import canvas

SECRET = "742 Evergreen Terrace"

SAMPLES = Path(__file__).resolve().parent / "tests" / "samples"

# Bitstream Vera Sans ships inside reportlab, so the sample that needs a
# real embedded TrueType subset does not have to carry a font of its own.
VERA = Path(reportlab.__file__).resolve().parent / "fonts" / "Vera.ttf"

BODY = [
    "Dear Sir or Madam,",
    "Please find enclosed the requested documents.",
    "Sincerely, A. Person",
]

# A line of typographic punctuation, for the sample that proves curly
# quotes are read as quotes rather than as leftovers of removed text.
# In WinAnsiEncoding these are the bytes 0x91 through 0x94.
SMART_QUOTES = "He said “the ‘enclosed’ papers” were sent."

# The standard PostScript name of every character of the secret that is
# not a letter, for the /Differences sample. A letter is named by itself;
# these are not, and naming them is how a producer such as LibreOffice
# writes the array. Looking a character up here rather than falling back
# to /uniXXXX means a secret that gained a character nobody named fails
# loudly instead of quietly changing what the sample tests. This maps a
# character to its name; the tool's own table goes the other way.
NON_LETTER_GLYPH_NAMES = {" ": "space", "2": "two", "4": "four", "7": "seven"}


# What each sample is, drawn on the page. Most of these documents would
# be indistinguishable from the same clean letter, because the leak in
# each one is invisible by definition; the caption is the only way to
# tell them apart in a viewer. No caption contains the secret.
CAPTIONS = {
    "clean.pdf": "Sample clean.pdf - nothing hidden anywhere",
    "fake_redacted.pdf": "Sample fake_redacted.pdf - black box drawn over live text",
    "orphan_font.pdf": "Sample orphan_font.pdf - stale ToUnicode CMap in the font",
    "tagged.pdf": "Sample tagged.pdf - address survives in the tag tree",
    "unapplied.pdf": "Sample unapplied.pdf - redaction mark saved but not applied",
    "annotated.pdf": "Sample annotated.pdf - address in a comment and a form field",
    "attachments.pdf": "Sample attachments.pdf - address in an embedded file and its name",
    "xmp.pdf": "Sample xmp.pdf - address in the XMP metadata packet",
    "outline.pdf": "Sample outline.pdf - address in a bookmark title",
    "font_variants.pdf": "Sample font_variants.pdf - every font dictionary shape",
    "differences.pdf": "Sample differences.pdf - address drawn through /Differences",
    "identity_h.pdf": "Sample identity_h.pdf - address drawn with two-byte codes",
    "cleartext_stream.pdf": (
        "Sample cleartext_stream.pdf - a stream that claims to be compressed"
    ),
    "image_stream.pdf": "Sample image_stream.pdf - a JPEG image, nothing hidden",
    "armored_image.pdf": (
        "Sample armored_image.pdf - a JPEG written as printable characters"
    ),
    "lying_image.pdf": (
        "Sample lying_image.pdf - compressed text under an image filter's name"
    ),
    "smart_quotes.pdf": "Sample smart_quotes.pdf - curly quotes, nothing hidden",
    "broken_fonts.pdf": "Sample broken_fonts.pdf - font dictionaries that misbehave",
    "form_xobject.pdf": "Sample form_xobject.pdf - text drawn inside a Form XObject",
    "saved_state.pdf": "Sample saved_state.pdf - a Q puts back the font a q saved",
    "deep_nesting.pdf": "Sample deep_nesting.pdf - nested deeper than a walk follows",
}

# The character codes the Form XObject sample draws, in WinAnsiEncoding.
# They are deliberately outside the letters the rest of the page uses, so
# that a font declaring them declares nothing the letter body could
# account for: 0xA5 to 0xA8 are the yen, broken bar, section and
# dieresis marks, and 0xB5 and 0xB6 are the micro and pilcrow signs.
OUTER_FORM_CODES = bytes(range(0xA5, 0xA9))
INNER_FORM_CODES = bytes(range(0xB5, 0xB7))

# The two fonts of the saved-state sample, as the standard PostScript
# glyph names a producer writes. Neither set of characters appears
# anywhere else on the page, so every one of them that shows up in the
# recovered text got there through the font named here.
#
# /FKept draws all three of its characters, after a Q has put it back in
# effect. /FDropped draws only the first of its four, so its other three
# are genuine leftovers -- and they are exactly the characters the codes
# drawn after the Q would spell if they were read through /FDropped,
# which is what makes the leftovers disappear when the Q is ignored.
KEPT_GLYPH_NAMES = ("Aacute", "Eacute", "Iacute")
DROPPED_GLYPH_NAMES = ("Ograve", "Ugrave", "Ydieresis", "Zcaron")

# How deep the deep-nesting sample nests, against a tool that follows 64
# levels. Deeper than the limit by enough that an off-by-one in either
# place cannot be what the sample is testing.
NESTING_DEPTH = 70

# The codes the innermost form of that sample draws, in WinAnsiEncoding:
# 0xBC to 0xBE are the three vulgar fractions. Nothing reaches them,
# which is the point of the sample.
DEEP_FORM_CODES = bytes(range(0xBC, 0xBF))


def unique_chars(text: str) -> list[str]:
    """Return the characters of `text` in order of first appearance."""
    return list(dict.fromkeys(text))


def page_text(caption: str, include_secret: bool, extra: str = "") -> str:
    """Return the visible text `letter_pdf` draws, in drawing order.

    Kept next to `letter_pdf` because the two must agree: the orphaned
    font sample builds its stale CMap from this text, and a CMap that
    did not match what was drawn would test nothing.

    `extra` is the optional fourth body line, drawn under the signature.
    An empty string means the page has none, which is the usual case.
    """
    parts = [BODY[0]]
    if include_secret:
        parts.append(SECRET)
    parts += [BODY[1], BODY[2]]
    if extra:
        parts.append(extra)
    parts.append(caption)
    return "".join(parts)


def letter_pdf(
    name: str,
    caption: str,
    include_secret: bool = True,
    cover: bool = False,
    extra: str = "",
) -> None:
    """Write a one-page letter, optionally with the secret drawn on it.

    The caption names the sample and what is hidden in it. Most of these
    documents are deliberately identical on screen -- that is the whole
    premise of the tool -- so without it there is no way to tell which
    file you have open.

    `extra` is an optional fourth body line, drawn under the signature.
    An empty string means the page has none.
    """
    c = canvas.Canvas(str(SAMPLES / name), pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(72, 720, BODY[0])
    if include_secret:
        c.drawString(72, 700, SECRET)
    c.drawString(72, 680, BODY[1])
    c.drawString(72, 660, BODY[2])
    if extra:
        c.drawString(72, 640, extra)
    if cover:
        c.setFillColorRGB(0, 0, 0)
        c.rect(70, 694, 200, 16, fill=1, stroke=0)
    c.setFillColorRGB(0.45, 0.45, 0.45)
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(72, 600, caption)
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
    caption = CAPTIONS["orphan_font.pdf"]
    letter_pdf("orphan_font.pdf", caption, include_secret=False)
    original = page_text(caption, include_secret=True)
    with pikepdf.open(SAMPLES / "orphan_font.pdf", allow_overwriting_input=True) as pdf:
        fonts = pdf.pages[0]["/Resources"]["/Font"]
        # Only the font that drew the redacted line carries the remnant.
        # The caption is set in a second, italic font that never rendered
        # the address, so a stale CMap there would be fiction.
        for name in list(fonts.keys()):
            if str(fonts[name].get("/BaseFont", "")) == "/Helvetica":
                fonts[name]["/ToUnicode"] = pdf.make_stream(build_cmap(original))
        pdf.save(SAMPLES / "orphan_font.pdf")


def build_tagged() -> None:
    """A page whose text is clean but whose tag tree keeps the secret."""
    letter_pdf("tagged.pdf", CAPTIONS["tagged.pdf"], include_secret=False)
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
    letter_pdf("unapplied.pdf", CAPTIONS["unapplied.pdf"], include_secret=True)
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
    letter_pdf("annotated.pdf", CAPTIONS["annotated.pdf"], include_secret=False)
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
    """A clean page dragging two unredacted files along with it.

    The first hides the address in its contents, which only the raw
    object sweep can reach. The second hides it in its *file name*,
    which is the layer the attachment check reports on: an attachment
    list is metadata about the document, and a name is often the whole
    leak.
    """
    letter_pdf("attachments.pdf", CAPTIONS["attachments.pdf"], include_secret=False)
    with pikepdf.open(SAMPLES / "attachments.pdf", allow_overwriting_input=True) as pdf:
        for filename, payload in (
            ("original_address.txt", f"resident: {SECRET}\n"),
            (f"{SECRET}.txt", "see the file name\n"),
        ):
            pdf.attachments[filename] = pikepdf.AttachedFileSpec(
                pdf,
                payload.encode(),
                filename=filename,
                description="pre-redaction source",
                mime_type="text/plain",
                creation_date="",
                mod_date="",
            )
        pdf.save(SAMPLES / "attachments.pdf")


def build_outline() -> None:
    """A clean page whose bookmark title still names the secret.

    Nothing has a dedicated check for the document outline, so this is
    the fixture for the catch-all sweep of string objects: text that no
    other layer claims.
    """
    letter_pdf("outline.pdf", CAPTIONS["outline.pdf"], include_secret=False)
    with pikepdf.open(SAMPLES / "outline.pdf", allow_overwriting_input=True) as pdf:
        item = pdf.make_indirect(
            pikepdf.Dictionary(
                Title=pikepdf.String(f"Correspondence about {SECRET}"),
                Dest=pikepdf.Array([pdf.pages[0].obj, pikepdf.Name("/Fit")]),
            )
        )
        outlines = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Outlines"),
                First=item,
                Last=item,
                Count=1,
            )
        )
        item["/Parent"] = outlines
        pdf.Root["/Outlines"] = outlines
        pdf.save(SAMPLES / "outline.pdf")


def build_xmp() -> None:
    """A clean page whose XMP packet still names the secret."""
    letter_pdf("xmp.pdf", CAPTIONS["xmp.pdf"], include_secret=False)
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
    letter_pdf("font_variants.pdf", CAPTIONS["font_variants.pdf"], include_secret=False)
    with pikepdf.open(
        SAMPLES / "font_variants.pdf", allow_overwriting_input=True
    ) as pdf:
        fonts = pdf.pages[0]["/Resources"]["/Font"]

        # Glyph names, one per route the tool resolves them by: a bare
        # character, uniXXXX, uXXXX, a standard PostScript name, a
        # Unicode character name for a glyph the standard names do not
        # cover, and one that resolves to nothing at all.
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
                        pikepdf.Name("/quoteright"),
                        pikepdf.Name("/infinity"),
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


def show_text(resource: str, codes: bytes, y: int) -> bytes:
    """Return drawing instructions that show raw character codes.

    The codes are written as a hex string, so they mean whatever the
    named font says they mean -- which is the point of the samples that
    use this. `0 g` restores black, because the caption drawn before
    this left the fill color grey.
    """
    return (
        b"BT 0 g /"
        + resource.encode("ascii")
        + b" 12 Tf 72 "
        + str(y).encode("ascii")
        + b" Td <"
        + codes.hex().encode("ascii")
        + b"> Tj ET\n"
    )


def draw_codes(pdf: pikepdf.Pdf, resource: str, codes: bytes) -> None:
    """Append a content stream drawing raw character codes on page 1."""
    pdf.pages[0].contents_add(pdf.make_stream(show_text(resource, codes, 700)))


def build_differences() -> None:
    """A page whose address is only legible through /Differences.

    The codes drawn on the page are 1 upwards and mean nothing on their
    own. The font's /Encoding /Differences array is what says which
    character each one stands for, so a reader that ignores it recovers
    nothing from this page.

    The glyph names are the ones a real producer writes: a letter is
    named by itself, and everything else by its standard PostScript name
    -- /seven, not /uni0037.
    """
    name = "differences.pdf"
    letter_pdf(name, CAPTIONS[name], include_secret=False)
    chars = unique_chars(SECRET)
    with pikepdf.open(SAMPLES / name, allow_overwriting_input=True) as pdf:
        differences: list[int | pikepdf.Name] = [1]
        for char in chars:
            if char.isalpha():
                differences.append(pikepdf.Name(f"/{char}"))
            else:
                differences.append(pikepdf.Name(f"/{NON_LETTER_GLYPH_NAMES[char]}"))
        pdf.pages[0]["/Resources"]["/Font"]["/FDiff"] = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Font"),
                Subtype=pikepdf.Name("/Type1"),
                BaseFont=pikepdf.Name("/Helvetica"),
                Encoding=pikepdf.Dictionary(
                    Type=pikepdf.Name("/Encoding"),
                    BaseEncoding=pikepdf.Name("/WinAnsiEncoding"),
                    Differences=differences,
                ),
            )
        )
        draw_codes(pdf, "FDiff", bytes(chars.index(c) + 1 for c in SECRET))
        pdf.save(SAMPLES / name)


def build_identity_h() -> None:
    """A page whose address is drawn as two-byte codes.

    A composite (/Type0) font addressed through /Identity-H takes two
    bytes per character code, not one. The embedded subset here is cut
    from Bitstream Vera Sans, which ships with reportlab, and the codes
    are the glyph numbers inside that subset; the font's /ToUnicode CMap
    is the only thing that says which character each one draws.
    """
    name = "identity_h.pdf"
    letter_pdf(name, CAPTIONS[name], include_secret=False)
    chars = unique_chars(SECRET)
    face = TTFontFile(str(VERA))
    # reportlab's subsetter reserves glyph 0 for "missing character" and
    # numbers the rest in the order asked for, so chars[i] is glyph i+1.
    program = face.makeSubset([ord(c) for c in chars])
    base = pikepdf.Name("/AAAAAA+" + face.name.decode("ascii"))

    entries = "\n".join(
        f"<{index + 1:04X}> <{ord(char):04X}>" for index, char in enumerate(chars)
    )
    cmap = f"""/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CMapName /Identity-Sample def
/CMapType 2 def
1 begincodespacerange
<0000> <FFFF>
endcodespacerange
{len(chars)} beginbfchar
{entries}
endbfchar
endcmap
CMapName currentdict /CMap defineresource pop
end
end
""".encode("ascii")

    with pikepdf.open(SAMPLES / name, allow_overwriting_input=True) as pdf:
        font_file = pdf.make_stream(program)
        font_file["/Length1"] = len(program)
        descriptor = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/FontDescriptor"),
                FontName=base,
                Flags=4,
                FontBBox=[round(value) for value in face.bbox],
                ItalicAngle=round(face.italicAngle),
                Ascent=round(face.ascent),
                Descent=round(face.descent),
                CapHeight=round(face.capHeight),
                StemV=round(face.stemV),
                FontFile2=pdf.make_indirect(font_file),
            )
        )
        descendant = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Font"),
                Subtype=pikepdf.Name("/CIDFontType2"),
                BaseFont=base,
                CIDSystemInfo=pikepdf.Dictionary(
                    Registry=pikepdf.String("Adobe"),
                    Ordering=pikepdf.String("Identity"),
                    Supplement=0,
                ),
                FontDescriptor=descriptor,
                DW=round(face.defaultWidth),
                CIDToGIDMap=pikepdf.Name("/Identity"),
            )
        )
        pdf.pages[0]["/Resources"]["/Font"]["/FCID"] = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Font"),
                Subtype=pikepdf.Name("/Type0"),
                BaseFont=base,
                Encoding=pikepdf.Name("/Identity-H"),
                DescendantFonts=[descendant],
                ToUnicode=pdf.make_indirect(pdf.make_stream(cmap)),
            )
        )
        codes = b"".join((chars.index(char) + 1).to_bytes(2, "big") for char in SECRET)
        draw_codes(pdf, "FCID", codes)
        pdf.save(SAMPLES / name)


def build_cleartext_stream() -> None:
    """A page carrying a stream that lies about being compressed.

    The stream says /Filter /FlateDecode and holds plain text, so
    decompressing it fails. The address is sitting in the file in the
    clear, and a checker that quietly skips the streams it cannot
    decompress reports the document as having nothing to find.
    """
    name = "cleartext_stream.pdf"
    letter_pdf(name, CAPTIONS[name], include_secret=False)
    with pikepdf.open(SAMPLES / name, allow_overwriting_input=True) as pdf:
        stream = pikepdf.Stream(pdf, b"")
        stream.write(
            f"resident: {SECRET}\n".encode(),
            filter=pikepdf.Name("/FlateDecode"),
        )
        pdf.Root["/OriginalRecord"] = pdf.make_indirect(stream)
        pdf.save(SAMPLES / name)


def jpeg_bytes() -> bytes:
    """Return a small grey JPEG, built here rather than committed."""
    photo = io.BytesIO()
    Image.new("L", (32, 32), color=200).save(photo, format="JPEG")
    return photo.getvalue()


def place_image(pdf: pikepdf.Pdf, stored: bytes, filters: pikepdf.Object) -> None:
    """Put a 32x32 grayscale image on page 1, stored exactly as given.

    `stored` is written into the stream untouched and `filters` is the
    /Filter entry that describes it, so a caller can build a picture
    that is what it says it is -- and, for the sample that needs it, one
    that is not.
    """
    image = pdf.make_stream(stored)
    image["/Type"] = pikepdf.Name("/XObject")
    image["/Subtype"] = pikepdf.Name("/Image")
    image["/Width"] = 32
    image["/Height"] = 32
    image["/ColorSpace"] = pikepdf.Name("/DeviceGray")
    image["/BitsPerComponent"] = 8
    image["/Filter"] = filters
    pdf.pages[0]["/Resources"]["/XObject"] = pikepdf.Dictionary(
        Im0=pdf.make_indirect(image)
    )
    pdf.pages[0].contents_add(pdf.make_stream(b"q 64 0 0 64 400 650 cm /Im0 Do Q\n"))


def build_image_stream() -> None:
    """A page with a JPEG image on it, and nothing hidden.

    A JPEG inside a PDF is stored as it came, under /DCTDecode -- a
    filter pikepdf does not run, so asking for the stream's decoded
    bytes raises exactly as it does for the sample above. The two must
    not be reported alike: a scanned document is made of these, and a
    check that called each one a layer it could not read would call
    every scan suspicious.
    """
    name = "image_stream.pdf"
    letter_pdf(name, CAPTIONS[name], include_secret=False)
    with pikepdf.open(SAMPLES / name, allow_overwriting_input=True) as pdf:
        # The JPEG is stored as it stands, which is what /DCTDecode
        # means: the filter names the format of the bytes rather than a
        # compression this could undo.
        place_image(pdf, jpeg_bytes(), pikepdf.Name("/DCTDecode"))
        pdf.save(SAMPLES / name)


def build_armored_image() -> None:
    """The same JPEG, written out as printable characters.

    `[/ASCII85Decode /DCTDecode]` is the filter chain the Distiller line
    of producers writes for a JPEG: the picture is spelled in printable
    characters, and undoing that spelling leaves the picture. pikepdf
    still refuses the chain, because of the /DCTDecode stage, so a
    checker that only exempts a lone image filter reports an ordinary
    scanned page as a layer it could not read.
    """
    name = "armored_image.pdf"
    letter_pdf(name, CAPTIONS[name], include_secret=False)
    # a85encode's Adobe framing puts <~ in front and ~> behind. A PDF
    # stream carries only the closing marker (ISO 32000 section 7.4.3).
    armored = base64.a85encode(jpeg_bytes(), adobe=True)[2:]
    with pikepdf.open(SAMPLES / name, allow_overwriting_input=True) as pdf:
        place_image(
            pdf,
            armored,
            pikepdf.Array([pikepdf.Name("/ASCII85Decode"), pikepdf.Name("/DCTDecode")]),
        )
        pdf.save(SAMPLES / name)


def build_lying_image() -> None:
    """A stream that hides compressed text under an image filter's name.

    /Filter is a claim the document makes about itself, and this is the
    sample where the claim is false: the stream says /DCTDecode, which
    would make it a JPEG, and holds the address compressed instead.
    Nothing can read those bytes -- pikepdf will not run /DCTDecode, and
    the bytes as stored are compressed -- so the address is in the file
    and beyond every check here. Exempting the stream because of the
    name it gave itself is how that gets reported as nothing to find.
    """
    name = "lying_image.pdf"
    letter_pdf(name, CAPTIONS[name], include_secret=False)
    with pikepdf.open(SAMPLES / name, allow_overwriting_input=True) as pdf:
        stream = pdf.make_stream(zlib.compress(f"resident: {SECRET}\n".encode()))
        stream["/Filter"] = pikepdf.Name("/DCTDecode")
        pdf.Root["/OriginalRecord"] = pdf.make_indirect(stream)
        pdf.save(SAMPLES / name)


def build_smart_quotes() -> None:
    """A page with curly quotes on it, and nothing hidden.

    In WinAnsiEncoding the typographic quotes are the bytes 0x91 to
    0x94, which are unassigned in Latin-1 and undefined in Adobe's
    StandardEncoding. Reading the page through the wrong table turns
    them into control characters, and the four quotes the font declares
    then look like characters that were removed from the page -- a
    clean document reported as a failed redaction.
    """
    name = "smart_quotes.pdf"
    letter_pdf(name, CAPTIONS[name], include_secret=False, extra=SMART_QUOTES)
    with pikepdf.open(SAMPLES / name, allow_overwriting_input=True) as pdf:
        # reportlab writes base-14 fonts without a /Widths array. Adding
        # one for exactly the four quote codes is what gives the font
        # subset check something to compare the page against.
        fonts = pdf.pages[0]["/Resources"]["/Font"]
        for key in list(fonts.keys()):
            if str(fonts[key].get("/BaseFont", "")) == "/Helvetica":
                fonts[key]["/FirstChar"] = 0x91
                fonts[key]["/LastChar"] = 0x94
                fonts[key]["/Widths"] = [500, 500, 500, 500]
        pdf.save(SAMPLES / name)


def build_broken_fonts() -> None:
    """A page whose font dictionaries cannot be read all the way.

    Five ways that happens, none of which may end in a crash or in a
    silent "nothing declared": a composite font listed as its own
    descendant, a /Widths array with a name where a number belongs, a
    /FirstChar that is not a number at all, a /Font resource that is a
    number rather than a font dictionary, and a /ToUnicode entry that is
    a number rather than the stream a character map lives in.

    The last two matter because pikepdf hands a number back as a plain
    Python int, which has none of the methods a font is read with, so
    reading one used to end the whole run in a traceback -- and a run
    that ended there reported no findings at all.
    """
    name = "broken_fonts.pdf"
    letter_pdf(name, CAPTIONS[name], include_secret=False)
    with pikepdf.open(SAMPLES / name, allow_overwriting_input=True) as pdf:
        fonts = pdf.pages[0]["/Resources"]["/Font"]

        looped = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Font"),
                Subtype=pikepdf.Name("/Type0"),
                BaseFont=pikepdf.Name("/ABCDEF+Loop"),
                Encoding=pikepdf.Name("/Identity-H"),
            )
        )
        looped["/DescendantFonts"] = pikepdf.Array([looped])
        fonts["/FLoop"] = looped

        # Codes 65 and 67 are A and C. A is on the page and C is not, so
        # this font also stands for the one-orphan case: a warning, not
        # the critical verdict three or more orphans earn.
        fonts["/FBadWidth"] = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Font"),
                Subtype=pikepdf.Name("/TrueType"),
                BaseFont=pikepdf.Name("/Arial"),
                Encoding=pikepdf.Name("/WinAnsiEncoding"),
                FirstChar=65,
                Widths=[500, pikepdf.Name("/NotANumber"), 500],
            )
        )

        fonts["/FBadFirstChar"] = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Font"),
                Subtype=pikepdf.Name("/TrueType"),
                BaseFont=pikepdf.Name("/Arial"),
                Encoding=pikepdf.Name("/WinAnsiEncoding"),
                FirstChar=pikepdf.String("sixty-five"),
                Widths=[500],
            )
        )

        # A /Font group entry that is not a font at all, and a font
        # whose /ToUnicode is not the stream a character map lives in.
        fonts["/FScalar"] = 42
        fonts["/FScalarCMap"] = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/Font"),
                Subtype=pikepdf.Name("/Type1"),
                BaseFont=pikepdf.Name("/Helvetica"),
                ToUnicode=42,
            )
        )

        # Both of those are drawn with, because the page text is read
        # through the font in effect: a font that cannot be read has to
        # cost the text it drew and nothing more. The codes are X and Y,
        # which are on no other font's list here -- drawing an A or a C
        # would put a character /FBadWidth declares onto the page and
        # quietly cost this sample its one-orphan case.
        page = pdf.pages[0]
        page.contents_add(pdf.make_stream(show_text("FScalar", b"XY", 580)))
        page.contents_add(pdf.make_stream(show_text("FScalarCMap", b"XY", 560)))
        pdf.save(SAMPLES / name)


def widths_font(first: int, count: int) -> pikepdf.Dictionary:
    """Return a font dictionary declaring `count` consecutive codes.

    A subset font keeps a width for every code it can draw, so a
    /Widths array is the shortest way to make a font declare exactly
    the characters a sample wants it to declare.
    """
    return pikepdf.Dictionary(
        Type=pikepdf.Name("/Font"),
        Subtype=pikepdf.Name("/Type1"),
        BaseFont=pikepdf.Name("/Helvetica"),
        Encoding=pikepdf.Name("/WinAnsiEncoding"),
        FirstChar=first,
        Widths=[500] * count,
    )


def form(
    pdf: pikepdf.Pdf, body: bytes, resources: pikepdf.Object | None
) -> pikepdf.Object:
    """Return a Form XObject drawing `body`, with or without resources.

    A Form XObject is a content stream of its own that a page draws with
    the `Do` operator. One that carries no /Resources of its own draws
    with the resources of whatever drew it (ISO 32000 section 8.10.1).
    """
    stream = pdf.make_stream(body)
    stream["/Type"] = pikepdf.Name("/XObject")
    stream["/Subtype"] = pikepdf.Name("/Form")
    stream["/BBox"] = [0, 0, 612, 792]
    if resources is not None:
        stream["/Resources"] = resources
    return pdf.make_indirect(stream)


def build_form_xobject() -> None:
    """A page that draws part of its text inside Form XObjects.

    Two of them, for the two ways a form relates to the page's
    resources.

    /Fm0 carries no resources of its own, so it draws with the page's,
    through a font the page defines. Everything it shows is on the
    screen like any other page text -- but a checker that reads only the
    page's own content stream never sees it, and then reports every
    character that font declares as a leftover of a removed passage.
    That is a clean document called a failed redaction.

    /Fm1 brings its own resources, naming a font the page never names.
    That font declares one character it does not draw, which is a real
    orphan and the finding this sample is meant to produce -- and one
    that nothing reaches without following the form.
    """
    name = "form_xobject.pdf"
    letter_pdf(name, CAPTIONS[name], include_secret=False)
    with pikepdf.open(SAMPLES / name, allow_overwriting_input=True) as pdf:
        page = pdf.pages[0]
        page["/Resources"]["/Font"]["/FOuter"] = pdf.make_indirect(
            widths_font(OUTER_FORM_CODES[0], len(OUTER_FORM_CODES))
        )
        inner = pikepdf.Dictionary(
            Font=pikepdf.Dictionary(
                FInner=pdf.make_indirect(
                    widths_font(INNER_FORM_CODES[0], len(INNER_FORM_CODES))
                )
            )
        )
        page["/Resources"]["/XObject"] = pikepdf.Dictionary(
            Fm0=form(pdf, show_text("FOuter", OUTER_FORM_CODES, 580), None),
            # The form draws the first of the two codes its own font
            # declares. The second is the orphan.
            Fm1=form(pdf, show_text("FInner", INNER_FORM_CODES[:1], 560), inner),
        )
        page.contents_add(pdf.make_stream(b"q /Fm0 Do Q q /Fm1 Do Q\n"))
        pdf.save(SAMPLES / name)


def differences_font(names: tuple[str, ...]) -> pikepdf.Dictionary:
    """Return a font whose /Differences maps code 1 upwards to `names`.

    The codes themselves mean nothing without the array: 1, 2 and 3 are
    control codes in every base encoding, so whatever these characters
    turn out to be, the /Differences array of the font in effect is what
    decided it.
    """
    return pikepdf.Dictionary(
        Type=pikepdf.Name("/Font"),
        Subtype=pikepdf.Name("/Type1"),
        BaseFont=pikepdf.Name("/Helvetica"),
        Encoding=pikepdf.Dictionary(
            Type=pikepdf.Name("/Encoding"),
            Differences=[1, *(pikepdf.Name(f"/{name}") for name in names)],
        ),
    )


def build_saved_state() -> None:
    """A page that draws text with the font a Q put back in effect.

    The font is part of the graphics state that `q` saves and `Q`
    restores (ISO 32000 section 8.4.2), and a producer wraps a block of
    drawing in the pair as a matter of course. The page selects /FKept,
    draws one character inside a q ... Q pair through /FDropped, and
    then draws three more codes with no /Tf of its own -- so what those
    codes spell is decided by the font the Q put back.

    Reading the page as though the Q had not happened gets both fonts
    wrong at once. The three codes come out as three of the four
    characters /FDropped declares, which hides the leftovers that font
    really does carry; and the three characters /FKept declares are then
    nowhere in the recovered text, so a font that drew everything it
    declares is reported as the remnant of a removed passage.
    """
    name = "saved_state.pdf"
    letter_pdf(name, CAPTIONS[name], include_secret=False)
    with pikepdf.open(SAMPLES / name, allow_overwriting_input=True) as pdf:
        fonts = pdf.pages[0]["/Resources"]["/Font"]
        fonts["/FKept"] = pdf.make_indirect(differences_font(KEPT_GLYPH_NAMES))
        fonts["/FDropped"] = pdf.make_indirect(differences_font(DROPPED_GLYPH_NAMES))
        # `0 g` restores black, which the grey caption left set. /Tf is a
        # text-state operator and is legal outside a text object, which
        # is where a producer puts it when several text objects share a
        # font.
        pdf.pages[0].contents_add(
            pdf.make_stream(
                b"0 g /FKept 12 Tf\n"
                b"q /FDropped 12 Tf BT 72 580 Td <01> Tj ET Q\n"
                b"BT 72 560 Td <010203> Tj ET\n"
            )
        )
        pdf.save(SAMPLES / name)


def build_deep_nesting() -> None:
    """A document nested deeper than any walk here follows.

    Every walk of the object graph stops at a fixed depth, because a
    hostile file can nest structures as deeply as it likes and a walk
    that followed them would never finish. Stopping is not the problem;
    stopping quietly is. This sample is what proves each walk says where
    it gave up, rather than reporting the part it managed to read as the
    whole of the document.

    Two nests, for the two shapes that matters in. The tag tree carries
    the address at the bottom of a chain of /K entries, so a walk that
    stopped without saying so would report a tagged document as carrying
    no structure text at all. The page draws a Form XObject that draws a
    Form XObject, and so on down to one that draws text through a font
    of its own -- so the same silence would cost the text that form
    draws, and then report the characters that font declares as the
    remnant of a passage that was removed.
    """
    name = "deep_nesting.pdf"
    letter_pdf(name, CAPTIONS[name], include_secret=False)
    with pikepdf.open(SAMPLES / name, allow_overwriting_input=True) as pdf:
        node = pdf.make_indirect(
            pikepdf.Dictionary(
                Type=pikepdf.Name("/StructElem"),
                S=pikepdf.Name("/Span"),
                ActualText=pikepdf.String(SECRET),
            )
        )
        for _ in range(NESTING_DEPTH):
            node = pdf.make_indirect(
                pikepdf.Dictionary(
                    Type=pikepdf.Name("/StructElem"),
                    S=pikepdf.Name("/Span"),
                    K=node,
                )
            )
        pdf.Root["/StructTreeRoot"] = pdf.make_indirect(
            pikepdf.Dictionary(Type=pikepdf.Name("/StructTreeRoot"), K=node)
        )
        pdf.Root["/MarkInfo"] = pikepdf.Dictionary(Marked=True)

        nested = form(
            pdf,
            show_text("FDeep", DEEP_FORM_CODES, 580),
            pikepdf.Dictionary(
                Font=pikepdf.Dictionary(
                    FDeep=pdf.make_indirect(
                        widths_font(DEEP_FORM_CODES[0], len(DEEP_FORM_CODES))
                    )
                )
            ),
        )
        for _ in range(NESTING_DEPTH):
            nested = form(
                pdf,
                b"q /Fm Do Q\n",
                pikepdf.Dictionary(XObject=pikepdf.Dictionary(Fm=nested)),
            )
        pdf.pages[0]["/Resources"]["/XObject"] = pikepdf.Dictionary(Fm0=nested)
        pdf.pages[0].contents_add(pdf.make_stream(b"q /Fm0 Do Q\n"))
        pdf.save(SAMPLES / name)


def main() -> None:
    """Rewrite every fixture in tests/samples."""
    SAMPLES.mkdir(parents=True, exist_ok=True)
    letter_pdf("clean.pdf", CAPTIONS["clean.pdf"], include_secret=False)
    letter_pdf(
        "fake_redacted.pdf",
        CAPTIONS["fake_redacted.pdf"],
        include_secret=True,
        cover=True,
    )
    build_orphan_font()
    build_tagged()
    build_unapplied()
    build_annotated()
    build_attachments()
    build_xmp()
    build_outline()
    build_font_variants()
    build_differences()
    build_identity_h()
    build_cleartext_stream()
    build_image_stream()
    build_armored_image()
    build_lying_image()
    build_smart_quotes()
    build_broken_fonts()
    build_form_xobject()
    build_saved_state()
    build_deep_nesting()
    print(f"wrote {len(CAPTIONS)} sample PDFs to {SAMPLES}")


if __name__ == "__main__":
    main()
