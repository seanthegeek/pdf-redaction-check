# Changelog

All notable changes to this project are recorded here.

The format is based on [Keep a Changelog][kac], and this project follows
[Semantic Versioning][semver]. The exit codes are part of the public interface:
changing what one of them means is a breaking change and gets a major version
bump.

## [Unreleased]

## [0.1.0] - 2026-08-02

First release.

### Added

- `pdf-redaction-check`, a read-only command that reports whether text survived
  a PDF redaction. It never edits, repairs, or re-saves the document under
  inspection.
- Seven checked layers, each reported with the observation and the inference
  stated separately:
  - **Content stream** — text drawn on the page, including text hidden under a
    filled rectangle, and text drawn inside a Form XObject, which is a content
    stream of its own that the page invokes with the `Do` operator.
  - **Raw objects** — stream and string data outside the text layer, decoded
    where the filters can be undone and searched as stored where they cannot.
  - **Structure tree** — the parallel copy of the text that tagged PDFs carry in
    `/ActualText`, `/Alt`, `/E`, `/T`, and `/TU`, which a naive text extraction
    never reads.
  - **Annotations** — comment text, form field values, and `/Redact` marks that
    were placed but never applied.
  - **Metadata** — DocInfo and XMP, which redaction tools generally do not
    clean.
  - **Attachments** — embedded files carried along unredacted.
  - **Font subsets** — orphaned `ToUnicode`, `/Differences`, `/CharSet`, and
    `/Widths` entries, in every font a page's resources reach, including the
    fonts named only by a Form XObject's own resources. This is the failure mode
    the Australian Signals Directorate documented in 2021: removing the visible
    glyphs does not rebuild the font's character map, so the characters of the
    removed text stay behind. The check reports what it found as *consistent
    with* removed text, never as proof of it.
- Page text read through the font that draws it. Each character code is mapped
  through the font's `ToUnicode` table, then its `/Encoding` and any
  `/Differences`, then the base encoding, with two-byte codes handled for
  composite fonts. A glyph name is resolved by the standard names of ISO 32000
  Annex D — the ones producers such as LibreOffice and Ghostscript write,
  `/seven` rather than `/uni0037` — as well as the hexadecimal forms, `uniXXXX`
  with the four digits Adobe's convention gives it and `uXXXX` with four to six,
  and the Unicode character names.
- A report for every layer that could not be read, rather than silence. Five
  layers can say it, each naming the page or object it concerns where there is
  one to name: a stream whose filters could not be undone and that holds no
  picture, or that cannot be read at all; a page whose drawing instructions will
  not parse, a form drawn on it that will not parse or that is drawn by a name
  nothing defines, or text drawn before any font was selected, with a font the
  resources in effect do not define, or with a character code that font does not
  map; a font whose `ToUnicode` table, `/Widths` array, or `/FirstChar` cannot be
  read, or whose `/DescendantFonts` entry is not a font dictionary; an `/Info`
  entry that is not a dictionary, or an XMP packet that cannot be read; and a
  `/Names` entry that is not a dictionary, so that attachments could not be
  looked for. This is the point of the tool: a run that found nothing because a
  check could not run must not look like a run that found nothing because the
  document is clean.
- A picture is the deliberate exception, because `/DCTDecode` and the other
  image filters are not filters this undoes and a scanned document is made of
  them — but what makes a stream a picture is what is in it, not the filter it
  names, since `/Filter` is exactly the claim this tool exists to distrust. A
  JPEG or JPEG 2000 stream has to start with that format's signature; the two
  fax formats, which have no signature, have to be an image XObject carrying the
  width and height every image XObject must declare. `/ASCII85Decode` and
  `/ASCIIHexDecode` in front of an image filter are undone here, because they
  only respell bytes as printable characters, and that chain is what Adobe
  Distiller and the producers descended from it write for a JPEG. Anything else
  that names an image filter is reported like any other stream nobody could
  read.
- `--secret` and `--secret-file` to name text that must not appear anywhere.
  The raw-object sweep matches on bytes, so it still works on documents whose
  page text cannot be read, and it names the object each match was found in.
- `--dump-hidden` and `--dump-all` to output recoverable text when you do not
  know what was redacted. Font-subset results are marked as characters rather
  than words, because that layer can only report which characters a removed
  passage used.
- `--output`, which writes a dump to a file instead of the terminal, created —
  or, with `--force`, overwritten — as mode 0600. It refuses to overwrite an
  existing file without `--force`, and refuses outright to write over the PDF
  being inspected.
- `--json` for machine-readable output.
- Exit codes for use in a pre-send hook or CI gate: `0` no evidence of surviving
  content, `1` suspicious, `2` content is recoverable, `3` the check could not
  be completed — the PDF could not be read, the `--output` path was unusable, or
  the write failed — and `4` a usage error, so that a mistyped option cannot be
  mistaken for a failed redaction. A reader that hangs up mid-report — the
  report piped into `head`, say — costs the output, not the verdict: the exit
  code is still the one the findings earned. The same holds for the diagnostics
  on standard error, which are never the verdict and are dropped rather than
  raised when that stream cannot be written to at all.
- Sample PDFs in `tests/samples/`, one per failure mode plus the clean controls
  that prove a check does not fire on an ordinary document, built from fictional
  data by `make-test-samples.py` and committed so test runs are deterministic.

[kac]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html
[Unreleased]: https://github.com/seanthegeek/pdf-redaction-check/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/seanthegeek/pdf-redaction-check/releases/tag/v0.1.0
