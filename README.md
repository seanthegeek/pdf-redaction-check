# pdf-redaction-check

[![CI](https://github.com/seanthegeek/pdf-redaction-check/actions/workflows/ci.yml/badge.svg)](https://github.com/seanthegeek/pdf-redaction-check/actions/workflows/ci.yml)

Verify that a PDF redaction actually removed the content, instead of just
covering it up.

Redaction fails quietly. A black rectangle drawn over text looks identical to
a real redaction on screen, but the text underneath is still selectable,
copyable, and extractable. Even tools that remove text properly can leave
recoverable traces in places nobody thinks to check. `pdf-redaction-check`
looks in seven of those places and reports what it finds.

## Why this exists

Redacting a PDF is not like erasing a word from paper. A PDF is a bundle of
loosely connected structures, and the same sentence can exist in several of
them at once: the drawing instructions for the page, a second copy kept for
screen readers, a form field, a comment, the document properties, an attached
file. Whether a redaction tool touches all of the copies of the items to redact
depends on the tool.

This tool checks for incomplete redactions.

There are three distinct ways a redaction fails, and they need to be looked for
in different places.

**The text is still on the page.** The rectangle is just a drawn shape. Putting
one over a name changes nothing underneath it, and the text stays selectable
and copyable — this is the failure behind most of the redaction news stories. A
variant is subtler: some tools let you mark text for redaction and then save
without applying the marks, so the document ships with the passages both intact
and helpfully labeled. Beyond the page's own drawing instructions, text can also
sit in compressed object data that neither a text extractor nor a search of the
raw file bytes will find — it surfaces only after each object is decompressed.

**The text left the page, but a copy survived elsewhere.** Tagged PDFs — the
ones built for screen readers — can carry parallel copies of passages in a
structure tree, which ordinary text extraction never reads; a document can
pass a naive grep while the tag tree still holds the string verbatim.
Annotations and form field values are stored separately from page content and
are routinely missed. Document properties and XMP metadata hold titles,
authors, and original filenames that most redaction tools do not clean. And an
embedded attachment is a whole second file, carried along untouched — redacting
its host does nothing to it.

**The text is gone, but its shape remains.** Even a correct removal can leave a
trace in the fonts. This is the failure mode the Australian Signals
Directorate documented in 2021, when it
[examined Adobe Acrobat Pro DC's redaction functionality][asd]. To keep files
small, a PDF embeds only the characters a document actually uses, along with a
table mapping each one back to the letter it represents — built in the order
each character first appeared in the text. Redacting after the fact deletes the
visible glyphs but does not rebuild that table, so mappings survive for
characters that no longer exist anywhere in the document. The report found this
in PDFs from LibreOffice Writer and CutePDF (Ghostscript), and found that
Acrobat's sanitize function did not remove the remnants either.

Those leftover mappings are a fingerprint of the removed text. If the redacted
passage used a letter found nowhere else in the document, and that letter is
still in the font, something leaked. It is the weakest of the signals here — it
recovers characters rather than words, and a document can have unused glyphs
for innocent reasons — which is why the tool reports it as consistent with
removed text rather than proof of it.

Most redaction verification advice stops at "run `pdftotext` and grep for it."
That inspects one of the seven layers below.

## What it checks

| Layer | What survives there |
| ----- | ------------------- |
| Content stream | Text the page draws, under a rectangle or inside a form |
| Raw objects | Stream and string data outside the text layer, decoded or raw |
| Structure tree | Tagged-PDF `/ActualText`, `/Alt`, `/E`, `/T`, `/TU` |
| Annotations | Comment text, form field values, unapplied `/Redact` marks |
| Metadata | DocInfo and XMP, which redaction tools generally do not clean |
| Attachments | Embedded files carried along unredacted |
| Font subsets | Orphaned `ToUnicode`, `/Differences`, `/CharSet`, `/Widths` |

## Installation

Requires Python 3.11+ and [pikepdf][pikepdf].

```bash
pipx install pdf-redaction-check   # or: pip install .
```

That installs a `pdf-redaction-check` command. To run from a checkout without
installing, `pip install pikepdf` and invoke `./pdf-redaction-check.py`
directly.

## Usage

```bash
# Check a document for a specific string
pdf-redaction-check letter_redacted.pdf --secret "742 Evergreen Terrace"

# Multiple secrets
pdf-redaction-check report.pdf -s "Jane Doe" -s "555-0100"

# Secrets from a file, one per line
pdf-redaction-check report.pdf --secret-file secrets.txt

# Structural checks only, no known secret
pdf-redaction-check report.pdf

# Machine-readable output
pdf-redaction-check report.pdf -s "..." --json
```

### Recovering hidden text

When you do not know what was redacted — auditing someone else's document,
or checking your own before sending it — the tool can output the recoverable
text instead of hunting for a string you have to supply.

```bash
# Text that survives somewhere but is NOT on the visible page
pdf-redaction-check report.pdf --dump-hidden

# Everything recoverable, with the off-page parts marked
pdf-redaction-check report.pdf --dump-all

# Write it to a file instead of the terminal (created, or overwritten
# with --force, as mode 0600)
pdf-redaction-check report.pdf --dump-hidden -o recovered.txt
```

> **The output is the sensitive content.** Piping a dump into a CI log, a
> chat message, or shell scrollback leaks exactly what you were checking was
> gone. `-o` refuses to overwrite an existing file without `--force`, and
> refuses outright to write over the PDF being inspected.

Two things to expect from the output:

- **Document metadata always appears in `--dump-hidden`.** DocInfo values are
  genuinely not on the page, so they are hidden text by definition. This is not
  a false positive — author names and original filenames are a real leak
  vector — but it does mean a clean document still produces a few lines.
- **Font-subset results are characters, not words.** That layer can only report
  *which* characters a removed passage used, in CMap order. It is marked as
  such in the output and must not be read as recovered wording.

This does not reconstruct an unredacted PDF. Where a redaction genuinely
deleted the page text, it is gone from that layer and cannot be put back; what
is recoverable is whatever survives in the other six.

### Output

The default report is one line per finding — severity, which check produced
it, where it was found, and what it observed — followed by a verdict. Every
finding says what it saw, so you can disagree with the inference.

```console
$ pdf-redaction-check letter.pdf --secret "742 Evergreen Terrace"
=== redaction check: letter.pdf ===
CRITICAL content-stream [visible page text]: secret text still present in the page text layer: '742 Evergreen Terrace'
CRITICAL raw-objects [object 8 0]: secret found in raw object data: '742 Evergreen Terrace'
INFO     structure-tree: document is not tagged; no structure tree to inspect
INFO     metadata: DocInfo /Author = 'anonymous'
INFO     metadata: DocInfo /Producer = 'ReportLab PDF Library - (opensource)'

RESULT: FAILED -- redacted content is still recoverable.
```

The examples in this section are shown with most of their `metadata` lines cut,
for length. A real run prints one per DocInfo entry the producer set — seven
even for the samples in this repository, and more from a word processor.

`INFO` lines are not problems. They record what each layer inspected. Anything
that could not be read at all is reported as a `WARNING`, naming the page or
object it concerns where there is one to name, which is what keeps a check that
found nothing distinguishable from a check that could not run. Seven check
names can carry one — not the same seven as the layers in the table above.
Nothing is ever reported this way under `annotations`, and the sweep for text
outside the text layer reports under two names: `raw-objects` for stream data,
`raw-strings` for the string objects no other layer claims. The seven are:

- `raw-objects`: a stream whose declared filters could not be undone and that
  holds no picture, or that cannot be read at all;
- `content-stream`: a page whose drawing instructions will not parse all the
  way through, or a form drawn on the page whose own will not — either of those
  two costs the text drawn from the point it stopped at and not the text drawn
  before it; a page whose `/Contents` is an array of content streams that will
  not read as one, which is how a reader reads them, or an entry of such an
  array that will not read on its own either — see "Limitations"; a page whose
  `/Contents` is neither a content stream nor an array of them, or an entry of
  that array that is not a content stream, either of which a parser hands back
  no instructions for rather than refusing; what the PDF reader itself
  reported, which is either a fault in the structure of the file, such as a
  cross-reference table it had to rebuild, or trouble reading the data the
  pages draw from, which is where a stream whose compressed data stops early
  shows up — see "Limitations"; a form drawn by a name nothing defines; forms
  drawn inside one another more than 64 levels deep, which is where every walk
  here stops — see "Limitations"; text drawn before any font was selected, with
  a font the resources in effect do not define, with a name they define as
  something other than a font dictionary, or with a character code that font
  does not map; a `Q` operator with no `q` left
  to restore a graphics state from, or one asking for a state saved more than
  64 `q` operators deep, which is as many as are kept, after either of which
  the text is read on the assumption that a reader would leave the font where
  it stands; or more operands written in a row than the 64 this holds waiting
  for an operator — see "Limitations" — which is more operands than any
  instruction a reader draws with, so the ones written first were passed over
  and the ones written last, which are the ones an operator would use, were
  kept;
- `font-charset`: a font whose character map, `/Widths` array, or `/FirstChar`
  cannot be read, a `/DescendantFonts` entry that is not an array or that holds
  something other than a font dictionary, a `/Font` resource that is not a font
  dictionary at all, a `/ToUnicode` entry
  that is not the stream a character map lives in, forms nested past that same
  limit, so that the fonts inside them were never reached, or a font's chain of
  descendant fonts nested past it, so that what the font at the bottom declares
  was never read;
- `structure-tree`: a tagged-PDF structure tree nested past that limit, so the
  tags below it were not inspected;
- `raw-strings`: an object graph nested past that limit, so the string objects
  below it were not swept — reported when a dump mode or a `--secret` asked for
  that sweep, which is when it runs;
- `metadata`: an `/Info` entry that is not a dictionary, or an XMP metadata
  packet that cannot be read, so that metadata was not inspected;
- `attachments`: a `/Names` entry that is not a dictionary, so embedded
  attachments could not be looked for, or a tree of embedded file names nested
  past that limit, so the attachments below it were not listed — that one, like
  the string sweep, is reported when a dump mode or a `--secret` runs it.

A document with nothing to report ends on:

```text
RESULT: no evidence of surviving content.
```

The font-subset check is the one that reports characters rather than text, and
it states its own uncertainty:

```text
CRITICAL font-charset [page 1 /F1]: 6 character(s) mapped by the font subset but absent from visible text, in CMap order: '742Evg' -- consistent with text removed from the content stream but not the font subset
```

That inference needs the page text it compared against to be the whole of the
page text. When any of it went unread — for any of the reasons listed under
`content-stream` above that cost text — the same check reports what it observed
instead, says what fell short, and drops to a `WARNING`, because a character
missing from a comparison this could not finish may be one the document is
still showing. What fell short is put the way every other count here is: how
many pages went unread and which one to start looking at, or that the PDF
reader had trouble reading the data the pages draw from, which is about the
file rather than any one page.

```text
WARNING  font-charset [page 1 /F1]: 3 character(s) mapped by the font subset but absent from the page text this could read, in CMap order: 'ÁÂÃ' -- the text of page 1 could not be read in full, so these may be characters the document still shows that this run never saw, rather than characters removed from the content stream
```

Every character is still listed and the finding is still made; only the
inference changes. It reaches every font in the document rather than only the
fonts of the page that went unread, because the text a font is compared against
is every page's joined together.

What weakens it is text going unread, not a `content-stream` warning being
printed. Two of those warnings are about a document that gave up all of its
text. A `Q` operator with no `q` before it is malformed, and ISO 32000 section
8.4.4 leaves a reader nothing to restore from, so a reader carries on and so
does this — the warning says the text after it was read on that assumption, and
every instruction on the page was still taken in. A cross-reference table the
PDF reader had to rebuild is a fault in the structure of the file, and the
pages read from what it recovered still handed over every instruction they
hold. Were either of them enough, two bytes no reader acts on — or one digit of
a byte offset — would talk this check down from `CRITICAL`.

`--json` emits the same findings as an object, for a CI gate that needs to do
more than branch on the exit code:

```console
$ pdf-redaction-check report.pdf --json
{
  "file": "report.pdf",
  "worst_severity": "CRITICAL",
  "findings": [
    {
      "severity": "INFO",
      "check": "structure-tree",
      "detail": "document is not tagged; no structure tree to inspect",
      "location": ""
    },
    {
      "severity": "INFO",
      "check": "metadata",
      "detail": "DocInfo /Producer = 'ReportLab PDF Library - (opensource)'",
      "location": ""
    },
    {
      "severity": "CRITICAL",
      "check": "font-charset",
      "detail": "6 character(s) mapped by the font subset but absent from visible text, in CMap order: '742Evg' -- consistent with text removed from the content stream but not the font subset",
      "location": "page 1 /F1"
    }
  ]
}
```

`worst_severity` is the highest severity in `findings`, and is what the exit
code is derived from. Adding `--dump-hidden` or `--dump-all` keeps both of
those and adds a `dump` object, whose `extracts` list carries the recovered
text with the layer and location it came from:

```console
$ pdf-redaction-check tagged.pdf --dump-hidden --json
{
  "file": "tagged.pdf",
  "worst_severity": "INFO",
  "findings": [
    {
      "severity": "INFO",
      "check": "structure-tree",
      "detail": "tagged PDF: 21 characters of structure text inspected",
      "location": ""
    },
    {
      "severity": "INFO",
      "check": "metadata",
      "detail": "DocInfo /Producer = 'ReportLab PDF Library - (opensource)'",
      "location": ""
    }
  ],
  "dump": {
    "mode": "hidden",
    "page_text_read_in_full": true,
    "extracts": [
      {
        "layer": "structure-tree",
        "location": "/StructTreeRoot",
        "hidden": true,
        "is_text": true,
        "text": "742 Evergreen Terrace"
      },
      {
        "layer": "metadata",
        "location": "DocInfo /Producer",
        "hidden": true,
        "is_text": true,
        "text": "ReportLab PDF Library - (opensource)"
      }
    ]
  }
}
```

Nothing in that run is a finding — `worst_severity` is `INFO`, and the exit
code is 0 — yet the dump recovers an address from the tag tree. Told what to
look for, `--secret "742 Evergreen Terrace"` reports the same string as a
`CRITICAL` finding. Text that only a dump can show you is why the dump modes
exist: without a secret to match against, the tool cannot tell a leaked
passage from a legitimate second copy of the page.

`is_text` is false for font-subset extracts, which are characters rather than
words — see the warning above.

`hidden` says the text is absent from the page text this run could read, which
is the same comparison the report makes and no stronger. `page_text_read_in_full`
is what says how much that was: `false` means some of the text the pages draw
went unread, so text marked hidden may be text the document is still showing. A
gate that branches on `hidden` should read that field too, in either dump mode
— `--dump-all` marks each block hidden or not as well, and carries the same
field. The `--dump-hidden` text output says it in words under its heading,
where being hidden is what put a block in the output; the text output of
`--dump-all` marks no block hidden, so it has nothing there to qualify. Every
recovered block is listed either way — text that survived somewhere is evidence
whatever the baseline was.

### Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | No evidence of surviving content |
| 1 | Suspicious; review warnings |
| 2 | Failed; redacted content is recoverable |
| 3 | The check could not be completed |
| 4 | Usage error; the arguments were wrong |

Suitable for a pre-send hook or CI gate.

`2` says the evidence shows content that was meant to be removed is still
recoverable, so a check whose evidence rests on something this could not read
does not reach it. The font-subset check is the one that turns on a comparison
against the page text: when a page could not be read in full, its findings are
`WARNING`s, and such a document ends on `1` unless something else convicts it.
That is not a change to what a code means — it is which code the evidence
supports.

`3` covers the three ways a run can end without a verdict: the PDF could not be
read, the `--output` path was unusable, or writing the output failed. `4` is
reserved for a bad invocation — an unknown option, a missing file argument, an
unreadable `--secret-file`, or a `--secret` with nothing in it — so that a typo
can never be mistaken for a failed redaction.

A blank `--secret` is refused rather than searched for, because text with
nothing in it is in every document ever written: matching it would report every
document as a failed redaction, and dropping it would check none of them while
looking like it had. The shape it arrives in is a CI gate running
`--secret "$NAME"` with the variable unset. Blank lines in a `--secret-file`
are different, and are skipped: that file holds one secret per line, so a line
with nothing on it is formatting rather than a request.

## Limitations

A clean result means the seven checked layers are clean. It is not proof the
file is clean.

- **A run with no secret judges only some of the layers.** Unapplied `/Redact`
  marks, embedded attachments, font-subset leftovers, and any layer that could
  not be read are findings on their own. Structure-tree text and document
  properties are reported as `INFO`; annotation text, form field values, XMP
  text, and leftover string objects are not reported at all. All of it is
  recovered by `--dump-hidden` and matched by `--secret`, but a default run
  cannot tell a leaked passage from a legitimate second copy of the page, and
  does not try.
- **Base-14 fonts.** Non-embedded standard fonts carry no subset metadata, so
  there is nothing to go stale. Absence of a font finding means "not
  applicable," not "verified."
- **Fonts whose encoding cannot be read.** Page text is read by mapping each
  character code through the font in effect — its `ToUnicode` table, then its
  `/Encoding` and any `/Differences`, then the base encoding. A font that
  supplies none of those, or a composite font whose character codes are not all
  the same number of bytes wide, leaves codes this cannot turn into characters.
  Those codes are dropped from the page text and reported as a warning rather
  than guessed at, so the visible-text comparison is incomplete for exactly
  those documents — and the font-subset finding says so and drops to a
  `WARNING`, rather than reporting characters this never saw as characters the
  document no longer draws. A `/Differences` array can also name a glyph this
  does not know — the names it resolves are the standard ones of ISO 32000
  Annex D, the four-digit `uniXXXX` and the four- to six-digit `uXXXX`
  hexadecimal forms, and the Unicode character names, so a producer that
  invents a name, or takes one from a symbol font, is naming a glyph this
  cannot identify. That code then keeps whatever the font's base encoding says
  it draws, which may be a character the page never showed, and nothing is
  reported. Prefer `--secret` on such files: the raw-object sweep works on
  bytes and does not depend on the font at all.
- **A file the PDF reader could only partly read.** qpdf, which reads the file
  underneath this, does not refuse one it can only partly recover. The common
  shape is a stream whose compressed data was cut short — a file truncated in
  transit — which it decompresses as far as the data goes and hands over as
  though that were the whole stream, leaving a warning on the document rather
  than raising. The parse of the page then succeeds, so nothing about the page
  says it stopped short of the end. What it said is collected and reported
  under `content-stream`, and because that is about the file rather than about
  any one page it puts the whole page text in question: every font-subset
  finding in such a run is the weaker of the two. What the lost bytes drew
  cannot be recovered here, and this tool does not attempt to repair the file.
  What the reader says about the *structure* of a file — a cross-reference
  table it had to rebuild by searching the file for its objects — is reported
  the same way and stops there, because a document put back together that way
  still hands over every instruction its pages hold. The cost of one of those
  is any object the search did not find: it is not in the document this
  inspected, and nothing here can say what was in it. What the reader says is
  collected up to the end of the page-text pass, so trouble it runs into later
  — decompressing an attachment for the raw sweep, say — is not reported this
  way; that stream is reported by the layer that could not read it.
- **An array of content streams that will not read as one.** A page's drawing
  instructions can be an array of content streams, and ISO 32000 section 7.8.2
  makes them one stream, divided only at the boundaries between tokens — so a
  reader joins them before parsing, and so does this. One entry that will not
  decode therefore costs the text of every other, because the parse of the
  joined stream hands over no instructions at all. When that happens the
  entries are read one at a time instead, carrying the font in effect and the
  saved graphics states across every join that could be read across, so the
  readable entries' text is recovered and each entry that would not read is
  named by its object. Two things cannot be recovered that way, and neither is
  guessed at. An instruction written across the join beside the entry that
  failed is split between the two, so its operands or its operator went with
  that entry. And an entry that would not read may have selected another font,
  or saved or restored the graphics state, so what it would have left behind is
  not known and is not carried past it: from there on the text reads as text
  drawn with no font selected, which shows up among the counts of text this
  could not turn into characters. ISO 32000 section 9.3.1 gives the font no
  initial value and wants a `Tf` before any text is shown, so text a reader
  would draw after that point brings its own font and is still recovered.
  Neither case draws the wrong characters — an invented character can land on a
  font mapping that really was orphaned and hide a leak, which is worse than
  losing the text. A page read this way is not a page read in full, so its
  fonts get the weaker of the two font-subset findings.
- **Non-ASCII text in the catch-all string sweep.** Strings that no dedicated
  layer claims are filtered by how much plain ASCII they contain, to keep
  binary values out of the output. Text in scripts that use little ASCII may be
  filtered with them. The dedicated layers — metadata, annotations, structure
  tree — are never filtered this way.
- **Not yet covered.** XFA form data, optional content groups (layers), and
  incremental update history. That last one matters most: a PDF saved
  incrementally retains prior revisions, including pre-redaction content.
- **Rasterized pages.** If a page was flattened to an image, no text-layer
  check applies. Text may still be recoverable via OCR. The image's own stream
  cannot be decoded here either — `/DCTDecode` and the other image filters are
  not filters this undoes — and a stream that holds a picture is not reported
  as a layer it failed to read, because otherwise every scanned document would
  come back suspicious; the picture's bytes are still searched for a `--secret`.
  What makes a stream a picture is what is in it, not the filter it names. A
  JPEG or JPEG 2000 stream has to start with that format's signature. The two
  fax formats start with no fixed bytes, so there is nothing to check them
  against: they have to be an image XObject — a picture stored as an object of
  its own — and carry the width and height every image XObject must declare.
  That is weaker, and a file that writes a whole image dictionary around bytes
  that are not an image defeats it; what it catches is the ordinary case, a
  stream that names a filter it does not use. A stream that corroborates its
  filter neither way — text hidden behind the name of a picture — is reported
  like any other stream nobody could read. `/ASCII85Decode` and
  `/ASCIIHexDecode` in front of an image filter are undone here rather than
  reported, because they only respell bytes as printable characters, and that
  chain is what Adobe Distiller and the producers descended from it write for a
  JPEG.
- **Text a page never draws.** The content-stream layer is what the page draws,
  which includes following the `Do` operator into a Form XObject — a reusable
  content stream that can draw text of its own. A form that nothing draws is
  not page text: its bytes are still swept for a `--secret` and its fonts are
  still checked for leftovers, but what it would have drawn is not recovered as
  page text and does not appear in `--dump-hidden`. Fonts are reached the same
  way, from the pages outwards, so a font named only by an annotation's
  appearance stream or by the form field defaults in `/AcroForm` is not one
  whose leftovers this inspects. A form drawn more than once is read once per
  distinct drawing, told apart by the form, the font in effect — both the
  resource name it was selected by and the font that name resolved to — and the
  content stream that drew it. Two drawings can still differ further out in the
  chain of resources than those three reach, which takes a document built to do
  it: a form drawn from two places draws a second form of its own, and the
  inner drawing looks the same both times — one form, one font in effect, one
  stream drawing it — while the outer resources that decide what it draws
  differ. That one is read once, and the second reading's text is missing from
  the page text.
- **Structures nested more than 64 levels deep.** Six walks here stop at that
  depth — the tag tree, the object graph, forms drawn inside forms, the
  resources reached through them, a font's chain of descendant fonts, and the
  tree the embedded file names hang off — because a hostile file can nest a
  structure forever and a walk that followed it would never finish. What is
  below the limit is not inspected, and every walk that stops says where it
  gave up, so this shows up as a warning rather than as a clean result. Two of
  the six only run when a dump mode or a `--secret` asks for them — the object
  graph and the tree of file names — so a default run says nothing about those
  two, as the list of warnings above notes. Ordinary documents are nowhere near
  the limit.
- **Drawing instructions built to cost more than the file does.** Instructions
  compress extremely well, so a page of a few kilobytes can hold millions of
  them, and reading a page has to cost something closer to what the page draws
  than to what it asks for. The instructions are read one at a time rather than
  all at once, so how many of them a page holds no longer decides what reading
  it costs. Two things are bounded on top of that, and each says so when it is
  reached: at most 64 operands are held waiting for an operator — the ones
  written last, because those are the ones an operator uses — and at most 64
  saved graphics states are kept for `q` and `Q` to restore the font from. Both
  limits are far above anything a producer writes, the longest run of operands
  on an ordinary page being the dictionary of an inline image, so reaching
  either is a fact about the file rather than about the document. What none of
  that bounds is the size of one operand: an array of a million empty strings
  is a single operand, built whole by the parser before any of this sees it, so
  a page whose instructions are few and enormous can still exhaust the memory
  available and end the run with a traceback instead of a report.
- **Heuristic, not proof.** The font-charset check infers intent from
  structure. Documents with legitimate unused glyphs may produce findings that
  are not leaks.

## The reliable approach

None of this replaces the actual fix. If you control the source document, edit
the original and export a fresh PDF. There is no redaction step, so there is no
class of remnant to verify. Use this tool when you only have the PDF, or to
audit a redaction someone else performed.

## Development

[docs/development.md](docs/development.md) covers building and testing, what CI
enforces, how a release is cut, and how the test samples are regenerated.
Released versions are listed in [CHANGELOG.md](CHANGELOG.md).

## AI assistance disclaimer

This tool was written with substantial assistance from a large language model
(Claude). The design, the checks it performs, and the reasoning behind them
were directed by a human, and the output was reviewed, tested against
synthetic fixtures for each failure mode, and linted before publication.

Treat it accordingly. It is a heuristic aid for a security-sensitive task, not
an audited security product. Read the source before trusting it with anything
that matters, and do not treat a clean result as a guarantee. If the
consequences of a failed redaction are serious, verify by other means as well.

## License

MIT. See [LICENSE](LICENSE).

[asd]: https://www.cyber.gov.au/sites/default/files/2023-03/PROTECT%20-%20An%20Examination%20of%20the%20Redaction%20Functionality%20of%20Adobe%20Acrobat%20Pro%20DC%202017%20(October%202021).pdf
[pikepdf]: https://github.com/pikepdf/pikepdf
