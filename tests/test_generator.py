# SPDX-FileCopyrightText: 2026 Sean Whalen
# SPDX-License-Identifier: MIT
"""Tests that the committed samples still match the generator.

The suite reads `tests/samples` rather than building PDFs, so nothing
else would notice if `make-test-samples.py` were edited without regenerating
and committing the result -- the binaries would quietly stop matching
the code that claims to produce them. This rebuilds the corpus into a
temporary directory and compares what the tool finds in each copy.

Bytes are not compared: a freshly built PDF carries a new CreationDate,
so two runs never produce identical files. Findings are the thing that
has to agree.
"""

from __future__ import annotations

from pathlib import Path
from types import ModuleType

import pytest
from conftest import SAMPLE_NAMES

SECRET = "742 Evergreen Terrace"


@pytest.fixture
def rebuilt(
    maketests: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Regenerate every sample into a temporary directory."""
    monkeypatch.setattr(maketests, "SAMPLES", tmp_path)
    maketests.main()
    return tmp_path


def summarize(prc: ModuleType, path: Path) -> set[tuple[str, str]]:
    """Reduce a document to the set of (check, location) it triggers.

    Detail text is left out because it embeds byte counts and dates that
    legitimately differ between two builds of the same fixture.
    """
    report, _ = prc.analyze(path, [SECRET])
    return {
        (f.check, f.location)
        for f in report.findings
        if not f.detail.startswith("DocInfo")
    }


@pytest.mark.parametrize("name", SAMPLE_NAMES)
def test_committed_sample_matches_a_fresh_build(
    prc: ModuleType, fixtures: Path, rebuilt: Path, name: str
) -> None:
    assert summarize(prc, fixtures / name) == summarize(prc, rebuilt / name)


def test_generator_writes_every_expected_sample(rebuilt: Path) -> None:
    assert sorted(p.name for p in rebuilt.glob("*.pdf")) == sorted(SAMPLE_NAMES)


def test_generator_creates_its_output_directory(
    maketests: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "brand" / "new"
    monkeypatch.setattr(maketests, "SAMPLES", target)
    maketests.main()
    assert target.is_dir()


def test_page_text_matches_what_the_page_actually_draws(
    prc: ModuleType, maketests: ModuleType, fixtures: Path
) -> None:
    """The stale CMap is built from page_text, so it has to be right.

    If page_text and letter_pdf ever disagree, the orphaned-font sample
    would encode a CMap for text the page never contained, and the check
    it exists to exercise would be testing fiction.
    """
    _, extracts = prc.analyze(fixtures / "clean.pdf", [], want_extracts=True)
    drawn = next(e.text for e in extracts if e.layer == prc.CONTENT_STREAM)
    expected = maketests.page_text(
        maketests.CAPTIONS["clean.pdf"], include_secret=False
    )
    assert drawn == expected
    assert maketests.SECRET not in expected


def test_page_text_includes_the_extra_body_line(
    prc: ModuleType, maketests: ModuleType, fixtures: Path
) -> None:
    """The same invariant, for the page that carries a fourth line."""
    _, extracts = prc.analyze(fixtures / "smart_quotes.pdf", [], want_extracts=True)
    drawn = next(e.text for e in extracts if e.layer == prc.CONTENT_STREAM)
    expected = maketests.page_text(
        maketests.CAPTIONS["smart_quotes.pdf"],
        include_secret=False,
        extra=maketests.SMART_QUOTES,
    )
    assert drawn == expected


def test_page_text_adds_the_secret_when_asked(maketests: ModuleType) -> None:
    caption = maketests.CAPTIONS["orphan_font.pdf"]
    assert maketests.SECRET in maketests.page_text(caption, include_secret=True)


def test_every_caption_names_its_own_file(maketests: ModuleType) -> None:
    for name, caption in maketests.CAPTIONS.items():
        assert name in caption, f"{name} caption does not name the file"
        assert maketests.SECRET not in caption


def test_every_sample_uses_only_the_fictional_address(
    prc: ModuleType, fixtures: Path
) -> None:
    """The corpus must never carry real personal data."""
    for name in SAMPLE_NAMES:
        _, extracts = prc.analyze(fixtures / name, [], want_extracts=True)
        for extract in extracts:
            for line in extract.text.splitlines():
                assert "Evergreen" not in line or SECRET in line
