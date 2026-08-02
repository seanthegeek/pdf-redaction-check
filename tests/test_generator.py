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
def rebuilt(maketests: ModuleType, tmp_path: Path, monkeypatch) -> Path:
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
    maketests: ModuleType, tmp_path: Path, monkeypatch
) -> None:
    target = tmp_path / "brand" / "new"
    monkeypatch.setattr(maketests, "SAMPLES", target)
    maketests.main()
    assert target.is_dir()


def test_every_sample_uses_only_the_fictional_address(
    prc: ModuleType, fixtures: Path
) -> None:
    """The corpus must never carry real personal data."""
    for name in SAMPLE_NAMES:
        _, extracts = prc.analyze(fixtures / name, [], want_extracts=True)
        for extract in extracts:
            for line in extract.text.splitlines():
                assert "Evergreen" not in line or SECRET in line
