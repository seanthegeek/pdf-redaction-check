# SPDX-FileCopyrightText: 2026 Sean Whalen
# SPDX-License-Identifier: MIT
"""Shared test fixtures.

The scripts have hyphenated filenames, which are not legal Python module
names, so they are loaded by path rather than imported. Registering each
one in `sys.modules` is required: `dataclasses` looks the module up
there while building `Extract` and `Finding`.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Every sample the suite expects to find checked in.
SAMPLE_NAMES = (
    "annotated.pdf",
    "armored_image.pdf",
    "attachments.pdf",
    "broken_contents.pdf",
    "broken_fonts.pdf",
    "clean.pdf",
    "cleartext_stream.pdf",
    "costly_stream.pdf",
    "deep_nesting.pdf",
    "differences.pdf",
    "fake_redacted.pdf",
    "font_variants.pdf",
    "form_xobject.pdf",
    "identity_h.pdf",
    "image_stream.pdf",
    "lying_image.pdf",
    "orphan_font.pdf",
    "outline.pdf",
    "rebound_font.pdf",
    "saved_state.pdf",
    "smart_quotes.pdf",
    "tagged.pdf",
    "truncated_stream.pdf",
    "unapplied.pdf",
    "xmp.pdf",
)


def load_script(name: str, filename: str) -> ModuleType:
    """Import a hyphenated script under the given module name."""
    path = ROOT / filename
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def prc() -> ModuleType:
    """The tool under test."""
    return load_script("prc", "pdf-redaction-check.py")


@pytest.fixture(scope="session")
def maketests() -> ModuleType:
    """The sample generator, used only to check the corpus is current.

    Running the generator from a test is the one sanctioned exception to
    "run it by hand": `tests/test_generator.py` rebuilds the corpus into
    a temporary directory to prove the committed binaries still match
    the code that claims to produce them. It is also why reportlab has
    to be installed to run the suite.
    """
    return load_script("maketests", "make-test-samples.py")


@pytest.fixture(scope="session")
def fixtures() -> Path:
    """The directory holding the committed sample PDFs.

    The samples are checked in rather than generated per run, so the
    tests are deterministic -- a freshly built PDF carries a new
    CreationDate every time. Every test but the drift check in
    `tests/test_generator.py` reads these files rather than building
    one. Rebuild them with `python make-test-samples.py` and commit the
    result.
    """
    samples = ROOT / "tests" / "samples"
    missing = [name for name in SAMPLE_NAMES if not (samples / name).is_file()]
    if missing:
        raise RuntimeError(
            f"missing sample PDFs in {samples}: {', '.join(missing)} "
            "-- run `python make-test-samples.py`"
        )
    return samples
