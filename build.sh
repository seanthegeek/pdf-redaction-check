#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sean Whalen
# SPDX-License-Identifier: MIT
#
# Build the sdist and wheel into dist/, creating a venv first if needed.

set -euo pipefail

cd "$(dirname "$0")"

VENV=".venv"
PYTHON="${PYTHON:-python3}"

if [ ! -x "$VENV/bin/python" ]; then
    echo "==> Creating virtual environment in $VENV"
    "$PYTHON" -m venv "$VENV"
else
    echo "==> Reusing existing virtual environment in $VENV"
fi

VPY="$VENV/bin/python"

echo "==> Installing build dependencies"
"$VPY" -m pip install --upgrade --quiet pip build

# Installs the project's own runtime and dev dependencies (declared in
# pyproject.toml) so the venv can also run, lint, and test the tool.
echo "==> Installing project dependencies"
"$VPY" -m pip install --quiet ".[dev]"

echo "==> Clearing previous build artifacts"
rm -rf dist build

echo "==> Building sdist and wheel"
"$VPY" -m build --sdist --wheel --outdir dist .

echo
echo "==> Built:"
ls -1 dist
