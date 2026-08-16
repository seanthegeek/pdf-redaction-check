# Development

Instructions for improving `pdf-redaction-check` itself. For what the tool does
and how to use it, see the [README](../README.md).

`./build.sh` creates `.venv` if it does not already exist, installs the runtime
and development dependencies into it, and builds the sdist and wheel into
`dist/`. In VSCode it is the default build task, so `Ctrl+Shift+B`
(`Cmd+Shift+B` on macOS) runs it, or pick it from *Terminal → Run Build Task*.

```bash
./build.sh
source .venv/bin/activate

pytest
pytest --cov          # enforces the coverage gate CI applies
ruff check pdf-redaction-check.py make-test-samples.py tests/
ruff format --check pdf-redaction-check.py make-test-samples.py tests/
pyright               # needs the venv active; paths come from pyproject
npx markdownlint-cli2
./pdf-redaction-check.py tests/samples/tagged.pdf --dump-hidden
```

Run the script from the working tree during development. Do not use
`pip install -e .`: the script filename is hyphenated, which is not a legal
Python module name, so the build renames it on the way into the wheel — and that
rename makes an editable install a stale copy rather than a live link.

## Continuous integration

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs on every pull
request and on every push to `main`:

| Job | What it does |
| --- | ------------ |
| Tests | The suite on Python 3.11 through 3.14 |
| Coverage gate | `pytest --cov`, failing below `fail_under` in pyproject |
| Lint | `ruff check`, `ruff format --check`, `pyright`, markdownlint |
| Build | sdist and wheel, `twine check`, then installs and runs the command |

The commands mirror the ones above, so a green local run is a strong predictor
— but CI additionally runs the tests on every supported Python version, and its
build job installs the wheel into a fresh environment to prove the console
script runs. Coverage is measured with branches enabled and currently sits at
100% for both `pdf-redaction-check.py` and `make-test-samples.py`; the gate is
enforced on a single Python version, because which lines are reachable can
differ between interpreters.

The build job installs the wheel and runs the console script against a sample
on purpose: the hyphenated filename is renamed on the way into the wheel, and
if that mapping breaks the package still installs while the command does not
run.

## Releasing

[`.github/workflows/release.yml`](../.github/workflows/release.yml) publishes to
PyPI when a GitHub release is published. To cut one:

1. Move the accumulated `## [Unreleased]` entries in
   [`CHANGELOG.md`](../CHANGELOG.md) under a new heading for the version, dated
   the day you are releasing, and update the link definitions at the foot of the
   file.
2. Bump `version` in `pyproject.toml` to match, and commit both together.
3. Tag with a `v` prefix and publish a GitHub release for that tag. The release
   notes are the changelog entry.

The workflow builds, refuses to continue if the tag disagrees with the packaged
version, installs the wheel and runs the command, publishes, and finally
attaches the sdist and wheel to the release. Running it manually from the
Actions tab publishes to TestPyPI instead, as a dry run.

There is no PyPI API token in this repository. Publishing uses [Trusted
Publishing][tp]: GitHub mints a short-lived credential for each run, scoped to
this repository, this workflow file, and the `pypi` environment. Renaming the
workflow file or the environment breaks releases until the publisher
configuration on PyPI is updated to match.

### GitHub environments

The two publishing jobs run in GitHub environments named `pypi` and `testpypi`.
GitHub creates an environment implicitly the first time a workflow references
one, but create them up front: the Trusted Publishing configuration on PyPI is
keyed to the environment name, and an environment that already exists can carry
protection rules such as a required reviewer before a real PyPI publish.

```bash
gh api --method PUT repos/:owner/:repo/environments/pypi
gh api --method PUT repos/:owner/:repo/environments/testpypi
gh api repos/:owner/:repo/environments --jq '.environments[].name'   # confirm
```

VSCode's GitHub Actions extension checks each `environment:` value against the
list it fetches from the GitHub API, and caches that list for the workspace
session. Two ways it reports `pypi` and `testpypi` as invalid values:

- **The environments were created after the editor started.** The cached list is
  stale. Reload the window — Command Palette → *Developer: Reload Window*.
- **The extension is not signed in to GitHub.** It fetches an empty list and
  then rejects every name, so the giveaway is that *all* environment values are
  flagged rather than one. Sign in from the GitHub Actions view in the sidebar.

Neither case means the workflow file is wrong. GitHub itself accepts a job whose
environment does not exist yet, so the warning is only ever about the editor's
view of the repository.

## Test samples

The sample PDFs in [tests/samples/](../tests/samples/) are committed, one per
failure mode. The tests read them directly, so a test run is deterministic — a
freshly generated PDF carries a new `CreationDate` every time, which would make
results drift.

`make-test-samples.py` rebuilds them. Run it by hand after changing or adding a
fixture, and commit the result:

```bash
python make-test-samples.py   # rewrites tests/samples/
```

[`tests/test_generator.py`](../tests/test_generator.py) is the one test that
runs the generator rather than reading the committed files. It rebuilds the
corpus into a temporary directory and compares what the tool finds in each copy,
because otherwise nothing would notice the generator being edited without the
samples being regenerated — the binaries would quietly stop matching the code
that claims to produce them. That test is why reportlab is a development
dependency and has to be installed to run `pytest`.

Keeping the generator next to the binaries is deliberate: a committed PDF in a
security tool should never be a blob nobody can reproduce or audit. Every
sample uses a fictional address, so they are safe to commit and safe to attach
to a bug report.

[tp]: https://docs.pypi.org/trusted-publishers/
