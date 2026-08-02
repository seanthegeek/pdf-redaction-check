# AGENTS.md

## Project overview

`pdf-redaction-check` is a single-module Python command-line tool that verifies
whether a PDF redaction actually removed content, rather than merely covering it
up on screen. It inspects seven layers where text can survive a bad redaction:
the content stream, raw decompressed object data, the tagged-PDF structure tree,
annotations and form fields, DocInfo and XMP metadata, embedded file
attachments, and font subsets (orphaned `ToUnicode`, `/Differences`, `/CharSet`,
and `/Widths` entries — the failure mode documented by the Australian Signals
Directorate).

The tool is read-only and diagnostic. It never edits, repairs, or re-saves a
document; it reports evidence and exits with a status code suitable for a
pre-send hook or CI gate.

It is a heuristic aid for a security-sensitive task, not an audited security
product. A clean result means the seven checked layers are clean — it is not
proof the file is clean, and no documentation, output string, or commit message
may imply otherwise.

### Layout

- `pdf-redaction-check.py` — the entire tool: checks, report model, and CLI
- `tests/samples/` — the committed sample PDFs, one per failure mode
- `make-test-samples.py` — rebuilds `tests/samples/`; run by hand, never by the
  tests
- `pyproject.toml` — hatchling build, pytest and coverage config; installs the
  `pdf-redaction-check` command
- `build.sh` — creates `.venv` if absent, then builds the sdist and wheel into
  the gitignored `dist/`
- `.github/workflows/ci.yml` — tests, coverage gate, lint, and build
- `.github/workflows/release.yml` — publishes to PyPI when a GitHub release is
  published; manual runs go to TestPyPI
- `.vscode/tasks.json` — makes `build.sh` the default VSCode build task
- `README.md` — user-facing overview, usage, and limitations
- `docs/development.md` — building, testing, CI, releasing, and test samples

**Script filenames in this repo are hyphenated, by preference.** A hyphen is not
legal in a Python module name, so `pyproject.toml` renames the file on the way
into the wheel:

```toml
[tool.hatch.build.targets.wheel]
force-include = { "pdf-redaction-check.py" = "pdf_redaction_check.py" }
```

Three consequences worth knowing before you touch packaging:

- The entry point is `pdf_redaction_check:run` — the *installed* name, with
  underscores. Renaming the source file means updating the `force-include`
  mapping, not the entry point.
- The source file cannot be imported from the repo root. `import
  pdf_redaction_check` only works against an installed copy.
- **Do not use `pip install -e .` here.** The rename makes hatchling fall back
  to copying the file into `site-packages` instead of linking it, so an
  "editable" install silently goes stale the moment you edit the source. Run
  `./pdf-redaction-check.py` directly during development, or re-run
  `pip install .` after each change when you specifically need to exercise the
  installed console script.

### Common commands

```bash
./build.sh                          # venv if needed, deps, sdist + wheel
source .venv/bin/activate           # pyright resolves imports from the
                                    # active interpreter
./pdf-redaction-check.py FILE.pdf   # run from the working tree
pytest
pytest --cov                        # same coverage gate CI applies
ruff check pdf-redaction-check.py make-test-samples.py tests/
ruff format --check pdf-redaction-check.py make-test-samples.py tests/
pyright                             # paths come from [tool.pyright]
npx markdownlint-cli2
python make-test-samples.py         # rebuild tests/samples/, then commit it
```

## Conventions

These rules apply to anyone — human or agent — making changes to this repo. They
are intentionally checked in (rather than living in any one agent's private
scratch memory) so that every collaborator picks them up the same way.

- **Wait for explicit commit AND push permission on the default branch — these
  are separate grants.** Finish the implementation, run the tests, summarize the
  diff, then **stop and ask**. The author decides when a change is ready to
  land; auto-committing makes review noisier and harder to reverse. "Commit
  this" mid-session counts as permission for that one commit, not a standing
  grant — and crucially, permission to commit is NOT permission to push. Pushing
  publishes the change to the remote where collaborators / CI / production
  deploys can pick it up, and is much harder to walk back than a local commit.
  Wait for an explicit "push it" before `git push`. If the prior commit was
  itself unauthorized, do NOT push it to "tidy up" — surface the situation and
  let the author decide whether to keep, amend, or reset.
- **Self-test before every `git commit`:** has the author typed "commit" (or an
  unambiguous equivalent — "ok to commit", "commit this", "commit and push") in
  a present-tense imperative since your last commit? If no, **ask**. Conditional
  phrasings like "if everything works we can push" or "we could commit this" or
  "if it looks good ..." are NOT authorizations — they are plans you must
  confirm before acting on. Treat the literal text of the user's last message as
  the source of truth, not your own interpretation of where the conversation is
  going.
  - **Self-test before every `git push`:** has the author typed "push" since
    your last push? Same rule. Permission to commit is NEVER permission to push.
  - **Exception — branches you created in-session.** When you have explicitly
    created a feature branch yourself (e.g. `git checkout -b feat/something`) in
    that session, commit and push to THAT branch freely without per-step
    permission. The entire branch is reviewed at PR-open, so the per-commit gate
    adds review noise without adding safety. The exception is scoped to branches
    Claude created in the current session; it does NOT extend to `main`, to
    other long-lived branches, or to branches the author created.
- **Project-specific rules belong in AGENTS.md, not in any agent's private
  memory store.** If you (Claude Code, Cursor, Codex, Aider, anything that has a
  "save this preference for next time" surface) catch yourself about to write
  down a rule that's actually about the codebase rather than about working with
  this particular user, write it here instead. Memory is fine for user-profile
  facts and tool-use preferences; project rules should be portable across
  agents.
- **Plain language over jargon.** Comments, docstrings, AGENTS.md, commit
  messages, PR descriptions, and user-facing docs should describe what the code
  does in words a non-specialist would understand. Avoid terminology imported
  from neighboring fields that only loosely applies. When a domain term IS the
  right word (because the code really is implementing that concept, or the
  reader needs to look it up to understand a library), use it AND a brief
  in-place gloss the first time it appears — PDF internals such as `ToUnicode`,
  `/CharSet`, and the structure tree are exactly this case. When a term is
  borrowed loosely, replace it with the literal description. The test is whether
  a contributor coming into the codebase from a different background would have
  to stop and search to understand what a term refers to here; when in doubt,
  prefer the plainer rewrite even if it's a few extra words.
- **Fix underlying bugs, never just patch the data.** A manual command that
  corrects ONE instance of bad state doesn't help other users running the same
  code, doesn't help future input hitting the same bug, and doesn't survive a
  fresh checkout. Every observed bug must result in a code change that prevents
  the bad state from recurring, even when an immediate manual patch is also
  applied to unblock the operator. The manual patch is the bridge; the code fix
  is the destination — both happen, never just the bridge.
- **Verify library signatures against the installed version, not memory.**
  Before calling an unfamiliar function from a third-party library, read the
  source of the version that is actually installed in the project (the file in
  `site-packages` or equivalent). Training data and prior conversations are not
  authoritative — the installed code is. This matters most for `pikepdf`, whose
  object model (`Dictionary`, `Array`, `Stream`, `Name`, `String`) does not
  behave like the Python built-ins it resembles.
- **Read official documentation in full before implementing against an
  unfamiliar API.** Fetch the relevant pages and read them end-to-end, not just
  the headings. When the docs offer both a quick-reference and a detail page on
  the same topic, read the detail page — quick-references omit aliases, edge
  cases, and secondary functions you will need.
- **SDK research order: installed source, then vendor docs, then GitHub
  issues.** When figuring out how a vendor SDK behaves, the installed SDK's
  source is the source of truth, vendor documentation is second, GitHub issues
  are third (for known bugs and undocumented behavior). Third-party blogs, Stack
  Overflow answers, and AI-generated explainers are not primary evidence — at
  best they are pointers to one of the three primary sources. For PDF structure
  itself, the ISO 32000 specification and the ASD report linked from the README
  outrank all of them.
- **Don't catch `Exception` broadly.** Catch only the specific exception types
  you have a recovery path for. A bare `except Exception:` (or `except:`) hides
  programming errors that should be loud, makes debugging harder, and disguises
  broken assumptions as transient failures. Let unexpected exceptions
  propagate.

## Tool-specific rules

These follow from what this tool is for. Breaking one of them produces a tool
that looks like it works and quietly gives the wrong answer about whether
someone's address is still in a document.

- **Never write to the document under inspection.** Open PDFs read-only. Do not
  call `Pdf.save()`, do not pass `allow_overwriting_input=True`, and do not add
  a "fix it for me" mode without an explicit decision from the author. The tool
  is evidence-gathering; a file it has touched is no longer the file the user
  wanted checked. `make-test-samples.py` is the only place that writes PDFs.
- **A malformed PDF is input, not a crash.** Hostile and broken files are the
  normal case here. Every parser path must degrade to "could not read this
  layer" rather than raising — but degrade narrowly, per the `except Exception`
  rule above, and never by silently returning an empty result that reads as
  "clean". If a check cannot run, say so in the report.
- **Every check must be able to say why it fired.** A `Finding` carries a
  severity, a check name, a human-readable detail, and a location. Detail text
  states the observation and the inference separately, so an operator can
  disagree with the inference. Heuristic checks — the font-subset one above all
  — must describe their finding as "consistent with" removed text, never as
  proof of it.
- **The exit-code contract is public API.** 0 clean, 1 suspicious, 2 failed
  (content recoverable), 3 file unreadable. People wire these into pre-send
  hooks and CI gates. Changing the meaning of a code is a breaking change and
  needs a major version bump and a README update in the same commit.
- **Never quiet a check to reduce noise.** Reducing false positives is a
  legitimate goal, but only by making the check more precise about what it
  observed, never by dropping a layer, capping the number of reported findings,
  or downgrading a severity to make output tidier. If a check is too noisy to be
  useful, that is a design conversation with the author, not a threshold tweak.
- **Adding a layer to the tool means adding it to the docs.** The README's
  "What it checks" table and its "Limitations" section together define what a
  clean result means. A new or removed check that does not update both leaves
  the tool making a promise its documentation does not match.

## Testing

- **Fixtures use fictional data only.** The samples use a fictional address (742
  Evergreen Terrace) so they are safe to commit and safe to paste into a bug
  report. Never add a fixture built from a real document, a real person's
  details, or a redacted file someone sent you.
- **The sample PDFs in `tests/samples/` are committed, and `make-test-samples.py`
  rebuilds them.** Tests read the committed files, so runs are deterministic and
  do not need reportlab. Changing a fixture means running `python make-test-samples.py`
  and committing both the generator change and the regenerated PDF — never one
  without the other, or the binary stops matching the code that claims to
  produce it.
- **Every check needs a fixture that fails without it.** A new detection layer
  ships with a builder in `make-test-samples.py`, the regenerated sample, and a
  test asserting the check fires on it — plus confirmation that `clean.pdf` still
  reports nothing. A check with no sample is an assertion about PDFs that nobody
  has tested.
- **A test named for an exclusive claim must prove both halves.** "Only",
  "never", and "exactly once" each assert a negative as well as a positive. If
  the shared test setup can't observe the negative half, build a fresh setup for
  it instead of substituting a nearby assertion that always passes.
- **Prove a regression test by running it against the unfixed code.** A test
  written alongside a bug fix must fail when the fix is reverted; otherwise it
  guards nothing.
- **When testing end-to-end, confirm you are running the edited code.** Running
  a package from outside the project directory can silently resolve an older
  installed copy; check the module's file path (or the paths in a traceback)
  before trusting the result — an old copy can convincingly reproduce the exact
  bug you are fixing. This project is especially prone to it: a `pip install .`
  copy in `site-packages` and `./pdf-redaction-check.py` in the working tree can
  both be reachable at once, and the hyphenated filename means even an
  "editable" install is a stale copy (see Layout above).

## Review discipline

These rules were distilled from real multi-agent review cycles in which defects
survived thorough author-side review — in later cycles, a fresh-context diff
review as well. Each one names a pattern that self-review reliably misses.
Grouped by theme.

### Review prose as prose

A review that only verifies functional correctness (tests pass, files import,
types check) sails past exactly the defects a text-first reviewer catches.

- **Whole-file regenerated artifacts put every line in the diff — review them as
  text, too.** Re-exporting a generated document rewrites the entire file, so
  pre-existing user-facing strings are formally part of the change; a semantic
  before/after comparison deliberately looks through them. Add a text-level pass
  over titles, labels, and markdown.
- **Proofread the whole hunk and the *rendered* text, not just the `+`/`-`
  lines.** Typos one line away from an edit are in your context window and fair
  game, and wrap points interact with markers and punctuation (a comment marker
  landing before an issue number, a trailing hyphen, a code span split across
  lines) — reflow rather than argue the raw text is technically correct.
- **Clean inert config inside hunks the diff already rewrites** — stale entries
  cost nothing to remove and confuse every later reader; "minimize the diff" is
  the wrong tiebreaker there, and remains the right one for untouched files.
- **Docstrings and comments are prose surface too — beware dual-use terms.**
  Words that are both colloquial English and load-bearing technical terms near
  the code in question pattern-match as true for an author who holds both facts.
  In this codebase, "encoding", "string", "object", and "character" are all
  ordinary English *and* named PDF constructs.
- **A plain-type docstring is wrong when `None` is a semantic state.**
  Documenting optional parameters with bare types is fine while `None` merely
  means "not provided"; when `None` is a meaningful third state (a sentinel
  selecting "inherit" or "auto"), document the union type and the sentinel's
  meaning, reading the entry as a naive caller who doesn't share your context.

### Nothing is pre-verified

Code that *feels* already-reviewed — or exempt from review — has zero review
coverage. Five disguises:

- **Moved code.** A "pure move" is a claim about behavior preservation, not an
  exemption from review — read extractions cold, and be *more* suspicious when a
  hunk gains callers than when it changes logic.
- **Extracted helpers.** A helper promoted out of a call site inherits none of
  that site's implicit guarantees: it needs its own eager input validation and
  its own docstring↔behavior check, even when every current caller happens to be
  safe.
- **Fixes made during review.** Touching one direction of a paired protocol
  (`__getstate__`↔`__setstate__`, save↔load, encode↔decode) obligates
  re-deriving the inverse direction, including version-skew inputs (old data
  into new code) that no current fixture produces. The review isn't done when
  the fixes are written.
- **Rewritten code, for coverage.** Rewritten lines are new patch lines even
  when behavior is intentionally identical — error branches carried over from
  the old code still need tests now.
- **Mid-incident glue.** Firefighting is not an exemption: before writing new
  shell/infra code mid-incident, check the file for an existing helper that
  already does it, and give your own inline code the same scrutiny you'd give a
  subagent's.

### Check claims against what they range over

The defects that author-side reviews miss are rarely inside one artifact — they
are relations between two individually-correct places.

- **When fixing one half of a contract, grep for the other half**: write↔read
  against the type contract, comment↔declaration, a docstring guarantee↔every
  statement in its scope, a UI string↔the docs naming it. Here the standing
  pairs are the check functions↔the README's "What it checks" table, the exit
  codes↔the README's exit-code table, and the module docstring↔the actual set of
  checks `analyze()` runs.
- **Count enumerations against the code-defined set they enumerate** — derive
  the set from the code and count both sides; a reader can't tell an intentional
  subset from an omission. The phrase "seven layers" appears in the module
  docstring, the README, and this file.
- **A quantified claim is an enumeration in disguise, and "pre-existing" triage
  stops applying when the diff extends its set.** A paragraph asserting
  something about "all the options above" becomes part of the diff the moment
  the diff adds options — re-derive the claim against the current diff; don't
  inherit an earlier pass's "pre-existing, out of scope" label.
- **Build verification fixtures containing what the sample corpus lacks** —
  optional fields, injected errors, over-the-cap sizes — because an absent field
  makes the wrong key and the right key behave identically. A PDF that simply
  lacks a structure tree cannot tell you whether your structure-tree check
  works.
- **Update tracking state only after the action it tracks has succeeded.** When
  code clears a counter, marks something done, or advances a cursor around an
  action that can fail, do the update after the action succeeds — then walk each
  failure branch and ask what the state means if the action fails right there.
  Reviews reliably verify that cleanup *exists*; they miss *when* it runs.
- **If something can report failure two ways, handle both ways the same.** A
  function that signals failure by return value in one configuration and by
  raised exception in another must run the same cleanup and safety logic on both
  paths. Find every place that raises, not just every place that returns — and
  remember that what happens to a raised exception depends on every caller it
  can propagate through.

### Verify what CI enforces, not a plausible subset

- **Run CI's literal commands from the repo root** — read
  `.github/workflows/ci.yml`. Its four jobs are tests across Python 3.11–3.14, a
  coverage gate, lint (ruff, pyright, markdownlint), and a build that installs
  the wheel and runs the console script. Run `pyright` with the virtualenv
  activated: it resolves imports from the active interpreter, and an
  unactivated run reports every third-party import as missing — noise that
  looks like a real failure. When repo-wide runs are noisy because of untracked
  local directories,
  fix the exclusion in config rather than narrowing the command — a narrowed
  command is a different check that happens to share a name. The markdownlint
  globs live in `.markdownlint-cli2.jsonc` for exactly this reason: the naive
  `**/*.md` walks `.venv` and fails on vendored files the repo does not own.
- **Coverage is a gate, not a report.** `pytest --cov` fails below the
  `fail_under` value in `pyproject.toml`, with branch coverage enabled — an `if`
  whose false path never runs is untested even when every line has executed. New
  code lands with the tests that cover both directions of its branches, or the
  threshold comes down deliberately and in the same commit.
- **Cover CI's gates, not just its commands.** Patch coverage corresponds to no
  replayable workflow command, so command-replay never asks "does a test execute
  every new line?" — compare coverage's missing-lines report against the diff
  before opening a PR.
- **An ad hoc check that matches nothing is broken, not green.** Build one-off
  verification scripts to fail loudly on zero matches — a filter aimed at the
  wrong path or key silently produces an empty, passing-looking result. Silence
  is not success. This tool has the same shape as such a script: a run that
  finds nothing because a check errored out looks exactly like a run that finds
  nothing because the document is clean.

### End with a fresh-context review, not a self re-read

The author's "cold re-read" is never cold — it confirms the model the author
already holds, which is exactly the blindness a fresh reader doesn't share.
Before opening a PR, run a review pass whose reviewer has seen *only* the final
diff — no plan, no conversation history, no memory of writing it (a subagent
given just the diff, or an external reviewer) — and end it asking "do these
hunks agree with *each other*?", not "is each hunk correct?". Triage its
findings like any external review: fix what's real, push back with cited
reasoning on what isn't. Two limits to design around: a fresh-context reviewer
running the same model still shares its priors (convention-compliance can pass
for correctness), and some defect classes are only caught by deterministic
gates, not by more reading.

## Python code style

These standards apply to ALL project Python code **including tests**.

- Formatter/linter: **Ruff**
  - All code must be linted and formatted
- Type annotations use `TypedDict` for structured results
- Supports all currently supported Python versions; this project's floor is
  Python 3.11, declared in `pyproject.toml`
- Modern type annotations across the entire project
  - Always use the latest version of pyright for static type checking
- Testing framework: **pytest**
- Every bit of code should have a test
- Build backend: **hatchling**
- Module-level loggers: `logger = logging.getLogger(__name__)` — one logger per
  module, named for the module. Diagnostic output about the *run* goes to the
  logger; findings about the *document* go to the report, never to a log
- Project-defined errors subclass `RuntimeError`, not bare `Exception`, so
  callers can catch project failures specifically without sweeping in unrelated
  bugs

## Markdown style

- All markdown must pass VSCode's default markdownlint config
  - VSCode projects must be configured with
    `"markdownlint.config": {"MD024": false}` to allow for proper changelog
    headings

## GitHub releases

- Releases are made by version tag not branch
- Version tags should be prefixed with `v`, unless prior tags are not
- Release titles must always exclude the `v` prefix
- For Python projects, wheels and srcbuilds should always be attached
  - Use existing build files **if** they match the release version — `./build.sh`
    produces both into `dist/`; check that the filenames carry the version being
    released rather than rebuilding blindly

Publishing is automated. `.github/workflows/release.yml` fires when a GitHub
release is published: it builds, verifies, uploads to PyPI, and attaches the
artifacts to the release. Three things follow from that.

- **Bump `version` in `pyproject.toml` before tagging.** The workflow refuses to
  publish when the tag disagrees with the packaged version, because PyPI will not
  let you reuse a version number to correct the mistake afterwards.
- **There is no PyPI API token, and none should ever be added.** Publishing uses
  Trusted Publishing: GitHub mints a short-lived OIDC token per run, bound to
  this repository, the `release.yml` filename, and the `pypi` environment. If any
  of those three change, update the publisher configuration on PyPI in the same
  change — renaming the workflow file silently breaks releases.
- **Manual runs go to TestPyPI, never PyPI.** `workflow_dispatch` is the dry run.

## Documentation

The project must be well documented. If existing documentation exists, follow
that convention.

`README.md` is the overview: the rationale, usage, exit codes, checked layers,
limitations, and an AI assistance disclaimer. Detail that only a contributor
needs lives in bite-sized pages under `docs/`, linked from the README — today
that is `docs/development.md`. Keep the split: the README describes what the
tool does, `docs/` describes working on it, and neither becomes a monolith.

The "Limitations" and "AI assistance disclaimer" sections are load-bearing for a
security tool. Keep them accurate and do not soften them.
