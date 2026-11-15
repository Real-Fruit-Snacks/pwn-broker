# Contributing

Small project, light process.

## Reporting a problem

Use the bug form. The useful parts:

- Kali, Python and pwn-broker versions (`pwn-broker --version`)
- Whether you ran it as root or a normal user
- What you typed in the prompt, and what it printed

Remove real credentials, flags and addresses from the output first.

## Changing something

1. Branch from `main`.
2. Write the test first. A change to behaviour comes with a test that fails without it.
3. Keep the dependencies few: `prompt_toolkit`, `rich` and `tomli-w` are all there is. Each one ships to every user.
4. Add a line to `CHANGELOG.md` under the version being worked on.

The design is in [docs/design.md](docs/design.md). Read the intent and the anti-goals before changing behaviour; most of the rules below come from there.

Rules that matter to a change:

- A value the user typed is never altered: no trimming, quoting, escaping or colour markup on the way in or out. A credential comes back exactly as it went in.
- Anything hard to undo shows what it is about to do and asks first. The default answer is no.
- Every status line starts with `ok`, `warn` or `fail`, so it reads without colour.
- Only the app writes metadata (`box.toml`, `files.toml` and the rest). Nothing else writes to it, and a change that reads it must cope with it being edited by hand.
- It works as root and as a normal user with `sudo`. Don't assume uid 0 or hard-code `/root`.

## Setting up and testing

You need Python 3.11 or later.

```sh
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q -W error
```

Some tests run a real vim and skip themselves when it is absent, so install `vim` to run them. On Windows, 15 tests skip (symlinks, named pipes, file modes, ownership, backslash file names, the installer) and run only on Linux, which is what CI is for. CI runs the suite on Python 3.11, 3.12 and 3.13, once more as root, and checks `install.sh` with `sh -n`, `dash -n` and `shellcheck`, then installs it into a temporary folder.

`install.sh` must stay POSIX `sh`. Test it from a checkout with `sh install.sh --from .`; set `PWN_BROKER_OPT` and `HOME` to temporary folders to keep it off your own system.

Some things only show on a real Kali desktop (the note window, colours, `sudo` tools). [docs/kali-checks.md](docs/kali-checks.md) is the list to run by hand, once as root and once as a normal user. In the PR, say what you ran it against.

## Commits

One short, plain line in the imperative: `Archive files whose names contain a backslash`. No prefixes, no trailing full stop. Say more in the PR if it needs it.

## Cutting a release

1. Edit the top heading of `CHANGELOG.md` to the version and drop `(unreleased)`, for example `## v0.1.0`. The notes under it become the release notes.
2. Set `version` in `pyproject.toml` and `__version__` in `src/pwn_broker/__init__.py` to match.
3. Commit, then tag and push: `git tag v0.1.0 && git push origin main v0.1.0`.

The `release` workflow fails if the tag is not the version in `pyproject.toml`. It runs the tests, builds the wheel, writes `SHA256SUMS.txt` and publishes both as the release. `install.sh` downloads exactly those two files from the latest release, so don't attach anything else that ends in `.whl`.

## Style

- Python: 4 spaces (`.editorconfig`), following the code around it.
- Shell: POSIX `sh`, `set -eu`, passes `shellcheck`.
- Comments say why, not what.
- Status lines: lowercase, plain, and they name the next step when there is one.
