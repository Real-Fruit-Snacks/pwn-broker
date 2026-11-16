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
3. Keep the dependencies few: `prompt_toolkit`, `rich`, `tomli-w` and `pyte` are all there is. Each one ships to every user. `pyte` is pinned to 0.8.2, because the text copy of a recording leans on how it works inside.
4. Add a line to `CHANGELOG.md` under the version being worked on.
5. A new dependency, or a new version of one, goes in `pyproject.toml`, in `release/requirements.lock`, and in `release/licences/sources.toml`. The lock has one `name==version --hash=sha256:<hex>` line per package, for every package the app needs including the dependencies of dependencies, and today every one is a pure Python wheel, so one set serves. `sources.toml` needs a table for it with its licence and the address of its exact source. A new or raised build tool for the release goes in `release/build-requirements.lock`. Tests fail if the locks and `sources.toml` disagree with `pyproject.toml`.

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

Some tests run a real vim and skip themselves when it is absent, so install `vim` to run them. On Windows, the tests that need Linux skip (symlinks, named pipes, file modes, ownership, the installer, the recorded shell's startup files) and run there, which is what CI is for. CI runs the suite on Python 3.11, 3.12, 3.13 and 3.14, once more as root, builds the release file twice in its `release-file` job and fails if the two differ, records real zsh and bash sessions under the asciinema installed from that file in its `recording` job, and checks `install.sh` with `sh -n`, `dash -n` and `shellcheck`, then installs the release file twice into a temporary folder and once in a Debian container with no Python and no network. Its `kali` job installs the release file with the container's network off, and runs one whole box in the official Kali image as root, through `.github/scripts/kali-cycle.sh` and `kali-cycle.py`, and runs the suite there too. It is the one job that downloads a real Python runtime: the shell script fetches the pinned CPython build and checks its size and SHA-256 before the driver wraps it in a test runtime package with `tests/toolkit.py`, so a change to that pin goes in `kali-cycle.sh` and in pwn-shop's `python-3.13` recipe together; when it fails, the `kali-evidence` artifact holds `steps.txt`, each terminal's transcript and the files it checked.

`install.sh` must stay POSIX `sh`. `tests/test_install_sh.py` runs it under `sh` and `dash` against a stand-in release file. To try it on a real one, build a release file (below) and run `sh install.sh --from dist/pwn-broker-<version>-linux-x86_64.tar.gz`; set `PWN_BROKER_OPT` and `HOME` to temporary folders to keep it off your own system.

## Building a release file

```sh
.venv/bin/python release/build.py
```

This needs x86_64 Linux, because the build runs the Python it packs, and the network, because it downloads the pinned Python build, the pinned asciinema and the pinned wheels. It checks each against its size or SHA-256 in `release/pins.toml`, `release/requirements.lock`, `release/build-requirements.lock` and `src/pwn_broker/recorder.py`, and refuses any that differs. `--out <folder>` (default `dist/`) is where the release file and `SHA256SUMS.txt` go, and `--cache <folder>` (default `.cache/release/`) holds the downloads. It ends with `ok    wrote <path> (<n> bytes, SHA-256 <hex>)`. The same checkout gives the same file, byte for byte. The unit tests never run it; CI does.

Some things only show on a real Kali desktop (the note window's terminal and focus, colours, `sudo` tools, a Hack The Box tunnel). [docs/kali-checks.md](docs/kali-checks.md) is the list to run by hand, once as root and once as a normal user, and marks the steps the `kali` job already covers. In the PR, say what you ran it against.

## Commits

One short, plain line in the imperative: `Archive files whose names contain a backslash`. No prefixes, no trailing full stop. Say more in the PR if it needs it.

## Cutting a release

1. Edit the top heading of `CHANGELOG.md` to the version and drop `(unreleased)`, for example `## v0.1.0`. The notes under it become the release notes.
2. Set `version` in `pyproject.toml` and `__version__` in `src/pwn_broker/__init__.py` to match.
3. Commit, then tag and push: `git tag v0.1.0 && git push origin main v0.1.0`.

The `release` workflow fails if the tag is not the version in `pyproject.toml`. It builds the release file with `release/build.py`, installs it, runs the tests on the Python it carries, and publishes three files: the release file, `SHA256SUMS.txt` and `install.sh`, from a second job that runs none of the repository's code. The release is created as a draft with all three files, then made public. `install.sh` downloads the first two from the latest release, so don't attach anything else that ends in `-linux-x86_64.tar.gz`. Started by hand, the workflow is a dry run and publishes nothing.

## Style

- Python: 4 spaces (`.editorconfig`), following the code around it.
- Shell: POSIX `sh`, `set -eu`, passes `shellcheck`.
- Comments say why, not what.
- Status lines: lowercase, plain, and they name the next step when there is one.
