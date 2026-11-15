# pwn-broker

Keeps a box's targets, notes, creds and tools in order

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/panel-dark.svg">
  <img alt="A pwn-broker session beside the box's folder. pwn-broker new creates target dc01 and box forest, and the folder 2026-11-14_htb_forest appears with box.toml, notes.md, creds.toml, lists/ and targets/dc01/; cred add at the forest/dc01 prompt saves a credential and svc-alfresco and s3rvice appear in the lists; finish writes 2026-11-14_htb_forest.finished.tar.gz to wrapped/" src="docs/assets/panel-light.svg" width="100%">
</picture>

<sub>A real session, without the questions each command asks. On the right, the box's folder as each step leaves it, with only the lists the credential fills; finish keeps the folder unless told to remove it.</sub>

```sh
curl -fsSL https://raw.githubusercontent.com/Real-Fruit-Snacks/pwn-broker/main/install.sh | sh
```

No release has been published yet, so that line does not work today. From a clone:

```sh
sh install.sh --from .
```

Run the installer as the user who will use pwn-broker, not with `sudo`; it asks for `sudo` itself when it needs to create the folder. It asks no questions otherwise. It creates `/opt/pwn-broker` (using `sudo` once if it has to) and gives it to you, builds a virtual environment in `app/`, installs the package there, and adds `/opt/pwn-broker/bin` to PATH in `~/.zshrc` and, if it exists, `~/.bashrc`. Nothing goes into the system Python. Run it again to upgrade.

| Option | Does |
|---|---|
| `--from <path>` | Install from a local folder or wheel instead of the latest release |
| `--config <path>` | Copy a settings file to `/opt/pwn-broker/config.toml` |
| `--no-path` | Leave the shell config files alone |
| `--help` | Show the options |

Set `PWN_BROKER_OPT` to install somewhere other than `/opt/pwn-broker`. Without `--from`, the installer downloads the wheel from the latest GitHub release and checks its SHA-256 against `SHA256SUMS.txt` before installing anything. That catches a corrupted download; it does not prove who published the release.

## Context

I solve Hack The Box machines and want each one kept in order the way an engagement would be. Without that, a box leaves scan output, notes, credentials and downloaded tools scattered across the machine, and nothing records which box any of it belonged to. I launch `pwn-broker` when I start a box. It asks a few questions, builds the workspace, opens my notes in vim, and stays open as a prompt for the whole session. When the box is done it packs everything into one archive. It is for Kali Linux with a desktop session, run by the user who installed it.

## What's in it

```
pwn-broker                 open the menu, or the box you are inside
pwn-broker new             start a new box
pwn-broker import <file>   unpack an exported box
pwn-broker resume [name]   reopen an active box
```

Launch runs a few checks, then offers a new box, an import, any active box to resume, or a finished box that is still on disk to reopen. Only one box is open at a time. The prompt commands:

| Command | Does |
|---|---|
| `check` | Run the setup checks again |
| `cred add` | Save a credential |
| `cred clear` | Empty a credential's secret or note |
| `cred edit` | Change a credential |
| `cred import` | Add usernames from a file, one per line |
| `cred list` | List the credentials |
| `cred remove` | Delete a credential |
| `cred show` | Print one secret and nothing else |
| `cred works` | Record where a credential works |
| `export` | Write a snapshot archive and keep working |
| `files` | List the files saved for a target or the whole box |
| `finish` | Archive the box and close it |
| `flag root` | Record the root flag |
| `flag user` | Record the user flag |
| `help` | List the commands |
| `note` | Open the note in vim |
| `path` | Print a folder's full path |
| `quit` | Leave the shell |
| `status` | Show the box at a glance |
| `target add` | Add a target to this box |
| `target edit` | Change a target's addresses or scope |
| `target list` | List the targets |
| `target remove` | Remove an empty target |
| `target rename` | Rename a target and its folder |
| `target show` | Show one target |
| `target use` | Switch to a target |
| `tool cache clear` | Empty the download cache |
| `tool info` | Show a tool's details, how to run it and its examples |
| `tool install` | Install a tool; name@version picks a version |
| `tool list` | List the tools in the index; --installed shows this box's |
| `tool refresh` | Fetch the tool index now |
| `tool remove` | Take a tool off this box |
| `tool search` | Search the index by name, description or tag |

A box lives in `~/pwn-broker/active/<date>_<platform>_<name>/`:

```
box.toml              identity, status, dates, flags
creds.toml            one credential list for the whole box
files.toml            a record of every file in the box
notes.md
lists/                usernames, passwords, pairs, hashes, IPs and hostnames
screenshots/
targets/
  dc01/
    target.toml       IPs, hostnames, scope
    creds/  files/  loot/  scans/  exploits/  screenshots/  recordings/
```

`finish` and `export` write archives to `~/pwn-broker/wrapped/`.

`notes.md` starts with a box drawn in `#` that holds the box details and one row per target, and the app redraws it whenever the targets change. Below it, each target has a section wrapped in a vim fold that starts with its `Target:` line, and the note opens with every fold closed down to that line. `F8` in vim adds an empty fold below the cursor. The app changes nothing else in the note, apart from a `Target:` line it wrote when that target is renamed or edited.

The app rebuilds the `lists/` folder from the credential record whenever a credential or target changes, so other tools can read the files as they are:

| File | Holds |
|---|---|
| `usernames.txt` | Every username, one per line |
| `passwords.txt` | Every password |
| `userpass.txt` | `username:password` pairs |
| `hashes.txt` | Every hash |
| `userhash.txt` | `username:hash` pairs |
| `pair-users.txt`, `pair-passwords.txt` | The same pairs, one half each, line N with line N |
| `ips.txt`, `hostnames.txt` | Every target address and name |
| `hosts.txt` | Each IP followed by its hostnames, in `/etc/hosts` form |
| `works-<target>-userpass.txt`, `works-<target>-userhash.txt` | Pairs confirmed on one target |

Edits made by hand to these files are overwritten at the next rebuild.

## Tools

`tool install <name>` puts a tool on the machine for this box, and `finish` takes it off again. A package is one zip for one build of one tool: a manifest, the upstream licence, the tool's own files exactly as upstream published them, and, for a Python tool, every dependency as a wheel with its SHA-256 recorded. A package holds no install script. A Python tool gets its own virtual environment, built from the bundled wheels with no network access, wheels only and hash checking on. Nothing else from a package runs during install. Every download and every cached zip is checked against the size and SHA-256 in the index before it is used, and the app refuses to delete anything outside `/opt/pwn-broker`, whatever a manifest says. x86_64 only.

The packages come from a second repository, `Real-Fruit-Snacks/pwn-shop`, where the published index lives. The first set planned for it is kerbrute, pspy, certipy, targetedkerberoast, ligolo-ng and peass-ng. None of them has been installed on Kali yet.

```
forest/dc01 > tool install ligolo-ng
ok    ligolo-ng 0.9.2 installed
run   ligolo-proxy   from any terminal
      sudo /opt/pwn-broker/bin/ligolo-proxy
files /opt/pwn-broker/upload/ligolo-ng   agent  agent.exe
```

That is the shape of the output, not a recorded run. `tool list`, `tool search` and `tool info` work from the cached index without a network.

- **Kali's own copies are never touched.** An install writes a launcher for each command into `/opt/pwn-broker/bin`, and that folder decides which copy a bare command name runs. If Kali already has a command of the same name, install prints a `warn` line with its path and says the installed one wins. `tool list` has a `kali` column that says whether Kali already has a command of that name.
- **`sudo` is never reconfigured.** `sudo` does not search your PATH, so a tool that needs root is run as `sudo <full path>`. The app prints that path after install and in `tool info`.
- **One build of a tool per machine**, shared by every unfinished box that uses it. A box that already has another build has to `tool remove` first.
- **At `finish`**, the tools this box installed are removed unless another unfinished box still uses them. For a tool that writes to your home folder, the manifest lists the paths. Before the archive is made, `finish` copies that data into the box, and it deletes it afterwards only if it did not exist before the install. `finish` refuses while one of the box's tools is running, and names it.
- **`export`** copies tool data into the box and removes nothing. **`import`**, and reopening a finished box, offer to install the box's tools again, at the same builds and checked against the SHA-256 the box recorded.

### The tools index

`tools_index` in `config.toml` says where the index is. It is a URL, or a folder on disk. In a folder, the index is `index.toml` and each zip is looked for by the `file` name the index gives, in the same folder; the `url` field is not used. A leading `~` is expanded.

```toml
tools_index = "~/pwn-shop/dist"
```

The app keeps a copy of a downloaded index in `/opt/pwn-broker/cache/`, refreshes it when it is more than a day old and the source answers within two seconds, and otherwise uses what it has. `tool refresh` fetches it now. With no index and no cached copy, every `tool` command prints one `fail` line that says where it looked and how to set `tools_index`.

## Tested on

- The unit tests, on Windows 11 with Python 3.13: 1264 passed, 33 skipped, with warnings treated as errors. The skips are the tests that need Linux (symlinks, named pipes, file modes, ownership, backslash file names, the installer, virtual environments and launchers).
- The unit tests, on Ubuntu 24.04 in CI with Python 3.11, 3.12 and 3.13. On Linux they include real tool installs into a virtual environment and the launchers. No Linux count is given here, because none has been recorded for this version.
- `install.sh`, run twice from a checkout on Ubuntu 24.04 in CI: the first run builds the environment, installs the package and writes the launcher and the PATH line; the second reuses the environment and adds no second PATH line.
- The vimrc, run by Vim 9.2 in headless mode on a note the app wrote: folds, fold text, `F8`, colours, settings, and the reload after the app changes the note. Timers and focus events do not fire in that mode, so the tests run the check by hand.
- *Not* tested: Kali Linux. The app has not been run there, and the checks in `docs/kali-checks.md`, the tool checks included, have not been run yet.
- *Not* tested: any real tool package. None of the six planned for `pwn-shop` has been installed on Kali.
- *Not* tested: the installer's download. No release exists, so fetching the wheel and checking its SHA-256 has not run.
- *Not* tested: the note window and the prompt on a real terminal.

## Known issues

- Recording is not in this release. It is a later phase in `docs/design.md`.
- The published tool index is private for now, because `pwn-shop` is. Until it is public, `tools_index` must point at a folder that holds `index.toml` and the zips it names. The first one to try needs `pwn-shop` to exist, and it does not yet.
- No release has been published, so the `curl` install line does not work yet. Install from a clone.
- `cred list` marks a secret it cannot show exactly (a tab, another control character, or a space at either end) with `*` after the number. `cred show` prints it unchanged.
- Links and special files (named pipes, sockets, devices) in a box are not archived. `export` and `finish` list them, and `finish` says how many will go when the folder is removed.

## Configuration

`/opt/pwn-broker/config.toml`, optional. Without it everything uses the defaults. The installer takes `--config <path>` to copy one in.

| Setting | Default | Meaning |
|---|---|---|
| `home` | `~/pwn-broker` | Where `active/` and `wrapped/` live |
| `copy_to` | not set | A second folder every finished archive and export is also copied to |
| `default_platform` | `htb` | Platform used when a box is created |
| `terminal` | `x-terminal-emulator` | What opens the note window |
| `check_updates` | `true` | Look for a newer release at launch |
| `tools_index` | the published index in `pwn-shop` | A URL, or a folder that holds `index.toml` and the zips it names |

## License

MIT
