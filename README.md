# pwn-broker

Keeps a box's targets, notes, creds and tools in order

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

## Tested on

- The unit tests, on Windows 11 with Python 3.13: 721 passed, 15 skipped. The skips are the tests that need Linux (symlinks, named pipes, file modes, ownership, backslash file names, the installer).
- *Not* tested: Kali Linux. The app has not been run there.
- *Not* tested: `install.sh`. It passes `sh -n`, its help and option handling are tested, and so is how it treats an existing `app/` folder (with a stand-in for `python3`), but it has not been run end to end.
- *Not* tested: the note window and the prompt on a real terminal.

## Known issues

- Recording and tool install are not in this release. They are later phases in `docs/design.md`.
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

## License

MIT
