# pwn-broker Walkthrough, Feature Index, Configuration & Known Issues

Session walkthrough, feature overview, configuration reference, tested summary, and known issues for `pwn-broker`. For the complete command-by-command guide see [guide.md](guide.md); for full test records see [tested.md](tested.md).

## Install & Offline

```sh
curl -fsSL https://github.com/Real-Fruit-Snacks/pwn-broker/releases/latest/download/install.sh | sh
```

Run as the user who will use `pwn-broker`, not with `sudo` (it uses `sudo` only to create `/opt/pwn-broker` when needed). It verifies the release archive against `SHA256SUMS.txt`, unpacks the app and its own Python into `/opt/pwn-broker`, and adds PATH to `~/.zshrc` (and `~/.bashrc` if present). Needs `sh`, `tar`, `gzip`, `sha256sum`, and `curl` (x86_64 Linux with glibc). Run again to upgrade.

Offline Kali machine: copy `pwn-broker-<version>-linux-x86_64.tar.gz` and `install.sh` from the [latest release](https://github.com/Real-Fruit-Snacks/pwn-broker/releases/latest) and run `sh install.sh --from pwn-broker-<version>-linux-x86_64.tar.gz`. See [guide.md#install-and-upgrade](guide.md#install-and-upgrade) for all options.

## What a Box Looks Like

`pwn-broker new`, then `cred add` and `finish` at the prompt:

```text
$ pwn-broker new
New box
  box name     > forest
  platform     [htb] > 
  date         [2026-11-14] > 
  os           > windows
  difficulty   > easy

  add a target? [Y/n] > 

Target 1
  ip           > 10.10.10.161
  hostname     > forest.htb.local
  scope        [external] > 
  name         [forest.htb.local] > dc01

  ok    target dc01 created

  add another? [y/N] > 

  add dc01's hostnames to /etc/hosts? [Y/n] > 

  ok    /etc/hosts updated
        10.10.10.161 forest.htb.local
  ok    10.10.10.161 answered in 43 ms
  ok    box forest created

  install playbooks in this box and every new box? [Y/n] > n

  ok    saved: new boxes start without playbooks
        for this box only: tool install playbooks
        for every new box: playbooks = true in /opt/pwn-broker/config.toml

  install the report tool in this box and every new box? [Y/n] > n

  ok    saved: new boxes start without the report tool
        for this box only: tool install report
        for every new box: report = true in /opt/pwn-broker/config.toml

forest/dc01 > cred add

  ok    cred 1 saved, found on dc01
  ok    lists updated: 1 username, 1 password, 1 pair

forest/dc01 > finish

  box      forest (htb), started 2026-11-14
  targets  1
  files    14
  archive  /home/kali/pwn-broker/wrapped/2026-11-14_htb_forest.finished.tar.gz
  report   none: tool install report adds the tool that builds one
  hosts    1 line to remove from /etc/hosts

  finish this box? [y/N] > y

  ok    archive /home/kali/pwn-broker/wrapped/2026-11-14_htb_forest.finished.tar.gz
  ok    removed 1 line from /etc/hosts
```

The two `install ...?` questions come only with the first new box on a machine. The answers are kept in `/opt/pwn-broker/state.toml`, and `playbooks` and `report` in `config.toml` decide instead when they are set. With yes, the box gets the package there and then, and so does every later new box.

## What's In It

- **Boxes and targets.** `pwn-broker new`, `import <file>` and `resume [name]`. A box gets a folder under `~/pwn-broker/active/`, each target a folder with `scans/`, `loot/`, `exploits/` and the rest, and one prompt runs for the whole session. Each new target with an IP is pinged once. [Guide](guide.md#boxes-and-targets)
- **The note.** `notes.md` in vim, in a window of its own: the box's details at the top, redrawn when the targets change, and a fold per target. Keys put in a target's IP, a credential from the box or the time, and `,h` lists them. [Guide](guide.md#the-note)
- **Credentials.** Kept exactly as typed, in one list per box. `lists/` is rebuilt from them, so other tools can read `usernames.txt`, `userpass.txt`, `hashes.txt` and the rest. [Guide](guide.md#credentials)
- **/etc/hosts.** One line per target, marked with the box ID, kept in step with the target and removed at `finish`. Other lines are never changed. [Guide](guide.md#the-hosts-file)
- **Recording.** `record [target]` in any terminal records that window with a pinned asciinema 3.2.1 and writes a timed text copy beside it, for grep. `replay` plays one back. [Guide](guide.md#recording)
- **VPN.** `vpn start`, `stop`, `status` and `log` for OpenVPN. The `.ovpn` file is copied into the box and never archived. [Guide](guide.md#vpn)
- **Scans.** `scan` runs nmap against the current target in the background, quick then full, into its `scans/` folder, and says in the prompt when each is done. [Guide](guide.md#scans)
- **Serving files.** `serve` offers the target's `upload/` folder and the tools' files over HTTP behind a random path, prints the line to fetch each one, and saves files the target sends back into `loot/`. [Guide](guide.md#serving-files)
- **Search.** `search <text>` looks through the current target's files, recordings and section of the note, and `search all <text>` through the whole box. [Guide](guide.md#searching)
- **Tools.** `tool install` from [`pwn-shop`](https://github.com/Real-Fruit-Snacks/pwn-shop) ([package list](https://github.com/Real-Fruit-Snacks/pwn-shop/blob/main/docs/PACKAGES.md)). Python tools bring their own Python so Kali's is never shadowed; ordinary dependencies come automatically, `--full` selects optional backends, and `tool doctor` reports them without changing anything. Apt-backed providers need confirmation and stay system-owned. `finish` removes the box's tools and orphaned automatic dependencies. [Guide](guide.md#tools)
- **Playbooks.** `tool install playbooks` gets [pwn-playbooks](https://github.com/Real-Fruit-Snacks/pwn-playbooks); `:Pb <name>` reads one into the note below the cursor with its placeholder fill block, while `playbook list` and `playbook show <name>` browse at the prompt. [Guide](guide.md#playbooks)
- **Reports.** `tool install report` gets [pwn-report](https://github.com/Real-Fruit-Snacks/pwn-report); `finish` builds a private SHA-256-indexed report folder beside the archive. [Guide](guide.md#reports)
- **Finish, export, import.** `finish` archives to `~/pwn-broker/wrapped/` and closes the box, `export` snapshots while continuing, and `pwn-broker import` unpacks either. [Guide](guide.md#finish-export-and-import)

`help` at the prompt lists every command; [guide.md#every-command](guide.md#every-command) has them all in one table.

## Configuration

`/opt/pwn-broker/config.toml`, optional. Without it everything uses the defaults. The installer takes `--config <path>` to copy one in.

| Setting | Default | Meaning |
|---|---|---|
| `home` | `~/pwn-broker` | Where `active/`, `wrapped/` and `tools.log` live; a whole path, as `copy_to` is |
| `copy_to` | not set | A second folder every finished archive, report and export is also copied to |
| `default_platform` | `htb` | Platform used when a box is created |
| `terminal` | `x-terminal-emulator` | What opens the note window |
| `check_updates` | `true` | Look for a newer release at launch |
| `tools_index` | the published index in `pwn-shop` | A URL, or a folder that holds `index.toml` and the zips it names |
| `playbooks` | not set | Whether each new box gets the playbooks. Not set, the first new box asks, and the answer is kept |
| `report` | not set | Whether each new box gets the report tool. Not set, the first new box asks, and the answer is kept |

## Tested On

- Unit suite on Windows 11 (Python 3.13) and Ubuntu 24.04 CI (Python 3.11–3.14 + root), warnings as errors.
- Full offline end-to-end box lifecycle in the official Kali 2026.3 image in CI (OpenVPN + `tun0`, virtual display + `xterm`), plus bare `debian:stable-slim` with no Python and no network.
- End-to-end manual runs in Kali 2026.2 under WSL 2 (root and normal user with `sudo`, `qterminal`) across releases `v0.1.0` through `v0.1.15`.

See [tested.md](tested.md) for the full record.

## Known Issues

- x86_64 Linux with glibc only. On any other machine the installer stops and says so.
- The app's Python and its OpenSSL are as new as the release, not as Kali; a fix to them reaches you only in a new release. They take about 100 MB more on disk.
- Close pwn-broker before you upgrade. The installer replaces `app/` and `python/` under a running prompt, and does not check.
- On a terminal that hosts all its windows in one process, such as gnome-terminal, `finish` closes the note's vim but cannot close its window.
- Nothing is signed. `SHA256SUMS.txt` and the tool index verify download integrity, not publisher identity.
- A password typed on a command line in a recorded window is in the recording and the archive. One typed at a hidden prompt is not.
- `quit` leaves the box's `/etc/hosts` lines in place; only `finish` removes them.
- `finish` refuses while a window is recording for the box or one of its tools is running. Exit those first.

The rest of the list is in [tested.md#known-limits](tested.md#known-limits).
