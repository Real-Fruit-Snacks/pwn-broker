# pwn-broker

Keeps a box's targets, notes, creds and tools in order

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/panel-dark.svg">
  <img alt="A pwn-broker session beside the box's folder. pwn-broker new creates target dc01 and box forest, and the folder 2026-11-14_htb_forest appears with box.toml, notes.md, creds.toml, lists/ and targets/dc01/; cred add at the forest/dc01 prompt saves a credential and svc-alfresco and s3rvice appear in the lists; finish writes 2026-11-14_htb_forest.finished.tar.gz to wrapped/" src="docs/assets/panel-light.svg" width="100%">
</picture>

<sub>Some of the lines of a real session: each command and the `ok` lines that go with the folder beside it. The launch checks, the questions, and the `/etc/hosts` and ping lines are left out. On the right, the box's folder as each step leaves it, with only the lists the credential fills; finish keeps the folder unless told to remove it.</sub>

```sh
curl -fsSL https://github.com/Real-Fruit-Snacks/pwn-broker/releases/latest/download/install.sh | sh
```

No release has been published yet, so that line does not work until `v0.1.0` is tagged. For a release file already on the machine:

```sh
sh install.sh --from pwn-broker-0.1.0-linux-x86_64.tar.gz
```

To install from a checkout, build a release file first, on x86_64 Linux. The build downloads the pinned inputs and refuses any that does not match its size or SHA-256, then prints `ok    wrote <path> (<n> bytes, SHA-256 <hex>)`:

```sh
python3 -m venv .venv && .venv/bin/pip install -e . && .venv/bin/python release/build.py
sh install.sh --from dist/pwn-broker-0.1.0-linux-x86_64.tar.gz
```

The first command needs `python3-venv` and `git` (`apt install python3-venv git`); installing the app does not. That first step is the build machine's own environment and its dependencies are not pinned; what goes into the release file is. `release/build.py` makes its own build environment with the Python it packs.

Run the installer as the user who will use pwn-broker, not with `sudo`; it asks for `sudo` itself when it needs to create the folder. It asks no questions otherwise. It creates `/opt/pwn-broker` (using `sudo` once if it has to) and gives it to you, unpacks the release's own Python into `python/`, makes a virtual environment in `app/` with that Python, installs the app and its dependencies there from the wheels in the release file, copies asciinema into `app/bin/`, runs the app's `setup`, and adds `/opt/pwn-broker/bin` to PATH in `~/.zshrc` and, if it exists, `~/.bashrc`. Nothing goes into the system Python. Run it again to upgrade: an install over an existing one replaces `python/` and `app/` and nothing else, and if it fails or is interrupted the previous install is put back. It refuses an `/opt/pwn-broker` that belongs to another user, for example one made as `kali` when you now run it as root: move that folder aside (`mv /opt/pwn-broker /opt/pwn-broker.old`) or run the installer as that user.

| Option | Does |
|---|---|
| `--from <file>` | Install from a release file on disk instead of the latest release |
| `--config <path>` | Copy a settings file to `/opt/pwn-broker/config.toml` |
| `--no-path` | Leave the shell config files alone |
| `--help` | Show the options |

Set `PWN_BROKER_OPT` to install somewhere other than `/opt/pwn-broker`. `--from` takes a release file only: a checkout (`--from .`) and a wheel are refused.

A release is one file, `pwn-broker-<version>-linux-x86_64.tar.gz`, about 47 MB. It holds the upstream CPython 3.13.18 build from python-build-standalone byte for byte, the wheel of the app and of each of its eight dependencies, `wheels.lock` pinning each wheel by SHA-256, the pinned asciinema 3.2.1, and `licences/`, a licence text and the address of the exact source for each of the 11 things in it. A release publishes three files: the release file, `SHA256SUMS.txt` and `install.sh`.

What an install needs:

- `sh`, `tar`, `gzip` and `sha256sum`, and `curl` when it is not given `--from`. It needs no `python3`, no `python3-venv`, and contacts neither PyPI nor asciinema's releases.
- x86_64 Linux with glibc. On any other machine it stops and says so.
- About 100 MB more on disk than the app alone, for the Python.

The app's Python and its OpenSSL are fixed when a release is made, not when Kali updates. A new Kali Python cannot break the app, and a fix to the app's Python reaches you only in a new release.

What is trusted is the release file. Downloaded, it is checked against `SHA256SUMS.txt` before anything is installed. `SHA256SUMS.txt` comes from the same release, so that catches a corrupted download; it does not prove who published the release. With `--from` the installer prints the file's SHA-256 (`ok    release file <name>, SHA-256 <hex>`) for you to compare with the release page. The wheels are checked by `pip` against `wheels.lock`, with no index, wheels only and every hash required. asciinema is checked by `setup` against the pin in the app. The Python inside the file is not checked again.

What still reaches out, and to where:

| When | What | Where |
|---|---|---|
| Install without `--from` | The release file and its checksum | This repository's release |
| `tool install` | Packages and the index | `pwn-shop`'s releases, or a folder on disk |
| Launch | Whether a newer release exists | This repository's releases; `check_updates = false` turns it off |

Nothing else, apart from a ping to each new target's first IP and OpenVPN when you start it. With `--from` and a folder for `tools_index`, the install and the tool commands contact nothing.

asciinema is the static x86_64 Linux build, and it is always in the release file. It goes in `/opt/pwn-broker/app/bin/`, which is not on PATH, so Kali's own `asciinema`, if there is one, is untouched. If it is missing or does not match its pin, `setup` fails and so does the installer, and the previous install is put back. If it goes missing later, every launch prints the `asciinema` `warn` line and says to run the installer again; nothing is downloaded. asciinema is GPL-3.0-or-later and is not in this repository; the release file carries its licence text and the address of its source.

The installer works in `/opt/pwn-broker/.install.<random>` and removes it at the end. After a kill or a power cut that folder can be left behind, and it may hold the previous install. The launchers, `pwn-broker` and `record`, start Python with `-I`, so a file in the folder you start the app from cannot be loaded in place of one of the app's modules. An existing install gets them at its next install.

## Context

I solve Hack The Box machines and want each one kept in order the way an engagement would be. Without that, a box leaves scan output, notes, credentials and downloaded tools scattered across the machine, and nothing records which box any of it belonged to. I launch `pwn-broker` when I start a box. It asks a few questions, builds the workspace, opens my notes in vim, and stays open as a prompt for the whole session. When the box is done it packs everything into one archive. It is for Kali Linux with a desktop session, run by the user who installed it.

## What's in it

```
pwn-broker                 open the menu, or the box you are inside
pwn-broker new             start a new box
pwn-broker import <file>   unpack an exported box
pwn-broker resume [name]   reopen an active box
record [target]            record this terminal window for a target of the open box
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
| `host` | List every hostname in the box and whether it is in `/etc/hosts` |
| `host add` | Add hostnames to the current target |
| `host file off` | Take a target's line out of `/etc/hosts` and forget it |
| `host file on` | Put a target's line into `/etc/hosts` |
| `host remove` | Take hostnames off the current target |
| `note` | Open the note in vim |
| `path` | Print a folder's full path |
| `quit` | Leave the shell |
| `replay` | List a target's recordings, or play one |
| `status` | Show the box at a glance |
| `target add` | Add a target to this box |
| `target edit` | Change a target's addresses or scope |
| `target list` | List the targets |
| `target remove` | Remove an empty target |
| `target rename` | Rename a target and its folder |
| `target show` | Show one target |
| `target use` | Switch to a target |
| `tool cache clear` | Empty the download cache |
| `tool history` | List every tool this box has had, removed ones too |
| `tool info` | Show a tool's details, how to run it and its examples |
| `tool install` | Install a tool; name@version picks a version |
| `tool list` | List the tools in the index; --installed shows this box's |
| `tool refresh` | Fetch the tool index now |
| `tool remove` | Take a tool off this box |
| `tool search` | Search the index by name, description or tag |
| `vpn log` | Show the last 20 lines of OpenVPN's log |
| `vpn start` | Copy a `.ovpn` file into the box and start OpenVPN |
| `vpn status` | Whether a tunnel is up, and which box started it |
| `vpn stop` | Stop the VPN pwn-broker started |

A box lives in `~/pwn-broker/active/<date>_<platform>_<name>/`:

```
box.toml              identity, status, dates, flags, targets with an /etc/hosts line, VPNs and tools used
creds.toml            one credential list for the whole box
files.toml            a record of every file in the box
notes.md
lists/                usernames, passwords, pairs, hashes, IPs and hostnames
screenshots/
vpn/                  copies of the .ovpn files vpn start used; never archived
targets/
  dc01/
    target.toml       IPs, hostnames, scope
    creds/  files/  loot/  scans/  exploits/  screenshots/  recordings/
```

`finish` and `export` write archives to `~/pwn-broker/wrapped/`. `~/pwn-broker/tools.log` records every tool each box installed and took off.

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

### Recording

`record [target]`, typed in any terminal window while a box is open in the prompt, records that window into the target's `recordings/` folder until you exit its shell:

```
$ record dc01
ok    recording this window for dc01 (forest)
    targets/dc01/recordings/2026-11-14_1432.cast
    exit this shell to stop
...
ok    recording saved, 14 min
    targets/dc01/recordings/2026-11-14_1432.cast
    targets/dc01/recordings/2026-11-14_1432.txt
```

That is the shape of the output, not a recorded run.

- The target is a name, an IP or a hostname, matched the way `target use` matches. With none, it records for the box's last-used target. An address that is not a target asks `10.10.10.200 is not a target of forest. add it? [y/N]`, then the `target add` questions with the address filled in, and adds it as `target add` would; the prompt's current target does not change. If the prompt is in the middle of a command for more than five seconds, `record` says so and adds nothing.
- It starts your own shell (`$SHELL`) under the pinned asciinema, with a title of the box name, the target name and the box ID. asciinema runs with settings folders of the app's own in `/opt/pwn-broker/run/asciinema/`, so nothing in your home folder changes how it records. A recording is only written to the local file; nothing is uploaded.
- Only what the terminal shows is recorded, never keystrokes. A password typed at a hidden prompt is not recorded; one typed on a command line is.
- In zsh and bash the prompt starts with `[rec dc01]` while recording. The shell starts from a small startup file of the app's that loads your own first, then adds the prefix. Any other shell records without it.
- Each window gets its own file, named by its start time to the minute, with `-2`, `-3` and so on when that name is taken. `record` inside a window that is already recording refuses and names its target. With no box open it records nothing and exits with status 1. Run through `sudo` by a normal user, it refuses: run `record` first, then `sudo` inside it.

Beside each `.cast` is a `.txt` of the same name, for vim and grep. An example of its form:

```
box      forest  6f9c1e0a-52c1-4b7e-9d0c-1a2b3c4d5e6f
target   dc01
started  2026-11-14 14:32:07
cast     2026-11-14_1432.cast

14:32:15  $ nmap -sC -sV 10.10.10.161
14:32:41  88/tcp  open  kerberos-sec
14:40:12  [full-screen program until 14:43:30, see the cast]
---- 2026-11-15 ----
00:01:10  $ evil-winrm -i 10.10.10.161 -u svc-alfresco
```

Every line of text starts with the time its last character was drawn; an empty line and a `---- <date> ----` line have no time. The app replays the `.cast` through a terminal model (`pyte`) at the recorded size: colours and control sequences are dropped, a line redrawn in place appears once as it last stood, a wrapped line is joined back into one, and a full-screen program (vim, less, a menu) is one line saying when it ran. The text is written when the window closes. `export`, `finish` and `replay` write it for any recording whose text is missing or older than its `.cast`, so a window that was killed still gets one. A `.cast` that cannot be read gets a `warn` line naming it and no text.

`replay` lists the current target's recordings, or a named target's, oldest first, with when each started, its length and size, or `recording now`. `replay <n>` (or `replay <target> <n>`) plays one in the prompt window with the pinned asciinema, idle gaps cut to two seconds; Ctrl-C stops it and returns to the prompt. A recording still being recorded cannot be played until its window exits.

`finish` refuses while a window is recording for the box and names the targets. `export` goes ahead with a `warn` line, and packs a recording still being written up to its last whole line. `quit` warns, and the window keeps recording into the box. `status` has a `recordings` line, and the status bar shows `rec 2` while two windows are recording.

### /etc/hosts

A target with an IP and a hostname can have one line in `/etc/hosts`, its first IP and all its hostnames, marked with the box ID:

```
10.10.10.161 forest.htb.local  # pwn-broker 6f9c1e0a-52c1-4b7e-9d0c-1a2b3c4d5e6f
```

`target add` (at launch, in the prompt or from `record`) and `target edit` ask `add dc01's hostnames to /etc/hosts? [Y/n]` when the target has both and no line yet. The default is yes. After that the line follows the target: `target edit`, `host add` and `host remove` rewrite it without asking, `target remove` takes it out, and `finish` removes the box's lines after the archive is verified. Opening a box puts its lines back if they are missing. At launch, lines left by a box that is finished or no longer on disk are offered for removal.

```
forest/web01 > host add crm.board.htb dev.board.htb
ok    web01 now answers to 3 names
ok    /etc/hosts updated
    10.10.11.5 board.htb crm.board.htb dev.board.htb
```

- Only the app's marked lines are ever changed. Every other line is written back byte for byte, except that a line break is added before the app's line when the file does not end with one. The file is written in place, not replaced, so its owner and mode stay. Just before writing, it is read again; if another program changed it, the app starts over once, then gives up with a `warn` line. As root the app writes it directly; as a normal user it writes the new content under `/opt/pwn-broker/run` and copies it into place with `sudo cp`. If that fails, nothing is changed and the line is printed for you to add.
- A hostname already on an unmarked line, one that is not the app's, with the same IP is left off, and the app says it already resolves. With a different IP it is left off too, and the `warn` line shows that line, its number and the `host file on` command to run once you have removed it yourself.
- A hostname on another of your boxes' lines takes that line out, with a `warn` naming the box; it comes back when that box is opened.
- Only a plain hostname is written: letters, digits, hyphens and dots, 253 characters at most. If `/etc/hosts` is missing, a link or not a regular file, nothing is written and the app says why.

### VPN

The `vpn` launch check prints a `warn` line when no interface named `tun<n>` has an IPv4 address, and never stops the launch. With several, the lowest-numbered one is used. The status bar shows `vpn 10.10.14.7` or `no vpn`; `status` has a `vpn` line that reads `10.10.14.7 on tun0` or `not up`; and `{lhost}` in `tool info` examples is filled from it.

```
forest > vpn start
vpn file     [/home/kali/Downloads/lab_user.ovpn] >
ok    copied to vpn/lab_user.ovpn
ok    vpn up, 10.10.14.7 on tun0
```

- The question takes a path, with Tab completing it, and defaults to the file used last time on any box. The file is copied into the box's `vpn/` folder, mode 600; a copy of the same name and content is reused, and different content gets `-2`, `-3` and so on. A file over 1 MiB is refused.
- OpenVPN is started in its own background mode, as root directly or through `sudo` for a normal user, in the original file's folder so a certificate or key named beside it is found. The file's own `up` and `down` scripts, if it has any, run as root, as they would if you ran `openvpn` yourself. What the running VPN needs lives in `/opt/pwn-broker/run/vpn/`, not in the box, so closing a window or quitting the prompt does not end it, and it outlives the box that started it.
- `vpn start` waits up to 15 seconds for the tunnel. If OpenVPN ends first, it says so and prints the last lines of the log; if it is still trying, it says so and names `vpn log`. If the app's own VPN is already up, it says so, starts nothing, and records that this box used it: `vpn stop` first to change files. If a tunnel is up that the app did not start, it asks `start another? [y/N]`.
- `vpn stop` signals only the process the app started, checked by its process ID, its start time and its name, `openvpn`. A tunnel you started by hand is reported and never touched.
- `box.toml` records each VPN the box started or used: the file's name, its SHA-256 and when. The `vpn/` folder is left out of `files.toml`, the manifest and every archive, because the file holds your VPN key. `import` restores the record and starts nothing. At `finish`, if the app's VPN is still up, it asks whether to stop it; the default keeps it for the next box.

### Ping

Each new target with an IP is pinged once at its first IP, with a two-second wait, wherever it was added: `ok    10.10.10.161 answered in 43 ms`, or a `warn` line that it did not answer, since Windows targets often do not. Ctrl-C cancels the ping and nothing else. With no `ping` on the machine, the app says once per session that it did not check.

## Tools

`tool install <name>` puts a tool on the machine for this box, and `finish` takes it off again. A package is one zip for one build of one tool: a manifest, the upstream licence, the tool's own files exactly as upstream published them, and, for a Python tool, every dependency as a wheel with its SHA-256 recorded. A package holds no install script. A Python tool gets its own virtual environment, built from the bundled wheels with no network access, wheels only and hash checking on, and its `wheels.lock` is checked line by line before pip reads it. Nothing else from a tool's package runs during install. Every download and every cached zip is checked against the size and SHA-256 in the index before it is used, and a tool's folder, its launchers and its upload files are created and removed only inside `/opt/pwn-broker`, whatever a manifest or index names. A tool's data in the home folder is the one thing removed outside it, at `finish` or when the last box that uses the tool removes it: a path is deleted only if it did not exist before the install, sits strictly inside the home folder, has no link anywhere on the way to it, and no other unfinished box uses the tool. It is copied into the box first, and a path that could not be copied in full is kept, with a warning. The first set of packages is x86_64 only, and a package built for another architecture is refused at install.

The app can install a Python tool that brings its own Python instead of using Kali's. Such a tool requires a runtime: a package of kind `runtime`, such as `python-3.13`, that carries one CPython build from [python-build-standalone](https://github.com/astral-sh/python-build-standalone) byte for byte, and its wheels are built for that Python alone. The first tool that requires a runtime installs it; every tool that requires it then shares it, and it is removed with the last of them, at `finish` or `tool remove`. A Kali upgrade to a new Python does not touch a tool on a runtime. A runtime puts nothing in `/opt/pwn-broker/bin`, so Kali's `python3` is never shadowed, and `tool list` and `tool search` do not show it; `tool install` and `tool remove` refuse its name. Its archive is unpacked by the app itself under strict rules: only regular files, folders and relative links that stay inside the runtime's folder, at most 20,000 entries and 1 GiB, and a damaged or cut-short archive is refused before anything is written. The runtime's interpreter and the `pip` it carries are what run during the install: they make the tool's virtual environment and install the bundled wheels into it, isolated from your shell's settings (`-I`, `pip --isolated`, no `PYTHON*` or `PIP_*` variables, the tool's own folder as the working directory). The first such tool on a machine costs the runtime: a download the app shows as 34 MB (the zip in mebibytes, rounded), about 100 MB unpacked, and the zip, which stays in the download cache until `tool cache clear`. Build 3 of `certipy` and `targetedkerberoast` requires a runtime, and is the only build of each that is published: builds 1 and 2 were withdrawn on 2026-11-15, before any box had used them. The app still reads a package that runs on Kali's own Python (schema 1); none is published.

The packages are published in a second repository, [`Real-Fruit-Snacks/pwn-shop`](https://github.com/Real-Fruit-Snacks/pwn-shop): kerbrute, pspy, certipy, targetedkerberoast, ligolo-ng and peass-ng, and the `python-3.13` runtime the two Python tools run on. With no setting, the app reads that repository's published index. To work with no network, fill a folder with `sh fetch.sh <folder>` in a clone of it and point `tools_index` at the folder.

```
forest/dc01 > tool install ligolo-ng
ok    ligolo-ng 0.9.2 installed
run   ligolo-proxy   from any terminal
      sudo /opt/pwn-broker/bin/ligolo-proxy
files /opt/pwn-broker/upload/ligolo-ng   agent  agent.exe
```

The first tool that requires a runtime brings it, and says so first:

```
forest/dc01 > tool install certipy
ok    python-3.13 3.13.18 installed (runtime, 34 MB)
ok    certipy 5.1.0 installed
run   certipy   from any terminal
```

Those are the shape of the output, not recorded runs. The runtime's size is its zip in mebibytes, rounded. If the tool then cannot be installed, the runtime it brought is removed again, with `ok    python-3.13 3.13.18 removed (runtime)` before the line that says why. `tool list`, `tool search` and `tool info` read the index. With a URL index they use the cached copy when the source does not answer in time, and fail with one line naming the location when there is neither. A folder index is read directly.

- **Kali's own copies are never touched.** An install writes a launcher for each command into `/opt/pwn-broker/bin`, and that folder decides which copy a bare command name runs. If Kali already has a command of the same name, install prints a `warn` line with its path and says the installed one wins. `tool list` has a `kali` column that says whether Kali already has a command of that name.
- **`sudo` is never reconfigured.** `sudo` does not search your PATH, so a tool that needs root is run as `sudo <full path>`. The app prints that path after install and in `tool info`. A bare `sudo <command>` finds nothing, or Kali's own command of that name: Kali's `ligolo-ng` package installs its own `ligolo-proxy`, so with both installed a bare `ligolo-proxy` runs the installed one and a bare `sudo ligolo-proxy` runs Kali's. Install prints a `warn` line when that happens.
- **One build of a tool per machine**, shared by every unfinished box that uses it. A box that already has another build has to `tool remove` first.
- **At `finish`**, the tools this box installed are removed unless another unfinished box still uses them. For a tool that writes to your home folder, the manifest lists the paths. Before the archive is made, `finish` copies that data into the box, and it deletes it afterwards only if it did not exist before the install and was copied in full; a path that could not be copied in full is kept, with a warning. A copy already in the box from an earlier install is kept beside the new one. `tool remove` by the last box that uses a tool does the same with its data. `finish` refuses while one of the box's tools is running, and names it.
- **`export`** copies tool data into the box and removes nothing. **`import`**, and reopening a finished box, offer to install the box's tools again, at the same builds and checked against the SHA-256 the box recorded. A tool that requires a runtime comes back with it: the one already on the machine, at any build, or the latest in the index. When that is not the build the box recorded, a line says so.

### Tool history

`box.toml` keeps every tool the box has had. `tool remove` marks the tool's line with the time it was removed and keeps it; `finish` marks nothing, so a finished box still offers its tools when it is opened again. `tool history` lists them all:

```
forest/dc01 > tool history
tool       version    installed          removed            runtime
kerbrute   1.0.3-1    2026-11-15 14:20   2026-11-15 15:02   -
certipy    5.1.0-3    2026-11-15 14:32   -                  python-3.13 3.13.18-1
```

That is the shape of the output, not a recorded run. A tool installed again at the same build, when its line is current, keeps that line with the latest install's time.

`~/pwn-broker/tools.log` spans every box: one line each time a box installs a tool, removes it with `tool remove`, or takes it off at `finish`. Each line holds, in order, the time, the event (`install`, `remove` or `finish`), the box's name and ID, the tool's name with its version and build, and the package's SHA-256. A runtime's lines end in `runtime`. Removals by the launch checks are not logged. The app only ever adds to the file, never reads it back, and keeps it readable only by you (mode 600). It follows the `home` setting, so removing or reinstalling the app does not lose it. If it cannot be written, the app warns once a session and the install or removal goes ahead.

### The tools index

`tools_index` in `config.toml` says where the index is. It is a URL, or a folder on disk. In a folder, the index is `index.toml` and each zip is looked for by the `file` name the index gives, in the same folder; the `url` field is not used. A leading `~` is expanded.

```toml
tools_index = "~/pwn-shop/dist"
```

The app keeps a copy of a downloaded index in `/opt/pwn-broker/cache/`, refreshes it when it is more than a day old and the source answers within two seconds, and otherwise uses what it has. `tool refresh` fetches it now. With no index and no cached copy, every `tool` command prints one `fail` line that says where it looked and how to set `tools_index`.

## Tested on

- The unit tests, on Windows 11 with Python 3.13 (the development machine, at commit 7e4c293): 2690 passed, 71 skipped, with warnings treated as errors. The skips are the tests that need Linux (symlinks, named pipes, file modes, ownership, inodes, `/proc`, signals, the installer's tests that need real links and file modes, virtual environments and launchers, the recorded shell's startup files) and the three tests of the real asciinema (the zsh session, the bash session and its version), which run in CI's `recording` and `kali` jobs.
- The unit tests, on Ubuntu 24.04 in CI with Python 3.11, 3.12, 3.13 and 3.14, and again as root on 3.13 (the `test-root` job). On Linux they include real tool installs into a virtual environment and the launchers. The `/etc/hosts` code is tested there against a file in a temporary folder, as root and as a normal user, including that the lines that are not the app's survive. On each of 3.11, 3.12, 3.13 and 3.14: 2753 passed, 8 skipped; as root on 3.13: 2752 passed, 9 skipped; with warnings treated as errors. This is GitHub Actions run 43783899615 on the `release-file` branch, commit d7c31ea, in which every job passed.
- The release file, in CI's `release-file` job on Ubuntu 24.04: built twice, and the two files were byte-identical. `pwn-broker-0.1.0-linux-x86_64.tar.gz` was 46,657,018 bytes (about 47 MB), `gzip -t` and `tar -xzf` accept it, and it holds 11 things, each with a licence text and a source address: Python, asciinema, pwn-broker and eight dependencies.
- The installer, in CI's `installer` job: `sh -n`, `dash -n` and shellcheck pass on `install.sh` and `.github/scripts/kali-cycle.sh`. The release file was installed twice into a temporary install folder and home. `pwn-broker --version` printed `pwn-broker 0.1.0`; `app/bin/python` is Python 3.13.18 and resolves to `python/bin/python3.13` in the install folder; `app/bin/asciinema --version` printed `asciinema 3.2.1`; `bin/record --help` printed `usage: record [target]`; the second run printed `PATH line already in` and left one PATH line.
- That an install needs neither Python nor the network, in the same job: inside `debian:stable-slim` started with `--network none`, where the only network interface was `lo` and no `python` or `python3` was on PATH or in `/usr/bin` or `/usr/local/bin`, `sh install.sh --from <file>` ran to its last line as root, and `pwn-broker --version` and `asciinema --version` worked.
- The installer's own tests (`tests/test_install_sh.py`), under `sh` and `dash`, against a stand-in release file: a full install, an upgrade that keeps `config.toml`, `tools/`, `run/` and a box folder, every refusal with the install folder unchanged, and a failed or interrupted upgrade (a failing step, TERM, HUP, a second signal) that puts the previous install back.
- One whole box in the official Kali image (`kalilinux/kali-rolling`, Kali 2026.3 at the time, with Python 3.14.10, zsh 5.9.2 and OpenVPN 2.7.8), as root, in CI's `kali` job. After the packages were installed with the network on, the container was taken off its only network (`docker inspect` showed none; inside, only `lo`, `github.com` did not resolve, a connection to 1.1.1.1:443 failed). With the network off, `sh install.sh --from` the release file printed every `ok` line: the app's Python was 3.13.18 at `/opt/pwn-broker/python/bin/python3.13` while Kali's was 3.14.10 at `/usr/bin/python3.14`, and root's `.zshrc` was Kali's own plus the one PATH line. The network was connected again, then the unit suite ran on Kali's own Python with the installed asciinema (2759 passed, 2 skipped, warnings treated as errors) and the whole box cycle ran on the app's bundled Python and ended with status 0. The cycle is a new box, the `/etc/hosts` line written and later removed byte for byte, a ping, the note window in vim, a credential, a hostname added later, a recording under Kali's own zsh settings with the `[rec dc01]` prefix and its text copy, `export` while recording, `replay`, `vpn start` and `vpn stop` with a real OpenVPN and `tun0`, a tool installed and removed, a Python test tool on a test runtime package around the pinned upstream CPython 3.13 build, which it downloads and checks first: the tool runs on 3.13 from the runtime, which `finish` removes and `import` puts back, `finish`, and `import`, which puts the line and the tools back. It was 19 steps on the bundled Python. Most steps are checked on disk or in the system, not only in what the app prints; `replay` and `status` are checked by their output. Stand-ins: a virtual display with `xterm` for the desktop, the container's gateway as the target, an OpenVPN file with no server behind it, and two small test packages for the tools. The real upstream Python archive passed the app's unpacking rules there.
- The pinned asciinema, in CI's `recording` job on Ubuntu 24.04: the job installs the release file, and the three real-asciinema tests pass against the installed `app/bin/asciinema`. `record` records a real bash session and a real zsh session through a pseudo-terminal, and the test checks the `[rec dc01]` prefix, the recording marker, the `.cast` header and the text copy. Both sessions are recorded, and both show that asciinema writes the recording to disk as it happens, not at the end.
- The seven packages in `pwn-shop`, in its CI on `main` (run 43772170454): the six tools and the `python-3.13` runtime. Its `packages` job, on Ubuntu 24.04, built the runtime and build 3 of `certipy` and `targetedkerberoast`, downloaded the four packages already published and rebuilt each to the same bytes, and installed all seven through this app's own code under Python 3.12, 3.13 and 3.14, then started each tool's commands. Its `kali` job, in the official Kali image (Kali 2026.3, Python 3.14.8) with the container's network confirmed off, installed the runtime and all six tools through this app's own code and started each tool. The run then published the runtime and build 3 of `certipy` and `targetedkerberoast`. Builds 1 and 2 of those two were withdrawn afterwards, so every package has exactly one published build.
- The published index, on Windows 11 on 2026-11-15, the day both repositories became public: with no `tools_index` setting, the app's own code loaded the index from `pwn-shop`'s release and downloaded `certipy` 5.1.0 build 3 and the `python-3.13` runtime, and each matched the size and SHA-256 the index gives. Nothing was installed there.
- The vimrc, run by Vim 9.2 in headless mode on a note the app wrote: folds, fold text, `F8`, colours, settings, and the reload after the app changes the note. Timers and focus events do not fire in that mode, so the tests run the check by hand.
- *Not* tested: the release workflow (`.github/workflows/release.yml`). It has never run, and no release exists, so the installer's download path (`curl ... | sh` with no `--from`) has never run against a real release; only against a stand-in in the unit tests. The one-line install cannot work until `v0.1.0` is tagged.
- *Not* tested: an upgrade from an install made by the old installer (an environment on Kali's own Python) to a release file, on a real machine. The unit tests cover an `app/` with `pyvenv.cfg` being replaced.
- *Not* tested: a real Kali desktop session and its terminal. The Kali run used a virtual display and `xterm`, so the window manager, focus and the terminal Kali opens by default have not been tried. Nor has your own VM.
- *Not* tested: a normal user. The Kali run is root, so `sudo` for `/etc/hosts` and OpenVPN has not run, and neither has the installer's own `sudo` step.
- *Not* tested: a real Hack The Box connection. The OpenVPN file in the Kali run has no server behind it.
- *Not* tested: a real tool package used by hand. `pwn-shop`'s CI installed and started each one on Kali, in a container. None has been run on a Kali desktop, against a real target, or by a normal user with `sudo`.

## Known issues

- The recording, `/etc/hosts`, VPN and ping part has run on Kali only as root, in a container, with a virtual display and an OpenVPN file with no server. The checks still to run by hand are in `docs/kali-checks.md`.
- A window still recording has no text copy until it closes or the box is exported.
- A full-screen program (vim, less, a menu) appears only in the `.cast`. The text copy has one line saying when it ran.
- A password typed on a command line in a recorded window is recorded, and goes into the archive. One typed at a hidden prompt is not.
- The `[rec]` prefix is for zsh and bash only. Any other shell records without it.
- `finish` refuses while a window is recording for the box. Exit those windows first.
- Only `tun` interfaces count as a VPN, and there is no setting for it.
- Only OpenVPN files can be started, and the app keeps track of one VPN at a time: `vpn stop` before starting another file.
- An archive holds no copy of the VPN file, only its name and SHA-256. Keep the `.ovpn` file yourself.
- A tunnel the app did not start is never stopped by it, at `vpn stop` or at `finish`.
- Ctrl-C while `vpn start` waits for OpenVPN to write its process ID can leave an OpenVPN running that the app does not track. `vpn stop` calls it a tunnel not started by pwn-broker; stop it by hand.
- Starting a second tunnel while one the app did not start is up is reported as not up after 15 seconds, because the app reads only the lowest-numbered tunnel.
- `quit` leaves the box's `/etc/hosts` lines in place. Only `finish` removes them; until then the hostnames go on resolving to the box's targets.
- Lines in `/etc/hosts` that are not the app's are never changed. One that names the same host with another address has to be removed by hand; the `warn` line gives its number and the command to run after.
- `tool install` from the published index has not been run on Kali. CI installs every package from a folder, with the network off. From the published address, the app's own download code has fetched the index and two packages (`certipy` build 3 and the `python-3.13` runtime) and checked each against the index, on Windows (see Tested on).
- Builds 1 and 2 of the two Python tool packages, `certipy` and `targetedkerberoast`, were withdrawn on 2026-11-15, before any box had used them. Build 3 of each, which requires the `python-3.13` runtime, is the only one published. The other four tools need no Python. A tool that still runs on Kali's own Python says so if Kali's Python cannot make its environment; none is published.
- A runtime carries its own OpenSSL and other libraries. They are fixed when a new build of the runtime is published, not when Kali updates. The first tool that requires one costs a download the app shows as 34 MB, about 100 MB unpacked, and the zip kept in the download cache.
- After `finish` removes the working folder, the note window stays open on a file that no longer exists. Close it by hand.
- Stop a tool before you type `finish`. `finish` refuses while one of the box's tools is running, but a tool started after that check can write into its home folder while the box is being archived, and those files are deleted without being copied.
- Tool data that could not be copied into the box in full is left in the home folder with a `warn` line. A later install of the same tool treats it as having been there before, so it is never copied or deleted again. Move it yourself.
- Within one install of a tool, a second `export` or `finish` replaces the box's copy of that tool's data with the current one. Files the tool deleted in between are only in the earlier archive.
- If `tools/installed.toml` is damaged, `finish` stops and names it. Moving it aside makes the next launch offer to remove every tool's files as leftovers; say yes and install the tools again.
- Run as a normal user, the app cannot read root's home folder. Data a tool wrote there under `sudo` is not copied or deleted; `finish` prints a `warn` line saying so.
- No release has been published, so the `curl` install line does not work until `v0.1.0` is tagged. To install now, build a release file from a checkout, as above.
- The app's own Python and OpenSSL are fixed when a release is made, not when Kali updates, and the app takes about 100 MB more on disk. A release is x86_64 with glibc only.
- After a killed or interrupted install, `/opt/pwn-broker/.install.<random>` can be left behind, and it may hold the previous install.
- `cred list` marks a secret it cannot show exactly (a tab, another control character, or a space at either end) with `*` after the number. `cred show` prints it unchanged.
- Links and special files (named pipes, sockets, devices) in a box are not archived. `export` and `finish` list them, and `finish` says how many will go when the folder is removed.

## Configuration

`/opt/pwn-broker/config.toml`, optional. Without it everything uses the defaults. The installer takes `--config <path>` to copy one in.

| Setting | Default | Meaning |
|---|---|---|
| `home` | `~/pwn-broker` | Where `active/`, `wrapped/` and `tools.log` live |
| `copy_to` | not set | A second folder every finished archive and export is also copied to |
| `default_platform` | `htb` | Platform used when a box is created |
| `terminal` | `x-terminal-emulator` | What opens the note window |
| `check_updates` | `true` | Look for a newer release at launch |
| `tools_index` | the published index in `pwn-shop` | A URL, or a folder that holds `index.toml` and the zips it names |

## License

MIT
