# pwn-broker guide

How pwn-broker works, command by command. The [README](../README.md) is the short version, and [tested.md](tested.md) is what has been run and where.

## Install and upgrade

```sh
curl -fsSL https://github.com/Real-Fruit-Snacks/pwn-broker/releases/latest/download/install.sh | sh
```

For a release file already on the machine:

```sh
sh install.sh --from pwn-broker-0.1.14-linux-x86_64.tar.gz
```

Run the installer as the user who will use pwn-broker, not with `sudo`. It asks no questions. It creates `/opt/pwn-broker` and gives it to you, using `sudo` for that only, and only when it cannot create the folder itself. It then unpacks the release's own Python into `python/`, makes a virtual environment in `app/` with that Python, and installs the app and its dependencies there from the wheels in the release file. It copies asciinema into `app/bin/`, runs the app's `setup`, and adds `/opt/pwn-broker/bin` to PATH in `~/.zshrc` and, if it exists, `~/.bashrc`. Nothing goes into the system Python. If the PATH line cannot be written, the install is kept and one `fail` line says to add `bin/` to PATH yourself.

| Option | Does |
|---|---|
| `--from <file>` | Install from a release file on disk instead of the latest release |
| `--config <path>` | Copy a settings file to `/opt/pwn-broker/config.toml` |
| `--no-path` | Leave the shell config files alone |
| `--help` | Show the options |

Set `PWN_BROKER_OPT` to an absolute path to install somewhere other than `/opt/pwn-broker`. A relative path, a path with a `.` or `..` part, and any path that is `/` itself, such as `//`, are refused. `--from` takes a release file only: a checkout (`--from .`) and a wheel are refused.

### What an install needs

- `sh`, `tar`, `gzip` and `sha256sum`, and `curl` when it is not given `--from`. It needs no `python3`, no `python3-venv`, and contacts neither PyPI nor asciinema's releases.
- x86_64 Linux with glibc. On any other machine it stops and says so.
- About 100 MB more on disk than the app alone, for the Python.

The app's Python and its OpenSSL are fixed when a release is made, not when Kali updates. A new Kali Python cannot break the app, and a fix to the app's Python reaches you only in a new release.

### Upgrading

Run the installer again. An install over an existing one replaces `python/` and `app/` and nothing else; `config.toml`, `tools/`, `run/` and your boxes stay. If it fails or is interrupted, the previous `python/` and `app/` are put back. If the app's `setup` had already started, the launchers in `bin/` and the vim and template files it may have rewritten stay as the new release wrote them.

- Close pwn-broker before you run the installer. It replaces `app/` and `python/` under a running prompt, and does not check whether one is open.
- It replaces a `python/` only if it holds the empty marker `.pwn-broker` that the installer writes into its own, and an `app/` only if it holds `pyvenv.cfg`. Otherwise it stops with `fail  /opt/pwn-broker/python exists and is not a pwn-broker Python. move it or choose another folder`, or for `app/` with `fail  /opt/pwn-broker/app exists and is not a pwn-broker environment. move it or choose another folder`.
- It refuses an `/opt/pwn-broker` that belongs to another user, for example one made as `kali` when you now run it as root. Move that folder aside (`mv /opt/pwn-broker /opt/pwn-broker.old`) or run the installer as that user.
- It works in `/opt/pwn-broker/.install.<random>` and removes it at the end. After a kill or a power cut that folder can be left behind, and it may hold the previous install.

The launchers, `pwn-broker` and `record`, start Python with `-I`, so a file in the folder you start the app from cannot be loaded in place of one of the app's modules. An existing install gets them at its next install.

### What a release holds

A release is one file, `pwn-broker-<version>-linux-x86_64.tar.gz`, about 47 MB. It holds the upstream CPython 3.13.18 build from python-build-standalone byte for byte, the wheel of the app and of each of its eight dependencies, `wheels.lock` pinning each wheel by SHA-256, the pinned asciinema 3.2.1, and `licences/`: a licence text and the address of the exact source for each of the 11 things in it. A release publishes three files: the release file, `SHA256SUMS.txt` and `install.sh`.

### What is trusted

The release file. Downloaded, it is checked against `SHA256SUMS.txt` before anything is installed. `SHA256SUMS.txt` comes from the same release, so that catches a corrupted download; it does not prove who published the release. With `--from` the installer prints the file's SHA-256 (`ok    release file <name>, SHA-256 <hex>`) for you to compare with the release page. The wheels are checked by `pip` against `wheels.lock`, with no index, wheels only and every hash required. asciinema is checked by `setup` against the pin in the app. The Python inside the file is not checked again; it was checked against `release/pins.toml` when the release was built.

### What reaches out, and to where

| When | What | Where |
|---|---|---|
| Install without `--from` | The release file and its checksum | This repository's release |
| `tool install` | Packages and the index | `pwn-shop`'s releases, or a folder on disk |
| A new box, when new boxes get the playbooks | The playbooks and the index | `pwn-shop`'s releases, or a folder on disk |
| A new box, when new boxes get the report tool | The report tool, its runtime and the index | `pwn-shop`'s releases, or a folder on disk |
| Launch | Whether a newer release exists | This repository's releases; `check_updates = false` turns it off |

Nothing else, apart from a ping to each new target's first IP and OpenVPN when you start it. With `--from` and a folder for `tools_index`, the install, the tool commands and a new box's playbooks and report tool contact nothing. The report `finish` builds contacts nothing either: pwn-report reads the archive on disk and writes the report beside it.

### asciinema

asciinema is the static x86_64 Linux build, and it is always in the release file. It goes in `/opt/pwn-broker/app/bin/`, which is not on PATH, so Kali's own `asciinema`, if there is one, is untouched. If it is missing or does not match its pin, `setup` fails and so does the installer, and the previous `python/` and `app/` are put back. If it goes missing later, every launch prints the `asciinema` `warn` line and says to run the installer again; nothing is downloaded. asciinema is GPL-3.0-or-later and is not in this repository; the release file carries its licence text and the address of its source.

### Building a release file from a checkout

On x86_64 Linux. The build downloads the pinned inputs, refuses any that does not match its size or SHA-256, and prints `ok    wrote <path> (<n> bytes, SHA-256 <hex>)`:

```sh
git clone https://github.com/Real-Fruit-Snacks/pwn-broker.git
cd pwn-broker
python3 -m venv .venv && .venv/bin/pip install -e . && .venv/bin/python release/build.py
sh install.sh --from dist/pwn-broker-0.1.14-linux-x86_64.tar.gz
```

The `git clone` line needs `git` and the `python3 -m venv` line needs `python3-venv` (`apt install python3-venv git`); installing the app needs neither. That `.venv` is the build machine's own environment and its dependencies are not pinned; what goes into the release file is. `release/build.py` makes its own build environment with the Python it packs. [CONTRIBUTING.md](../CONTRIBUTING.md#building-a-release-file) has the build's options.

## The launch and the prompt

```
pwn-broker                 open the menu, or the box you are inside
pwn-broker new             start a new box
pwn-broker import <file>   unpack an exported box
pwn-broker resume [name]   reopen an active box
record [target]            record this terminal window for a target of the open box
```

Launch prints `pwn-broker <version>` and runs its checks: vim, the terminal, tar, a desktop session, PATH, the box folders, asciinema and the VPN, and whether a newer release exists unless `check_updates` is off. Then it offers a new box, an import, any active box to resume, or a finished box that is still on disk to reopen. Started inside an active box's folder, it opens that box. Only one box is open at a time.

pwn-broker is for Kali Linux with a desktop session, run by the user who installed it. Started as anyone else, it prints `fail  pwn-broker was installed by <user>; run it as <user>` and exits with status 1. `record` refuses the same way, with `fail  record must run as <user>, the user who installed pwn-broker. run record first, then sudo inside it`.

`setup` and the launch make `~/pwn-broker/active` and `wrapped` without asking; the `folders` check speaks only when it cannot make them.

Everything the app prints is indented two spaces, apart from the prompt line, the launch header, headings, `setup`'s lines and output meant to be copied. What each command prints has one blank line above it and one below. Every status line starts with `ok`, `warn` or `fail`, so it reads without colour.

- A yes or no question takes `y`, `yes`, `n`, `no`, or Enter for its default, in any case. Anything else gets `fail  answer y or n` and the question again.
- A wrong argument gets the command's usage under the `fail` line, such as `usage: target rename <target>`.
- On a terminal, the one column a table names is cut to fit and ends in `...`; piped output is whole.
- A control character in a value the app prints (a hostname, a credential, a line of OpenVPN's log) is shown as `?`, so it cannot move the cursor or change the terminal. A tab stays a tab, except in a table cell, where it is a space. `cred show` and `path` print the value exactly.

## Every command

| Command | Does |
|---|---|
| `check` | Run the setup checks again |
| `clear` | Clear the screen |
| `cred add` | Save a credential |
| `cred clear <n> <field>` | Empty a credential's secret or note |
| `cred edit <n>` | Change a credential |
| `cred import <file>` | Add usernames from a file, one per line |
| `cred list` | List the credentials |
| `cred remove <n>` | Delete a credential |
| `cred show <n>` | Print one secret and nothing else |
| `cred works <n> [<target>...]` | Record where a credential works |
| `exit` | Leave the shell, as `quit` does |
| `export` | Write a snapshot archive and keep working |
| `files [<target>]` | List the files saved for a target or the whole box |
| `finish` | Archive the box and close it |
| `flag root` | Record the root flag |
| `flag user` | Record the user flag |
| `help` | List the commands |
| `host` | List every hostname in the box and whether it is in `/etc/hosts` |
| `host add <hostname>...` | Add hostnames to the current target |
| `host file` | List the `host file` commands |
| `host file off [<target>]` | Take a target's line out of `/etc/hosts` and forget it |
| `host file on [<target>]` | Put a target's line into `/etc/hosts` |
| `host remove <hostname>...` | Take hostnames off the current target |
| `note` | Open the note in vim |
| `path [<folder>]` | Print a folder's full path |
| `playbook list [<word>...]` | List the box's playbooks; words narrow the list |
| `playbook show <name>` | Print a playbook in the terminal, without its run block |
| `quit` | Leave the shell |
| `replay [<target>] [<n>]` | List a target's recordings, or play one |
| `scan [quick\|full\|udp]` | Run nmap on the current target in the background |
| `scan log` | Show the last 20 lines of the current target's scan |
| `scan stop` | Stop the current target's scan |
| `search [all\|<target>] <text>` | Find text in the current target, another, or the whole box |
| `serve [<interface or address>] [<port>]` | Offer the target's upload folder and the tools' files over HTTP |
| `serve files [<word>]` | Show the download line for each file served |
| `serve log` | Show the last 20 requests and server lines |
| `serve stop` | Stop serving files |
| `status` | Show the box at a glance |
| `target add` | Add a target to this box |
| `target edit <target>` | Change a target's addresses or scope |
| `target list` | List the targets |
| `target remove <target>` | Remove an empty target |
| `target rename <target>` | Rename a target and its folder |
| `target show [<target>]` | Show one target |
| `target use <target>` | Switch to a target |
| `tool cache clear` | Empty the download cache |
| `tool doctor <name>` | Show a tool's dependencies, backend commands and enabled features without changing anything |
| `tool history` | List every tool this box has had, removed ones too |
| `tool info <name>` | Show a tool's details, how to run it and its examples |
| `tool install <name>[@<version>[-<build>]] [--full]` | Install a tool and its dependencies; `--full` selects its optional backends |
| `tool list [--installed]` | List the tools in the index; `--installed` shows this box's |
| `tool refresh` | Fetch the tool index now |
| `tool remove <name>` | Take a tool off this box |
| `tool search <word>...` | Search the index by name, description or tag |
| `vpn log` | Show the last 20 lines of OpenVPN's log |
| `vpn start` | Copy a `.ovpn` file into the box and start OpenVPN |
| `vpn status` | Whether a tunnel is up, and which box started it |
| `vpn stop` | Stop the VPN pwn-broker started |

## Boxes and targets

A box lives in `~/pwn-broker/active/<date>_<platform>_<name>/`. A second box with the same name and platform on the same day, while the first one's folder or one of its archives is still there, gets `-2` on the end, and its archives too, so one box's archive is never offered to another for replacing.

```
box.toml              identity, status, dates, flags, targets with an /etc/hosts line, VPNs and tools used
creds.toml            one credential list for the whole box
files.toml            a record of every file in the box, with its SHA-256
notes.md
lists/                usernames, passwords, pairs, hashes, IPs and hostnames
screenshots/
vpn/                  copies of the .ovpn files vpn start used; never archived
targets/
  dc01/
    target.toml       IPs, hostnames, scope
    creds/  files/  loot/  scans/  exploits/  screenshots/  recordings/  upload/
```

Only the app writes `box.toml`, `files.toml` and the rest of the metadata. `finish` and `export` write archives to `~/pwn-broker/wrapped/`. `~/pwn-broker/tools.log` records every tool each box installed and took off ([below](#the-tool-log)).

### Ping

Each new target with an IP is pinged once at its first IP, with a two-second wait, wherever it was added: `ok    10.10.10.161 answered in 43 ms`, or a `warn` line that it did not answer, since Windows targets often do not. Ctrl-C cancels the ping and nothing else. With no `ping` on the machine, the app says once per session that it did not check.

## The note

`notes.md` starts with a box drawn in `#` that holds the box details and one row per target, and the app redraws it whenever the targets change. Below it, each target has a section wrapped in a vim fold that starts with its `Target:` line, and the note opens with every fold closed down to that line. `F8` in vim adds an empty fold below the cursor, and `,h` lists the note's keys in a small window that any key closes. `,t` puts the date and time after the cursor, `,i` the IP of the target whose section the cursor is in, and `,c` offers the box's `user:password` and `user:hash` pairs from `lists/` in a numbered list and puts the one you pick in, exactly as it is. `,x` ticks or unticks the first `[ ]` or `[x]` on the line, and `:Pb <name>` reads one of the box's [playbooks](#playbooks) in below the cursor. The app changes nothing else in the note, apart from a `Target:` line it wrote when that target is renamed or edited.

The note opens in a second terminal, the `terminal` setting, which runs vim with the app's own vimrc. Without a desktop session the `display` check says how to run that vim by hand.

A box has one note window. While its vim is running, opening the box, importing it or `note` prints `ok    the note is already open` and opens no other. The app finds that vim by reading `/proc`, so this holds on Linux only. When `finish` removes the working folder it closes the note's vim, and the terminal window that was started only to run it, unless that terminal still runs something else, such as a shell in another of its windows. It keeps the folder, with a `warn` line, when the note has unsaved changes, has changed since the archive was made, or its window did not close.

## Credentials

A credential is kept exactly as typed, in `creds.toml`: no trimming, quoting or escaping on the way in or out. `cred list` marks a secret it cannot show exactly (a tab, another control character, or a space at either end) with `*` after the number, and cuts a long one to fit, ending in `...`. `cred show <n>` prints the whole secret, unchanged, and nothing else.

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

Edits made by hand to these files are overwritten at the next rebuild. The credentials are not encrypted: treat a box folder, its archives and its exports like the credentials they hold.

## The hosts file

A target with an IP and a hostname can have one line in `/etc/hosts`, its first IP and all its hostnames, marked with the box ID:

```
10.10.10.161 forest.htb.local  # pwn-broker 6f9c1e0a-52c1-4b7e-9d0c-1a2b3c4d5e6f
```

`target add` (at launch, in the prompt or from `record`) and `target edit` ask `add dc01's hostnames to /etc/hosts? [Y/n]` when the target has both and no line yet. The default is yes. After that the line follows the target: `target edit`, `host add` and `host remove` rewrite it without asking, `target remove` takes it out, and `finish` removes the box's lines after the archive is verified. `quit` leaves them in place. Opening a box puts its lines back if they are missing. `import` asks first, since the names come from the archive: it shows the lines and asks `this box wants these lines in /etc/hosts. add them? [y/N]`, naming any hostname that is not under a lab domain such as `.htb` or `.local` (`(not a lab name: github.com)`). On no, the box keeps no lines until you add one with `host file on`. At launch, lines left by a box that is finished or no longer on disk are offered for removal.

```
forest/web01 > host add crm.board.htb dev.board.htb

  ok    web01 now answers to 3 names
  ok    /etc/hosts updated
        10.10.11.5 board.htb crm.board.htb dev.board.htb
```

- Only the app's marked lines are ever changed. Every other line is written back byte for byte, except that a line break is added before the app's line when the file does not end with one. The file is written in place, not replaced, so its owner and mode stay.
- Just before writing, the file is read again; if another program changed it, the app starts over once, then gives up with a `warn` line.
- As root the app writes the file directly. As a normal user it writes the new content under `/opt/pwn-broker/run` and copies it into place with `sudo cp`. If that fails, nothing is changed and the line is printed for you to add.
- A hostname already on an unmarked line, one that is not the app's, with the same IP is left off, and the app says it already resolves. With a different IP it is left off too, and the `warn` line shows that line, its number and the `host file on` command to run once you have removed it yourself.
- A hostname on another of your boxes' lines takes that line out, with a `warn` naming the box; it comes back when that box is opened.
- Only a plain hostname is written: letters, digits, hyphens and dots, 253 characters at most. If `/etc/hosts` is missing, a link or not a regular file, nothing is written and the app says why.

## Recording

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
- Only what the terminal shows is recorded, never keystrokes. A password typed at a hidden prompt is not recorded; one typed on a command line is, and goes into the archive.
- In zsh and bash the prompt starts with `[rec dc01]` while recording. The shell starts from a small startup file of the app's that loads your own first, then adds the prefix. Any other shell records without it.
- Each window gets its own file, named by its start time to the minute, with `-2`, `-3` and so on when that name is taken. `record` inside a window that is already recording refuses and names its target. With no box open it records nothing and exits with status 1. Run through `sudo` by a normal user, it refuses: run `record` first, then `sudo` inside it.

### The text copy

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

Every line of text starts with the time its last character was drawn; an empty line and a `---- <date> ----` line have no time. The app replays the `.cast` through a terminal model (`pyte`) at the recorded size. Colours and control sequences are dropped, a line redrawn in place appears once as it last stood, a wrapped line is joined back into one, and a full-screen program (vim, less, a menu) is one line saying when it ran; the `.cast` holds it.

The text is written when the window closes, so a window still recording has none until then. `export`, `finish` and `replay` write it for any recording whose text is missing or older than its `.cast`, so a window that was killed still gets one. A `.cast` whose first line cannot be read gets a `warn` line naming it and no text. One that fails further in, at a bad line or on output the terminal model cannot handle, gets a `warn` line and a text copy that says why. One that takes longer to render than 60 seconds for each megabyte of it and up to 10 seconds more from a minute that all the recordings one `export`, `finish` or `replay` writes share (`record` gives its own recording the whole minute) gets a `warn` line too, and a text copy that says it took too long; `replay` still plays it. Neither is tried again until its `.cast` changes: delete that text copy to try again. One that already has a text copy, from an `export` while its window recorded for instance, keeps it, with a last line saying where it stops, and the `warn` line says it is not up to date. Once the shared minute is spent, the first recording that runs out of time or fails ends the rendering, and a `warn` line says how many are left for the next time.

### Replay, and the other commands

`replay` lists the current target's recordings, or a named target's, oldest first, with when each started, its length and size, or `recording now`. `replay <n>` (or `replay <target> <n>`) plays one in the prompt window with the pinned asciinema, idle gaps cut to two seconds; Ctrl-C stops it and returns to the prompt. A recording still being recorded cannot be played until its window exits.

`finish` refuses while a window is recording for the box and names the targets. `export` goes ahead with a `warn` line, and packs a recording still being written up to its last whole line. `quit` warns, and the window keeps recording into the box. `status` has a `recordings` line, and the status bar shows `rec 2` while two windows are recording.

## VPN

The `vpn` launch check prints a `warn` line when no interface named `tun<n>` has an IPv4 address, and never stops the launch. With several, the lowest-numbered one is used. Only `tun` interfaces count, and there is no setting for it. The status bar shows `vpn 10.10.14.7` or `no vpn`; `status` has a `vpn` line that reads `10.10.14.7 on tun0` or `not up`; and `{lhost}` in `tool info` examples is filled from it.

```
forest > vpn start

  vpn file     [/home/kali/Downloads/lab_user.ovpn] >
  ok    copied to vpn/lab_user.ovpn
  ok    vpn up, 10.10.14.7 on tun0
```

- The question takes a path, with Tab completing it, and defaults to the file used last time on any box. The file is copied into the box's `vpn/` folder, mode 600; a copy of the same name and content is reused, and different content gets `-2`, `-3` and so on. A file over 1 MiB is refused.
- Only OpenVPN files can be started. OpenVPN runs in its own background mode, as root directly or through `sudo` for a normal user, in the original file's folder so a certificate or key named beside it is found. The file's own `up` and `down` scripts, if it has any, run as root, as they would if you ran `openvpn` yourself; start only a file you trust.
- What the running VPN needs lives in `/opt/pwn-broker/run/vpn/`, not in the box, so closing a window or quitting the prompt does not end it, and it outlives the box that started it.
- `vpn start` waits up to 15 seconds for the tunnel. If OpenVPN ends first, it says so and prints the last lines of the log; if it is still trying, it says so and names `vpn log`.
- The app keeps track of one VPN at a time. If its own VPN is already up, `vpn start` says so, starts nothing, and records that this box used it: `vpn stop` first to change files. If a tunnel is up that the app did not start, it asks `start another? [y/N]`.
- `vpn stop` signals only the process the app started, checked by its process ID, its start time and its name, `openvpn`. A tunnel you started by hand is reported and never touched, at `vpn stop` or at `finish`.
- `box.toml` records each VPN the box started or used: the file's name, its SHA-256 and when. The `vpn/` folder is left out of `files.toml`, the manifest and every archive, because the file holds your VPN key; keep the `.ovpn` file yourself. `import` restores the record and starts nothing. At `finish`, if the app's VPN is still up, it asks whether to stop it; the default keeps it for the next box.

## Tools

`tool install <name>` puts a tool on the machine for this box, and `finish` takes it off again. The packages are published in a second repository, [`Real-Fruit-Snacks/pwn-shop`](https://github.com/Real-Fruit-Snacks/pwn-shop), which [lists every one](https://github.com/Real-Fruit-Snacks/pwn-shop/blob/main/docs/PACKAGES.md#whats-in-it) with its version: Active Directory tools such as NetExec, Impacket, Certipy and Rubeus, PEASS-ng and pspy, the potatoes, ligolo-ng and chisel, and the `python-3.13` runtime the Python tools run on. With no setting, the app reads that repository's published index. To work with no network, fill a folder with `sh fetch.sh <folder>` in a clone of it and point `tools_index` at the folder.

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

Those are the shape of the output, not recorded runs. The runtime's size is its zip in mebibytes, rounded. If the tool then cannot be installed, the runtime it brought is removed again, with `ok    python-3.13 3.13.18 removed (runtime)` before the line that says why.

### What a package is

A package is one zip for one build of one tool: a manifest, the upstream licence, the tool's own files exactly as upstream published them, and, for a Python tool, every dependency as a wheel with its SHA-256 recorded. A package holds no install script, and nothing from it runs during install.

- Every download and every cached zip is checked against the size and SHA-256 in the index before it is used. The index itself is not signed, so the check catches corruption and a swapped zip, not who published the index.
- A Python tool gets its own virtual environment, built from the bundled wheels with no network access, wheels only and hash checking on. Its `wheels.lock` is checked line by line before pip reads it.
- The first set of packages is x86_64 only, and a package built for another architecture is refused at install.
- A package's commands may not take a name that must never be stood in for:
    - shells and what starts a program for one: `sh`, `bash`, `dash`, `zsh`, `fish`, `env`
    - what asks for a password or changes who you are: `sudo`, `sudoedit`, `su`, `doas`, `pkexec`, `run0`, `passwd`, `login`, `newgrp`, `visudo`, `ssh`, `scp`, `sftp`, `ssh-agent`, `ssh-add`, `ssh-keygen`, `gpg`
    - Python and pip, under any versioned name too: `python`, `python3`, `python3.13`, `python3.13t`, `pip`, `pip3`
    - what the app runs itself: `chown`, `cp`, `rm`, `kill`, `ip`, `ping`, `tar`, `vim`, `openvpn`, `x-terminal-emulator`, `pwn-broker`, `record`, `asciinema`
    - everyday commands: `sed`, `cut`, `mkdir`, `cat`, `ls`, `mv`, `ln`, `vi`, `grep`, `awk`, `find`, `head`, `tail`, `chmod`, `id`, `uname`, `test`, `whoami`, `hostname`, `sleep`, `touch`, `tee`, `which`, `ps`, `tput`, `dircolors`, `xargs`, `timeout`, `nohup`
    - what other programs start to show or edit something: `less`, `more`, `pager`, `man`, `nano`, `editor`
    - what manages the system or fetches something to run: `apt`, `apt-get`, `dpkg`, `systemctl`, `mount`, `umount`, `curl`, `wget`, `git`

  It is not a list of everything Kali has. A tool may take the name of Kali's own copy of it, and install prints a `warn` line when it does.

### Runtimes

A Python tool can bring its own Python instead of using Kali's. Such a tool requires a runtime: a package of kind `runtime`, such as `python-3.13`, that carries one CPython build from [python-build-standalone](https://github.com/astral-sh/python-build-standalone) byte for byte, and its wheels are built for that Python alone.

- The first tool that requires a runtime installs it; every tool that requires it then shares it, and it is removed with the last of them, at `finish` or `tool remove`. A Kali upgrade to a new Python does not touch a tool on a runtime.
- A runtime puts nothing in `/opt/pwn-broker/bin`, so Kali's `python3` is never shadowed, and `tool list` and `tool search` do not show it; `tool install` and `tool remove` refuse its name. `tool info` shows what a tool requires and whether it is installed.
- Its archive is unpacked by the app itself under strict rules: only regular files, folders and relative links that stay inside the runtime's folder, no backslash, colon or control character in a name, at most 20,000 entries and 1 GiB. A damaged or cut-short archive is refused before anything is written.
- The runtime's interpreter and the `pip` it carries are what run during the install: they make the tool's virtual environment and install the bundled wheels into it, isolated from your shell's settings (`-I`, `pip --isolated`, no `PYTHON*` or `PIP_*` variables, the tool's own folder as the working directory).
- The first such tool on a machine costs the runtime: a download the app shows as 34 MB, about 100 MB unpacked, and the zip, which stays in the download cache until `tool cache clear`. A runtime carries its own OpenSSL and other libraries, fixed when a new build of the runtime is published, not when Kali updates.

Build 3 of `certipy` and `targetedkerberoast` requires a runtime, and is the only build of each that is published: builds 1 and 2 were withdrawn on 2026-11-15, before any box had used them. The tools that are not Python need no Python at all. The app still reads a package that runs on Kali's own Python (schema 1), and such a tool says so if Kali's Python cannot make its environment; none is published.

### Ordinary dependencies and optional backends

Package and index schema 4 adds ordinary tool dependencies and optional external backends. They are separate from Python runtimes: `requires` names runtimes, `depends` names tools that must always be present, and a package's `[[backend]]` entries describe optional features. An index with any schema-4 build needs pwn-broker 0.1.14 or later, including one that also contains schema-3 notes packages.

- **Minimal installs bring only what is required.** `tool install <name>` resolves the ordinary dependency graph first, detects missing targets and cycles, and reuses an installed build that is still pinned by the index. A failed graph is rolled back. Another box using the same tool shares it.
- **`--full` is opt-in.** `tool install <name> --full` additionally selects every optional backend declared by that tool. Package-backed providers are installed from pwn-shop; a dependency's own optional backends are not selected. Repeating a minimal install makes no optional change, while an explicit install of an automatic dependency takes ownership of it.
- **Apt needs a plan and confirmation.** For each apt-backed feature whose command is missing, `--full` shows the provider and the exact `apt-get install --no-install-recommends` command, with `sudo` when needed, before asking. Declining skips those system packages and continues with pwn-shop's packages. Apt failure aborts the install. Apt packages remain system-owned: rollback, `tool remove` and `finish` never remove them. No recipe-supplied installer is run.
- **Orphaned automatic dependencies go; explicit tools stay.** `tool remove` refuses a package that one of the box's installed parents still requires. Removing the parent releases only automatic dependencies no remaining tool needs; explicitly installed packages are kept. `finish` follows the same ownership rule, then removes idle runtimes.
- **Diagnostics are read-only.** `tool doctor <name>` reports runtime and ordinary dependencies, selected package backends, and each optional backend's command, provider and enabled feature. It looks up executables but never runs a backend, installs a package or changes apt state. It uses the box's installed build when present, otherwise the latest index build.

For example, `tool install ad-sweep` brings NetExec and its Python runtime automatically. `tool install cred-spray` installs the tool and runtime without optional backends; `tool install cred-spray --full` selects NetExec from pwn-shop and offers any missing Nmap, FreeRDP, ipmitool and Ruby evil-winrm apt packages for confirmation. `tool doctor cred-spray` shows which of those features is enabled.

### Playbooks

Playbooks are short notes, one per job, that you read into the box's note and fill in. They come from the [pwn-playbooks](https://github.com/Real-Fruit-Snacks/pwn-playbooks) repository as a package of kind `notes`, through the same index as the tools:

```
forest/dc01 > tool install playbooks

  ok    playbooks 2026.11.23 installed (88 playbooks)
  read  :Pb <name>      in the note window
  list  playbook list   at the prompt
```

- **They come and go with the box, like a tool.** `finish` takes them off, the box records which build it had, and reopening or importing it installs that build again. One build is on the machine at a time: while an unfinished box still has an older build, `tool install playbooks` stops and names that box.
- **New boxes can get them as they are made.** The first `pwn-broker new` on a machine asks once the box is made, and keeps the answer in `/opt/pwn-broker/state.toml`. With yes, that box and every later new box get them before the note window opens, as `tool install playbooks` installs them:

  ```
    ok    box forest created

    install playbooks in this box and every new box? [Y/n] > 

    ok    saved: new boxes get the playbooks
          to change it: playbooks = false in /opt/pwn-broker/config.toml
    ok    playbooks 2026.11.23 installed (88 playbooks)
    read  :Pb <name>      in the note window
    list  playbook list   at the prompt
  ```

  Answered `n`, the lines under `saved: new boxes start without playbooks` are `for this box only: tool install playbooks` and `for every new box: playbooks = true in /opt/pwn-broker/config.toml`.

  An install that fails is a `warn` line, `playbooks not installed: <why>`, then `try again with: tool install playbooks`, and the box opens all the same. `playbooks = true` or `false` in `config.toml` decides instead, and then nothing is asked. A box that is resumed, reopened or imported is never asked: it offers the tools it had.
- **`:Pb <name>`** in the note window reads one into the note below the cursor, never into the box at the top, and below a closed fold when the cursor is on one. Tab completes the name from any part of it, so `:Pb serv` finds `06-privesc/windows/services`. `:Pb` on its own lists them all to pick one by number.
- **Each playbook is one fold.** Closed, it shows its `Playbook:` line: its title, its path and the build it came from.
- **Placeholders** are written `<Name>`, such as `<TargetIP>` or `<Username>`, and the note shows them in Ember.

At the prompt, `playbook list` lists the box's playbooks by name, folder and title. Words after it keep only the playbooks with every one of them in the name, the folder or the title, in any case:

```
forest/dc01 > playbook list windows

  name                     folder              title
  always-install-elevated  06-privesc/windows  Windows privesc: AlwaysInstallElevated
  potatoes                 06-privesc/windows  Windows privesc: SeImpersonate and potatoes
  ...
  windows-kernel           06-privesc/windows  Windows privesc: kernel exploits
  port-forwarding          08-pivoting         Port forwarding on Windows
  11 of 88 playbooks in playbooks 2026.11.23; playbook show <name> prints one
```

`playbook show <name>` prints one in the terminal: its `Playbook:` line, then the playbook without its fold markers, run block and `END OF` line. It is flush left, so a command copies cleanly, and its placeholders are left as they are, since only the note fills them in. It takes the name `:Pb` takes, or the playbook's path, such as `02-enum/smb`, and Tab completes the name from any part of it. When two installed packages hold the same name, it names both, and `playbook show <package>/<path>` picks one.

A playbook starts with a run block that fills its placeholders in that playbook only:

```
my
/^\%>'yEND OF smb PLAYBOOK$
mz
:'y,'zs/<TargetIP>/<Replace>/ge
:'y,'zs/<Username>/<Replace>/ge
'y

Fill in:  <TargetIP>  <Username>
```

1. On each replace line, put the value over `<Replace>`: `ca>` on it removes the word and its angle brackets and starts insert mode. Delete with `dd` each replace line you are not filling.
2. On the `my` line, `V}` selects the run block down to its blank line, and `"qy` copies it into register `q`.
3. `@q` runs it: it marks the block's first line `y`, finds this playbook's `END OF` line, marks it `z`, replaces each placeholder between the two, and ends back at the run block.

Afterwards the `Fill in:` line shows the values used, and a placeholder still on it is one not filled yet. The same playbook read in for two targets fills only the copy the block belongs to. Pasting the block from the terminal does not run it: vim inserts pasted text as text, which is why it goes through a register.

- A value holding `/`, `&`, `\` or `~` breaks or changes the replacement unless you escape it (`\/`, `\&`). That matters mostly for passwords.
- A replace line left as `<Replace>` turns that placeholder into `<Replace>` throughout the playbook.
- Marks `y` and `z` are overwritten each time a run block runs.
- The search looks only below the run block (`\%>'y`), so a playbook whose `END OF` line you deleted stops there and changes nothing, even with another copy above it. With another copy of the same playbook below it, the fill runs down to that copy's end, your own lines between included.

### Reports

`tool install report` gets [pwn-report](https://github.com/Real-Fruit-Snacks/pwn-report), the `pwn-report` command, on the `python-3.13` runtime. With it in the box, `finish` builds a report from the finished archive and puts it beside the archive, after the archive is written and copied and before the tools come off:

```
  ok    archive /home/kali/pwn-broker/wrapped/2026-11-23_htb_forest.finished.tar.gz
  report  building beside the archive
  ok    report /home/kali/pwn-broker/wrapped/2026-11-23_htb_forest.finished.report
  ok    report 0.1.0 removed
  ok    python-3.13 3.13.18 removed (runtime)
```

- **What it holds.** `report.md`, with the box, its targets and flags, a timeline from the archive's own records and an index of the evidence, each file with its SHA-256; `report.json` and `report.toml`; a copy of the notes and of the scans, screenshots and exploits, each linked from the index; and `SHA256SUMS`. Loot, recordings and the `files/` and `upload/` folders are indexed but not copied. It is private: it never reads `creds.toml`, `lists/`, a target's `creds/` or `tooldata/`, but it copies the notes and the scans as they are, and they can hold a password you typed. [pwn-report's guide](https://github.com/Real-Fruit-Snacks/pwn-report/blob/main/docs/guide.md) has the rest.
- **`finish`'s summary says first** whether one will be built: `report  will be built beside the archive`, or `report  none: tool install report adds the tool that builds one`.
- **A report is never replaced.** A box finished again after it is reopened or imported puts its report beside the first, as `.report-2`, then `.report-3`.
- **With `copy_to`** set, the report is copied there too, with an `ok    copy <path>` line; a copy that fails is a `warn` line.
- **A report that fails** is a `warn` line, `the report was not built: <why>`, and `finish` goes on; the archive is not touched. pwn-report has 600 seconds: after that it is stopped, any half-made report folder is removed, and the line says it took longer than that. Ctrl-C while it runs stops the report, not the finish.
- **New boxes can get it as they are made**, the way they get the playbooks: after the playbooks' question, the first new box asks `install the report tool in this box and every new box? [Y/n]` and keeps the answer in `/opt/pwn-broker/state.toml`. Answered yes:

  ```
    install the report tool in this box and every new box? [Y/n] >

    ok    saved: new boxes get the report tool
          to change it: report = false in /opt/pwn-broker/config.toml
    ok    python-3.13 3.13.18 installed (runtime, 34 MB)
    ok    report 0.1.0 installed
    run   pwn-report   from any terminal
  ```

  Answered `n`, the lines under `saved: new boxes start without the report tool` are `for this box only: tool install report` and `for every new box: report = true in /opt/pwn-broker/config.toml`. `report = true` or `false` in `config.toml` decides instead, and then nothing is asked. An install that fails is a `warn` line, `report tool not installed: <why>`, then `try again with: tool install report`, and the box opens all the same.
- pwn-broker never imports pwn-report. It runs `/opt/pwn-broker/bin/pwn-report build <archive> -o <folder>`, with no shell and the environment it gives every tool. Status 0 with the folder in place is a report built; anything else is one not built, with pwn-report's own `fail` line as the reason.

### Kali's copies, sudo, and one build per machine

- **Kali's own copies are never touched.** An install writes a launcher for each command into `/opt/pwn-broker/bin`, and that folder decides which copy a bare command name runs. If Kali already has a command of the same name, install prints a `warn` line with its path and says the installed one wins. `tool list` has a `kali` column that says whether Kali already has a command of that name.
- **`sudo` is never reconfigured.** `sudo` does not search your PATH, so a tool that needs root is run as `sudo <full path>`. The app prints that path after install and in `tool info`. A bare `sudo <command>` finds nothing, or Kali's own command of that name: Kali's `ligolo-ng` package installs its own `ligolo-proxy`, so with both installed a bare `ligolo-proxy` runs the installed one and a bare `sudo ligolo-proxy` runs Kali's. Install prints a `warn` line when that happens.
- **One build of a tool per machine**, shared by every unfinished box that uses it. A box that already has another build has to `tool remove` first.
- A tool's folder, its launchers and its upload files are created and removed only inside `/opt/pwn-broker`, whatever a manifest or index names. `/opt/pwn-broker/bin` is writable by your user and first on your PATH; that suits a single-user lab VM, not a shared machine.

### Tool data in the home folder

A tool's data in the home folder is the one thing removed outside `/opt/pwn-broker`, at `finish` or when the last box that uses the tool removes it. For a tool that writes there, the manifest lists the paths. A path has to be a folder named after the tool, or something inside one: `.<name>`, or `<name>` under `.config`, `.local/share`, `.local/state` or `.cache`, where `<name>` is the tool's name or one of its commands' (`ligolo-ng` lists `.ligolo-proxy`). A package that lists anything else is refused, and so is one named after a place that holds keys or settings, such as `.ssh`: a command named `config` does not own `.config` or anything in it, only `.config/config`. Before the archive is made, `finish` copies that data into the box. It deletes a path afterwards only if it did not exist before the install, sits strictly inside the home folder, has no link anywhere on the way to it, was copied in full, and no other unfinished box uses the tool. A path that could not be copied in full is kept, with a warning. A copy already in the box from an earlier install is kept beside the new one. `tool remove` by the last box that uses a tool does the same with its data.

- `finish` refuses while one of the box's tools is running, and names it. Stop a tool before you type `finish`: a tool started after that check can write into its home folder while the box is being archived, and those files are deleted without being copied.
- Tool data that could not be copied in full is left in the home folder with a `warn` line. A later install of the same tool treats it as having been there before, so it is never copied or deleted again. Move it yourself.
- Within one install of a tool, a second `export` or `finish` replaces the box's copy of that tool's data with the current one. Files the tool deleted in between are only in the earlier archive.
- Run as a normal user, the app cannot read root's home folder. Data a tool wrote there under `sudo` is not copied or deleted; `finish` prints a `warn` line saying so.
- If `tools/installed.toml` is damaged, `finish` stops and names it. Moving it aside makes the next launch offer to remove every tool's files as leftovers; say yes and install the tools again.

### Tool history

`box.toml` keeps every tool the box has had. `tool remove` marks the tool's line with the time it was removed and keeps it; `finish` marks nothing, so a finished box still offers its tools when it is opened again. `tool history` lists them all:

```
forest/dc01 > tool history

  tool      version  installed         removed           runtime
  kerbrute  1.0.3-1  2026-11-15 14:20  2026-11-15 15:02  -
  certipy   5.1.0-3  2026-11-15 14:32  -                 python-3.13 3.13.18-1
```

That is the shape of the output, not a recorded run. A tool installed again at the same build, when its line is current, keeps that line with the latest install's time.

### The tool log

`~/pwn-broker/tools.log` spans every box: one line each time a box installs a tool, removes it with `tool remove`, or takes it off at `finish`. Each line holds, in order, the time, the event (`install`, `remove` or `finish`), the box's name and ID, the tool's name with its version and build, and the package's SHA-256. A runtime's lines end in `runtime`. Removals by the launch checks are not logged. The app only ever adds to the file, never reads it back, and keeps it readable only by you (mode 600). It follows the `home` setting, so removing or reinstalling the app does not lose it. If it cannot be written, the app warns once a session and the install or removal goes ahead.

### The tools index

`tools_index` in `config.toml` says where the index is: a URL, or a folder on disk. In a folder, the index is `index.toml` and each zip is looked for by the `file` name the index gives, in the same folder; the `url` field is not used. A leading `~` is expanded.

```toml
tools_index = "~/pwn-shop/dist"
```

The app keeps a copy of a downloaded index in `/opt/pwn-broker/cache/`, refreshes it when it is more than a day old and the source answers within two seconds, and otherwise uses what it has. `tool refresh` fetches it now. `tool list`, `tool search` and `tool info` read the index: with a URL index they use the cached copy when the source does not answer in time, and a folder index is read directly. With no index and no cached copy, every `tool` command prints one `fail` line that says where it looked and how to set `tools_index`.

## Searching

`search <text>` finds text in the current target: every file in its folder, the text copies of its recordings, and its section of the note. `search web01 <text>` looks in another target without switching to it, and `search all <text>` in the whole box: every target, the whole note, the credential lists and the box's own files.

```
forest/dc01 > search password

  notes.md
        52  admin password reused on ftp
  targets/dc01/loot/web.config
        14  <add key="DbPassword" value="Sup3r!" />
  2 hits in 2 files in dc01
```

- Case is ignored. The text is the rest of the line after the scope; runs of spaces count as one.
- A first word that is `all` or a target's exact name sets the scope when something follows it; on its own it is what is looked for.
- Binary files, links, names starting with a dot, recordings' `.cast` files (their `.txt` copies are searched) and the `vpn/` folder are skipped. A file over 16 MiB is skipped and named.
- The first 200 hits are shown, with the count of the rest.
- In the note, a [playbook](#playbooks)'s run block, and its lines still holding a `<Placeholder>`, are template text and are skipped; a last line says how many matching lines were. A line you have filled in is searched like any other.

## Scans

`scan` runs nmap against the current target's first IP in the background, with its output in the target's `scans/` folder, and says in the prompt when each mode is done:

```
forest/dc01 > scan

  ok    scanning dc01 (10.10.10.161): quick then full
  results go to targets/dc01/scans; a line here when each is done

forest/dc01 > note

  ok    scan quick of dc01 done: 53, 88, 135, 445 are open   targets/dc01/scans/2026-11-18_010203-quick.nmap
```

| Mode | What it runs | Setting |
|---|---|---|
| `scan quick` | the top 1,000 TCP ports with scripts and versions: `-sC -sV` | `scan_quick` |
| `scan full` | every TCP port, `-p- --min-rate 5000`, then `-sC -sV` on only the ports it found | `scan_full` (the first stage) |
| `scan udp` | the top 100 UDP ports: `-sU --top-ports 100`; needs root | `scan_udp` |
| `scan` | quick, then full | |

- Each mode writes `-oA` output, `.nmap`, `.gnmap` and `.xml`, named with the date and time it started and the mode: `scans/2026-11-18_010203-quick.nmap`. Full's first stage is `...-full-ports`.
- The line that a mode is done comes after the output of the next command you type, with the open ports and the file to read. A mode that nmap ended with an error gets a `warn` line instead.
- While a scan runs, the status bar shows `scan dc01`. One scan runs per target at a time; `scan stop` stops the current target's, nmap with it. `scan log` shows the last 20 lines of the commands it ran and what nmap printed.
- It outlives `quit`. `finish` waits while any scan of the box is running, since what it wrote after the archive would be lost: wait for it, or `scan stop`.
- Each mode's options are a setting, read as a shell would split them. `-oA` and the target are always added, so leave them out.

## Serving files

`serve` offers files to the targets over HTTP, from a server that runs in the background until `serve stop`, or until the box that started it is finished. It serves two folders: the current target's `upload/`, for files of your own, and `/opt/pwn-broker/upload/`, where the box's tools put the files meant for a target. `serve files` prints the line to paste on the target for each file, `iwr` on a Windows box and `wget` on a Linux one, and `serve files <word>` only those whose path holds the word:

```
forest/dc01 > serve

  ok    serving dc01's upload folder and the tools' files on http://10.10.14.5/k7Qx2p/
  2 files; serve files shows the lines to fetch them and to send files back
  serve log shows who fetched what; serve stop ends it

forest/dc01 > serve files agent

        iwr http://10.10.14.5/k7Qx2p/ligolo-ng/agent.exe -OutFile agent.exe
```

It also takes files back from the target. A `PUT` to the same address and random part, with a file name, saves the file into the target's `loot/` folder; `serve files` ends with the line to send one, `iwr -UseBasicParsing -Method PUT -InFile <file> http://10.10.14.5/k7Qx2p/<file>` on Windows and `curl -T <file> http://10.10.14.5/k7Qx2p/` on Linux.

- `serve` listens on the tunnel's address. `serve eth0` or `serve 192.168.1.20` names an interface or an address of this machine instead; with no tunnel up and nothing named, it says so and starts nothing. `serve 0.0.0.0` listens on every interface, with a `warn` line.
- The port is 80 as root and 8000 otherwise; `serve tun0 8080` picks one. A port in use is said at once.
- Every URL starts with a random part, six letters and digits, chosen each time `serve` starts. A request without it gets `404`, so knowing a tool's file name is not enough to fetch it.
- Nothing is listed: `/`, the random part and every folder get `404`. Only a file asked for by its exact path is sent. A file whose name starts with a dot, a link, or anything outside the two folders is never sent. A file put in `upload/` after the start is served at once.
- A name at the top of `upload/` that is also a tool's folder is the tool's. A file put straight into `/opt/pwn-broker/upload/`, in no tool's folder, is neither listed nor served.
- On a Windows box, a file whose name holds `[` or `]` gets the line `(New-Object Net.WebClient).DownloadFile('<url>', (Join-Path $pwd '<name>'))`, because Windows PowerShell 5.1 reads those two after `-OutFile` as a pattern and saves nothing. A character a Windows file name cannot hold (`< > : " \ | ? *` or a control character), and each byte of a name that is not UTF-8, is `_` in the name the file is saved under; the URL still names the file as it is. The send-back line has `-UseBasicParsing` because without it Windows PowerShell 5.1 fails in a shell that cannot ask a question, after the file was saved.
- `serve` again while it runs shows the address, the box and target it serves, and how many files. Naming another address then is refused: `serve stop` first.
- `serve log` shows the last 20 lines of `/opt/pwn-broker/run/serve/serve.log`: when it started, then one line per request, with the address that asked, the request and the answer. A request line longer than 200 characters is cut there, and a connection that ends part of the way through is one line, `the connection ended early: <why>`. Once the log passes 1 MiB only its last half is kept.
- A connection that sends nothing, or takes nothing, for 30 seconds is closed. An upload that goes quiet is answered `408`; the room held for it is free again and nothing of it stays in `loot/`.
- It outlives `quit` and a closed window. `finish` lists it in its summary as `serving  http://10.10.14.5/   (will be stopped)` and stops it; a server another box started is left alone.
- `upload/` is part of the box, so whatever you put there is in its archives.
- A file sent back lands in `loot/` under its own name, or `name-2` and on when that is taken: nothing there is ever replaced. It needs the random part, one plain name with no folder and no dot at the start, and a length. One file is at most 4 GiB, and one that would leave less than 1 GiB free on the disk is refused with `507`. A transfer cut short leaves nothing. What lands in `loot/` is not served back, and `serve log` shows `saved loot/<name>` beside the request.

## Finish, export and import

`finish` shows a summary (the box, its targets, its files, the archive's path, whether a report will be built, the `/etc/hosts` lines and tools it will remove) and asks `finish this box? [y/N]`. A tool another unfinished box has is listed as `(will be kept; forest still uses it)`, and a tool that was not installed again when the box was imported or reopened is not listed, since there is nothing to remove. Then it:

- writes `~/pwn-broker/wrapped/<box folder>.finished.tar.gz`, and a copy to `copy_to` if that is set;
- builds the report beside it when the box has the report tool, `<box folder>.finished.report`, and copies that to `copy_to` too ([Reports](#reports));
- removes the box's `/etc/hosts` lines after the archive is verified, takes off the tools and runtimes no other unfinished box uses, with a line for each (`ok    kerbrute 1.0.3 removed`, or `ok    kerbrute 1.0.3 kept; forest still uses it` for a tool another box has), and asks whether to stop the app's VPN if it is still up (the default keeps it);
- asks `remove working folder? [y/N]`, and on yes closes the note window and removes the folder, unless the note has unsaved changes, any file in the box was made or changed since the archive was written, or the note's window did not close. A `warn` line says which, and the folder stays.

It refuses while a window is recording for the box or one of the box's tools is running, and names them. A box whose archive already exists asks `replace the existing archive?`, which is only ever asked about the same box.

`export` writes a snapshot archive to `wrapped/` and keeps working. It copies tool data into the box and removes nothing; a window still recording gets a `warn` line and is packed up to its last whole line. `exit` and `quit` ask `export forest before you go? [Y/n]` first.

Links and special files (named pipes, sockets, devices) in a box are not archived. `export` and `finish` list them, and `finish` says how many will go when the folder is removed. A file whose name is not UTF-8 is archived under the name it has, but `files.toml` and the manifest cannot hold that name, so it is not listed or checked; a `warn` line names it. Two names for one file (a hard link) are packed as two files. A box of more than 300,000 files and folders is refused by `export` and `finish`.

Unpacking refuses any entry that would land outside the box folder, and an archive that holds anything but files and folders, a sparse file, more than 300,000 entries, a header of more than 64 KiB, or a top folder whose name starts with a dot. It checks that the archive fits in the free space first.

`pwn-broker import <file>` unpacks an exported or finished box into `active/`. When a box of that folder name is already there it asks `a box named <folder> is already here. replace it?`, and the box that is there is only replaced once the new one has been unpacked and loaded. A box that is already here under another folder name is refused. `pwn-broker import` with no file prints `fail  import needs a file: pwn-broker import <file>` and exits with status 2, and `pwn-broker import ""` prints `fail  give the path of an exported box` once and stops. The start menu's `import a box from a file` asks for the file again after that line until it gets one. A folder gets `fail  <path> is a folder, not an exported box`. `import`, and reopening a finished box from the menu, offer to install the box's tools again, at the same builds and checked against the SHA-256 the box recorded. A tool that requires a runtime comes back with it: the one already on the machine, at any build, or the latest in the index; when that is not the build the box recorded, a line says so. The `/etc/hosts` lines come back when the box opens.

## Settings

`/opt/pwn-broker/config.toml`, optional. Without it everything uses the defaults. The installer takes `--config <path>` to copy one in.

| Setting | Default | Meaning |
|---|---|---|
| `home` | `~/pwn-broker` | Where `active/`, `wrapped/` and `tools.log` live; a whole path, as `copy_to` is |
| `copy_to` | not set | A second folder every finished archive, report and export is also copied to |
| `default_platform` | `htb` | Platform used when a box is created |
| `terminal` | `x-terminal-emulator` | What opens the note window |
| `check_updates` | `true` | Look for a newer release at launch |
| `tools_index` | the published index in `pwn-shop` | A URL, or a folder that holds `index.toml` and the zips it names |
| `scan_quick` | `-sC -sV` | nmap's options for `scan quick` |
| `scan_full` | `-p- --min-rate 5000` | nmap's options for the first stage of `scan full` |
| `scan_udp` | `-sU --top-ports 100` | nmap's options for `scan udp` |
| `playbooks` | not set | Whether each new box gets the playbooks. Not set, the first new box asks, and the answer is kept in `/opt/pwn-broker/state.toml` |
| `report` | not set | Whether each new box gets the report tool. Not set, the first new box asks, after the playbooks' question, and the answer is kept in `/opt/pwn-broker/state.toml` |

Two environment variables are read as well. `PWN_BROKER_OPT` is the install folder, for the installer and the app alike (default `/opt/pwn-broker`). `PWN_BROKER_HOME` is where the boxes live when `home` is not set in `config.toml`.
