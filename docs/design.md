# pwn-broker design

Keeps a box's targets, notes, creds and tools in order

Written 2026-11-14. Nothing is built yet. This document is the agreed design for `pwn-broker` (the app) and `pwn-shop` (the tools repo).

## 1. Intent

I solve Hack The Box machines and want each one kept in order the way a professional engagement would be. Today a box leaves scan output, notes, credentials and downloaded tools scattered across the machine, and nothing records which box any of it belonged to.

`pwn-broker` is a Python application for Kali Linux. I launch it when I start a box. It asks a few questions, builds the workspace, opens my notes, and then stays open as a prompt for the whole session. When the box is done it packs everything into one archive and puts Kali back the way it was.

The record matters as much as the tidiness. Every piece of metadata says which box it belongs to and when, under an ID unique to that box, so that two machines that reuse the same IP address are never confused when I look back through old work.

## 2. Goals, non-goals, anti-goals

### Goals

- One predictable folder per box, with one folder per target inside it.
- A prompt I stay in for the whole box, in the RFS terminal palette, that feels like a finished product.
- A notes file that opens on launch in vim, already filled in with the box and its targets.
- A credentials list that stores exactly what I typed.
- Tool-ready lists of usernames, passwords, pairs, hashes and target addresses, always in step with the record.
- A record of every file in the box: which box, which target, when it appeared.
- One command that closes a box: archive it, verify the archive, undo what the box changed on Kali.
- A box can be exported, carried to a new VM and imported, and work continues where it stopped.
- Per-window terminal recordings filed under the right target (phase 2).
- Tools installed on demand from my own repo, isolated from Kali, removed when the box is finished (phase 3).
- Works on a VM that was created that day, with no memory of earlier runs.
- Works as root and as a normal user with `sudo`.

### Non-goals

- It does not run my tools for me. I run nmap and everything else in my own terminal. The app hands me the right path.
- No report or writeup generation. The end product is an archive.
- No tmux. The notes are in a separate terminal window.
- No shell variables (`$IP` and the like) in my working terminal. With several targets they would point at the wrong machine.
- No bulk target import. A box has fewer than ten targets.
- No automatic recording of windows I have not asked to record.
- No uploads to any outside service, ever.
- No containers and no security sandbox. Tool isolation is about files and dependencies.
- Kali only. No Windows or macOS support.

### Anti-goals

These would make it a failure even if it works.

- Friction in the middle of an exploit. If recording a credential takes more than a few keystrokes I will stop using it.
- Kali left changed after `finish`: stray tools, `/etc/hosts` lines, tool data in my home folder.
- Work lost because a throwaway VM was destroyed.
- Anything deleted or overwritten without asking first.
- A credential altered on the way in or out: quoting, escaping, trimmed spaces, colour markup.

## 3. Constraints

- **Platform:** Kali Linux with a desktop session. Python 3.11 or later.
- **Users:** root, or a normal user with `sudo`. Nothing may assume uid 0 or hard-code `/root`.
- **Fresh VMs:** some days the VM is new. Every launch runs checks. Nothing may depend on state from an earlier run. Install is one command with no questions.
- **Brand:** output follows `BRAND.md` in `rfs-brand`. Section 9 (terminal palette), section 1 (status always has a word), section 4 (voice: plain, specific, dry, honest; no emoji; sentence case), section 5 (naming). Two deliberate exceptions to section 5: `record` is a second command on PATH beside `pwn-broker`, and commands inside the prompt are grouped by noun (`target add`, `cred add`).
- **Two repos:** `Real-Fruit-Snacks/pwn-broker` and `Real-Fruit-Snacks/pwn-shop`.
- **Confirmation:** anything hard to undo shows what it is about to do and waits for a yes. The default answer is no.

## 4. Approaches considered

| Decision | Options | Chosen | Why |
|---|---|---|---|
| Where the prompt sits | An organiser beside my shell · a wrapper my tools run through | Organiser | A wrapper gets in the way of reverse shells and tools with odd terminal behaviour |
| Prompt and notes sharing the screen | tmux split · second terminal window · prompt inside vim | Second window | I do not work in tmux |
| Metadata store | Plain TOML files · SQLite | TOML | Readable and greppable without the app, and it survives inside a tar |
| App and tools | One repo · two repos | Two | Tool releases would bury the app's own releases, and the app should not share the tools repo's fate |
| Tool releases | One release holding every tool · one release per tool version | Per tool version, plus an index file | A tool can be updated alone and an old version can be pinned. GitHub allows 1,000 files per release and states no limit on the number of releases |
| Tool isolation | Own folder per tool with links in a shared `bin` · containers · install into the system | Own folder | Containers complicate the VPN, raw sockets and file access. Installing into the system is what this exists to avoid |
| Python tools | Hand-written virtual environments · drive `uv` or `pipx` | Drive `uv` or `pipx` | Those already solve environment creation, launchers and clean removal |
| Tool data in my home folder | Clean up at `finish` · redirect into the box from the first run | Redirect, with cleanup as the fallback | Nothing to delete afterwards, and two boxes cannot mix results |
| Boxes open at once | One · several | One | `record` and tools run from any terminal and must know their box. Two boxes can share an IP |
| Recorder | `script` · `asciinema` | `asciinema` | Better playback. The cost is one more thing to install on a fresh VM, which the installer covers |
| Install location | `/opt/pwn-broker` · under my home folder | `/opt/pwn-broker` | The customary place for add-on software on Kali, and the same path for root and a normal user |
| Build order | Organiser, recording, tools · tools earlier · all at once | Organiser, recording, tools | Usable on a real box after phase 1. Tools is the largest and riskiest part |

## 5. Overall shape

Three phases. Each is usable when it is done.

| Phase | Contents |
|---|---|
| 1. Organiser | Install, launch checks, new box questions, targets and folders, notes window, the prompt, creds, file records, flags, `finish`, `export`, `import` |
| 2. Recording and Kali changes | `record`, `replay`, `/etc/hosts` management, VPN check, ping on target add |
| 3. Tools | The `pwn-shop` repo and its release workflow, the first six packages, the `tool` commands |

Phase 1 is specified in full below. Phases 2 and 3 are specified to the level decided so far. Each gets its own detailed design before it is built.

### On disk

```
/opt/pwn-broker/                 owned by the installing user
  app/                           the application, in its own virtual environment
  bin/                           on PATH: pwn-broker, record, tool links and launchers
  templates/notes.md             note template, editable
  vim/vimrc                      loaded with vim -u
  vim/nightshift.vim             Nightshift colours for vim
  run/                           which box is open, and its lock
  state.toml                     last-used values, rebuilt when missing
  tools/<name>/<version>/        phase 3
  upload/<name>/                 phase 3
  cache/                         phase 3: downloaded zips and the tool index
  config.toml                    settings, optional

~/pwn-broker/
  active/
    2026-11-14_htb_forest/       a box in progress
  wrapped/
    2026-11-14_htb_forest.finished.tar.gz
    2026-11-15_htb_sauna.exported.tar.gz
```

Everything the app owns is under `/opt/pwn-broker`. Uninstalling it is deleting that folder and one PATH line. Upgrading replaces only `app/`. My boxes are never inside `/opt`, so removing the app can never remove my work.

### A box

```
2026-11-14_htb_forest/
  box.toml              identity, status, dates, flags, what the box changed on Kali
  creds.toml            one credential list for the whole box
  files.toml            a record of every file in the box
  notes.md
  lists/                usernames, passwords, pairs, hashes, IPs and hostnames, one per line
  screenshots/
  targets/
    dc01/
      target.toml       IPs, hostnames, scope, and the box it belongs to
      creds/            hashes, tickets, keys saved as files
      files/
      loot/
      scans/
      exploits/
      screenshots/
      recordings/       phase 2
  tooldata/             phase 3: data that tools write while they run
```

The folder name is `<date>_<platform>_<name>`. If that name is taken, a number is added.

## 6. Phase 1: the organiser

### 6.1 Install

```
curl -fsSL https://raw.githubusercontent.com/Real-Fruit-Snacks/pwn-broker/main/install.sh | sh
```

- Creates `/opt/pwn-broker`, using `sudo` once if it is not root, and gives it to the user who ran the install.
- Creates a virtual environment in `app/` and installs the released package into it, after checking its SHA-256. Nothing goes into Kali's system Python.
- Writes the `pwn-broker` launcher into `bin/`.
- Adds `/opt/pwn-broker/bin` to the front of PATH in the user's shell config, and prints that it did.
- Asks no questions. Defaults are good enough to start a box immediately.

### 6.2 Root and normal user

Root and a normal user are two ways of setting up a VM. They are not two users sharing one box.

- No path is hard-coded to `/root`. Boxes live under the home folder of the user who installed the app.
- The app runs as the user who installed it. Started as anyone else, including through `sudo pwn-broker`, it refuses and names the user to run it as.
- Which box is open is recorded in `/opt/pwn-broker/run`, not under a home folder. `record` and tool launchers may run under `sudo`, where the home folder is root's, and they still have to find the box.
- One helper runs privileged steps: directly as root, or through `sudo` otherwise.
- As a normal user, tools run with `sudo` leave root-owned files in the box. `finish` and `export` correct ownership before archiving.
- Every feature is tested as root and as a normal user.

### 6.3 Launch

`pwn-broker` with no arguments runs the checks, then offers:

```
1  new box
2  import a box from a file
3  resume forest (htb, started 2026-11-14)
4  reopen sauna (htb, finished 2026-11-13)
```

Choice 3 appears once per active box on this VM, and choice 4 once per finished box whose working folder was kept. `pwn-broker new`, `pwn-broker import <file>` and `pwn-broker resume [name]` go straight there. Launching from inside a box folder resumes that box.

Only one box is open on the VM at a time, enforced by a lock in `/opt/pwn-broker/run`. Other boxes stay on disk and can be resumed after quitting the current one. `record` and installed tools always belong to the open box, so nothing can be filed under the wrong machine.

**Checks, every launch.** Fast, and quiet when they pass:

```
ok    5 checks passed
warn  display   no desktop session; open the note with: vim -u /opt/pwn-broker/vim/vimrc notes.md
```

- Dependencies present: vim, a terminal emulator, tar. Later phases add `asciinema`, and `uv` or `pipx`.
- A desktop session exists.
- The PATH line is present.
- The home folders exist.
- `/opt/pwn-broker` is owned by the current user. If it is not, the app refuses to start (section 6.2).
- A newer release of the app exists. This never blocks, stays silent when offline, and never updates anything.

A check that can repair its problem offers to. One that cannot prints the exact command to run. `check` in the prompt reruns them.

### 6.4 New box

```
box name     > forest
platform     [htb] >
date         [2026-11-14] >
os           > windows
difficulty   > easy

add a target? [Y/n]
  ip         > 10.10.10.161
  hostname   > forest.htb.local
  scope      [external] >
  name       [forest.htb.local] > dc01
ok  target dc01 created

add another? [y/N]
```

- Date defaults to today. Platform defaults to the last one used on this VM, then the `default_platform` setting, then `htb`.
- OS and difficulty may be left blank.
- A target needs an IP or a hostname. Either may be blank, not both. Each takes several values separated by spaces.
- Scope is `external` or `internal`, defaulting to external.
- The target's name defaults to its hostname, or its IP when there is no hostname. The name is the folder name and what I type in the prompt.
- After each target it asks whether there is another.
- When the questions end, the folders are created, the note is written from the template, and the note window opens.

### 6.5 Metadata

The purpose is provenance: which box, which target, when. Each box gets a unique ID when it is created. The ID is never reused, and it appears in every metadata file, so a file or folder copied out of a box still says where it came from.

`box.toml`:

```toml
schema = 1
id = "0b7f3c1e-5a2d-4e8b-9c41-7d2a6f0e913b"
name = "forest"
platform = "htb"
os = "windows"
difficulty = "easy"
status = "active"                      # active or finished
started = 2026-11-14T13:02:11-05:00
last_target = "dc01"

[flags.user]
value = "e5e4e47ae7022664cda6eb013fb0d9ed"
at = 2026-11-14T15:40:02-05:00
```

`target.toml`:

```toml
schema = 1
box_id = "0b7f3c1e-5a2d-4e8b-9c41-7d2a6f0e913b"
box = "forest"
name = "dc01"
ips = ["10.10.10.161"]
hostnames = ["forest.htb.local"]
scope = "external"
added = 2026-11-14T13:02:40-05:00
```

Only the app writes these files. Changes to a target go through `target edit`, not through editing the TOML by hand.

`files.toml` holds one record per file in the box: its path, the target it sits under, when it was first seen, its size and its SHA-256. `box.toml` also records what the box changed on Kali (hosts lines in phase 2, installed tools in phase 3) so `finish` can undo it and `import` can redo it.

### 6.6 The note window

- On launch the app opens a second terminal window running `vim -u /opt/pwn-broker/vim/vimrc notes.md`. My own `~/.vimrc` is never read or changed.
- The terminal is `x-terminal-emulator`, with a setting to name another.
- The vimrc carries the Nightshift colours so the note and the prompt match.
- The note starts from `templates/notes.md`, with the box details and a table of targets at the top:

```
# forest
platform     htb
date         2026-11-14
os           windows
difficulty   easy

## targets
dc01   10.10.10.161   forest.htb.local   external

## dc01
### enumeration
### foothold
### privilege escalation
```

- Adding a target later adds its row to the table and its section to the end of the note.
- The app only ever rewrites the targets table, appends sections and, on a rename, changes that target's own section heading. It never touches anything I wrote.
- The vimrc saves the note when I leave the window and reloads it when I come back, so the app and vim never overwrite each other.
- `note` in the prompt reopens the window if I closed it.

### 6.7 The prompt

```
forest/dc01 > tool ins
              tool install   install a tool from the repo
              tool info      show a tool's details

 forest   dc01  10.10.10.161   2 targets   01:42
```

Built on `prompt_toolkit` for the prompt and `rich` for tables.

**Look.** The palette is `BRAND.md` section 9, Nightshift values, in full colour:

| Element | Colour |
|---|---|
| Prompt (`forest/dc01 >`) | Ember `#FF6A3D`, bold. The only Ember on screen |
| What I type | text `#E8E6E1` |
| `ok` lines | Mint `#3DDC97` |
| `warn` lines | Amber `#FFC247` |
| `fail` lines | Raspberry `#F06292` |
| Everything else, and the status bar | mute `#8A8F99` |

- Every status line starts with the word `ok`, `warn` or `fail`. Colour is never the only signal.
- No emoji, no gradients, no banner art. Sentence case.
- The status bar shows the box, the current target and its IP, the number of targets and the time on the box.
- `NO_COLOR` is respected. Terminals without full colour get the nearest match.

**Feel.**

- Tab completion for commands, target names and file paths.
- History with the up arrow and Ctrl-R, kept per box, with a muted suggestion from the last matching command.
- A mistyped command gets a suggestion. Every error says what to do next.
- Ctrl-C cancels the current line. It never ends the session.
- Values I typed (credentials, hostnames, notes) are always printed literally and never interpreted as colour markup.

**Commands in phase 1.**

| Command | Does |
|---|---|
| `target add` | Asks the same questions as launch, creates the folders, updates the note |
| `target list` | Every target with its IP, hostname and scope |
| `target use <name>` | Switches the current target. A partial name works when it matches only one |
| `target show [name]` | One target in full |
| `target edit <name>` | Asks the target's questions again with the current answers as defaults. This is how an IP is changed after a respawn, or a newly found hostname added |
| `target rename <name>` | Renames the target everywhere: its folder, its row and section heading in the note, its file records, and the "found on" of its credentials |
| `target remove <name>` | Removes a target that holds no files, after asking. If its folder holds anything, it refuses and says what is there. It never deletes collected work |
| `cred add` · `cred list` · `cred show <n>` · `cred edit <n>` · `cred clear <n> <field>` · `cred works <n>` · `cred remove <n>` · `cred import <file>` | Section 6.8 |
| `files [target]` | Lists recorded files |
| `flag user` · `flag root` | Asks for the flag and records it with the time |
| `path [folder]` | Prints the full path of the current target's folder, or one of its subfolders, to copy into my own terminal |
| `note` | Reopens the note window |
| `status` | The box at a glance |
| `check` | Reruns the launch checks |
| `export` · `finish` | Sections 6.11 and 6.10 |
| `help` · `quit` | |

### 6.8 Credentials and lists

One record for the whole box, in `creds.toml`. A password found on one machine often works on another, so the record is not split by target. Each entry says where and when it was found.

```
forest/dc01 > cred add
  username   > svc-alfresco
  domain     [htb.local] >
  secret     > p@ss "word" with spaces\
  kind       [password] >
  found on   [dc01] >
  note       >
ok  cred 3 saved, found on dc01
ok  lists updated: 3 usernames, 2 passwords, 2 pairs
```

- One field at a time. Each answer is taken exactly as typed: no quotes needed, no escaping, nothing interpreted.
- Spaces, quotes, backslashes and every other character are stored and shown back unchanged.
- If an answer starts or ends with a space, the app points it out and asks whether to keep it. It never trims silently.
- The secret is visible as I type, so I can check a paste.
- Each field is one line. A pasted value that spans several lines is refused, with a line saying to save it as a file in the target's `creds/` folder.
- Kinds are `password`, `hash`, `token` and `other`.
- The domain is optional and defaults to the last one used in this box. It is kept in the record beside the username, never joined onto it.
- The secret may be left blank. That records a username I have found but have no password for, and the kind question is skipped.
- `cred list` shows the table. `cred show <n>` prints one secret alone on a line, ready to copy.
- `cred edit <n>` asks the questions again with the current answers as defaults. `cred remove <n>` asks first.
- `cred clear <n> secret` or `cred clear <n> note` empties that field, after asking. Clearing the secret also clears its kind and where it was marked as working.
- `cred works <n> [target ...]` marks a credential as confirmed on one or more targets, defaulting to the current one. The record keeps the list of targets, `cred list` shows it in a "works on" column, and `cred edit` can take a target back off.
- `cred import <file>` loads a file of usernames, one per line. It asks the domain and where they were found once for the whole file, skips blank lines and names already in the record, and reports how many it added.
- Anything that is a file, such as a ticket or a private key, is saved into the target's `creds/` folder and recorded like any other file.

**Lists.** Other tools want plain files, so the app keeps a set in the box's `lists/` folder:

```
lists/
  usernames.txt        every username, one per line, no duplicates
  passwords.txt        every password, one per line, no duplicates
  userpass.txt         username:password, one pair per line
  hashes.txt           every hash, one per line, no duplicates
  userhash.txt         username:hash, one pair per line
  pair-users.txt       line N goes with line N of pair-passwords.txt
  pair-passwords.txt
  ips.txt              every target IP, one per line
  hostnames.txt        every target hostname, one per line
  hosts.txt            ip, then that target's hostnames, in /etc/hosts form
  works-dc01-userpass.txt    username:password pairs confirmed on dc01
  works-dc01-userhash.txt    username:hash pairs confirmed on dc01
```

- Every list is rebuilt from the record each time a credential or target is added, edited, renamed or removed. A list can never hold a duplicate, a removed entry, or anything the record does not.
- The lists are output only. A line added by hand is overwritten at the next rebuild; `cred import` is the way to load usernames in bulk.
- No header lines, no comments, one entry per line, in the order added. Tools read them as they are.
- Usernames are written bare, without the domain. That is the form kerbrute and netexec take.
- Two entries are the same only when they match exactly, including case.
- Passwords go in `passwords.txt` and hashes in `hashes.txt`. Neither file ever holds the other kind. Tokens and `other` entries stay in the record only.
- A username with no secret appears in `usernames.txt` and in no pair file.
- The pair files use a colon, and tools split at the first one, so a password may contain colons. A username that contains a colon cannot be written that way: it is left out of the colon files, with a `warn` line saying so, and still appears in `usernames.txt` and the line-matched pair files.
- `pair-users.txt` and `pair-passwords.txt` hold the same pairs as `userpass.txt` in the same order, one half each. netexec's `--no-bruteforce` reads pairs that way.
- `ips.txt` and `hostnames.txt` cover every target in the box, for `nmap -iL` and host lists.
- `hosts.txt` has one line per target IP, followed by that target's hostnames, ready to paste wherever a hosts file is wanted. A target with no IP or no hostname is left out.
- Each target with at least one confirmed credential gets its own `works-<target>-userpass.txt` and `works-<target>-userhash.txt`. A file is written only when it has something in it, and it goes away when its last entry does.
- `path lists` prints the folder's path.

### 6.9 Files

- I save files into the target's folders myself, with my own tools: `nmap -oA`, `wget`, `scp`. There is no command to add a file.
- The app notices new and changed files each time I use the prompt, and again at `export` and `finish`, and records them in `files.toml`.
- Each record carries the box ID, the target, the first-seen time, the size and the SHA-256. There are no manual tags; the folder a file is in says what it is.
- Checksums of large files may be left until `export` or `finish` so the prompt never stalls.

### 6.10 Finish

```
forest/dc01 > finish
box       forest (htb), started 2026-11-14
targets   2
files     47
archive   ~/pwn-broker/wrapped/2026-11-14_htb_forest.finished.tar.gz

finish this box? [y/N]
```

Nothing happens before a yes. Then, in order:

1. If vim has unsaved changes to the note, stop and say so.
2. Record every file and its checksum. Write `manifest.toml` at the top of the box: the box's identity, whether it was packed as a finished box or an export, and every file with its target, times, size and checksum.
3. Set the status to finished and stamp the end time.
4. Correct file ownership if needed.
5. Write the archive under a temporary name, read it back, and compare it with the manifest. Only then give it its final name.
6. Copy it to the `copy_to` folder, if one is set, and verify the copy.
7. Undo what the box changed on Kali (phases 2 and 3).
8. Ask whether to remove the working folder. The default is no.

If any step fails, nothing after it runs, nothing is removed, and the box goes back to active. A finished archive is never overwritten without asking.

A finished box whose working folder I kept shows in the launch menu as a box to reopen. Reopening sets it back to active. Finishing it again asks before replacing the earlier archive.

### 6.11 Export and import

`export` packs the box as it stands into `wrapped/<box>.exported.tar.gz`. It does not close the box or undo anything: the box stays open and its status stays active. It does bring the file records up to date, rewrite `manifest.toml` and correct ownership first, exactly as `finish` does. An exported box and a finished archive are the same format; `manifest.toml` says which one it is. A new export of the same box replaces the previous one, after the new file has been verified.

`import <file>` on any VM:

```
# pwn-broker import /mnt/share/2026-11-14_htb_forest.exported.tar.gz
ok     unpacked to ~/pwn-broker/active/2026-11-14_htb_forest
ok     2 targets
ok     note opened
forest/dc01 >
```

- Unpacks into `active/`. If a box with that folder name is already there, it asks.
- Restores everything: targets, note, creds, files, flags, recordings.
- Opens the note and the prompt on the target I was last on.
- Importing a finished archive reopens the box.
- Phase 2 adds restoring `/etc/hosts` lines. Phase 3 adds reinstalling the same tool versions, after asking.
- Unpacking refuses any archive entry that would land outside the box folder.

**Quit.** Leaving the prompt on an unfinished box offers to export it, defaulting to yes, because the VM may not exist tomorrow.

### 6.12 Settings

`/opt/pwn-broker/config.toml`. Optional. Without it everything uses defaults.

| Setting | Default | Meaning |
|---|---|---|
| `home` | `~/pwn-broker` | Where `active/` and `wrapped/` live |
| `copy_to` | not set | A second folder every finished archive and export is also copied to, such as a folder shared with the host |
| `default_platform` | `htb` | |
| `terminal` | `x-terminal-emulator` | What opens the note window |
| `check_updates` | `true` | |

On a fresh VM the file does not exist. The installer takes `--config <path>` to copy one in.

## 7. Phase 2: recording and Kali changes

Decided so far. A detailed design comes before it is built.

**`record <target>`**, typed in any terminal window:

```
# record 10.10.10.161
ok  recording this window for dc01 (forest)
    targets/dc01/recordings/2026-11-14_1432.cast
```

- The target can be given as an IP, a hostname or a name. The recording goes into that target's `recordings/` folder.
- Every window gets its own file, named by start time.
- It always files under the box that is open. With no box open, it says so and records nothing.
- Recording starts only when I type the command.
- An address that is not a target offers to add it.
- The window shows that it is recording and for which target.
- Built on `asciinema`. The installer fetches a pinned, hash-checked copy into `app/`, so the version is the same on every VM and does not depend on `apt`.
- Recordings are only ever written to a local file. Nothing is uploaded.
- Beside each `.cast` file the app writes a plain-text copy with clock times, for reading in vim and for grep.
- Each recording's header names the box by ID.
- `replay` in the prompt lists a target's recordings and plays one, with long idle gaps capped.
- `finish` warns if a window is still recording.
- Passwords typed on a command line are recorded and go into the archive.

**`/etc/hosts`.** Adding a target that has a hostname offers to add the line. Each line the app adds is marked with the box ID. `finish` removes exactly those lines. `import` puts them back.

**VPN check.** At launch, warn if no VPN tunnel is up. The VPN address is shown in the status bar.

**Ping.** A new target is pinged once and the result reported. No reply is a warning, not a failure, since Windows targets often do not answer.

## 8. Phase 3: tools

Decided so far. A detailed design comes before it is built.

### The repo

`pwn-shop` holds one release per tool version, tagged `<tool>-v<version>`, each with one zip. An index file in the repo lists every tool: its versions, download URLs, SHA-256, kind, description and tags. This is an exception to the SemVer-only release rule in `BRAND.md`, limited to this repo.

Each zip holds the tool's files, the upstream licence, and a manifest: name, version, kind, what to link into `bin`, what it needs, the data it writes while running, and a few example commands. Packages are a manifest, not an install script. A script is allowed only for a tool that needs a build step, it is reviewed, and it writes only inside the tool's folder.

Any tool can be packaged, including ones Kali already ships, for when Kali's version is wrong or a specific version is needed.

### Commands

| Command | Does |
|---|---|
| `tool list` | Everything available, with installed tools and tools Kali already has marked. `--installed` narrows it |
| `tool search <words>` | Matches name, description and tags. Several words must all match |
| `tool info <name>` | What it does, how to run it, where it lives, available versions, and examples filled in with the current target |
| `tool install <name>[@version]` | Downloads, checks the hash, installs, prints how to run it |
| `tool remove <name>` | Asks first |
| `tool cache clear` | Empties the download cache |

The index is cached, so `list`, `search` and `info` work offline.

### Install and isolation

- Each tool installs into `/opt/pwn-broker/tools/<name>/<version>/`. Its command is linked into `/opt/pwn-broker/bin`, which is on PATH, so it runs from any terminal with no environment to enter.
- Kinds: `kali` (runs on Kali), `upload` (files for the target, placed under `/opt/pwn-broker/upload/<name>/`), and `both`.
- Python tools go through `uv` or `pipx` pointed at the tool's folder: a private environment that cannot see Kali's Python packages, with pinned and hash-checked dependencies.
- Ruby tools keep their gems inside the tool's folder. Java tools get a launcher. Binaries are shipped prebuilt; nothing is compiled on Kali.
- Nothing is ever installed into the system Python.
- System packages from `apt` are asked about first and left in place afterwards.
- If a command already exists on Kali, install says so. The installed version wins, and the message gives the path to Kali's copy. Kali's copy is never changed.
- `sudo <tool>` must also find the installed version. One `sudo` settings file adds `/opt/pwn-broker/bin` to its path. It is validated before it goes live and removed on uninstall.
- Every download is checked against the index's SHA-256.
- Deletes are guarded: the app refuses to remove anything outside its own folders, whatever a manifest says.
- Uninstall is deleting the tool's folder and its link.

### Tools belong to the box

- `box.toml` records every tool and version installed during the box.
- `finish` lists them on the confirmation screen and removes them, unless another active box also installed them.
- `import` reinstalls the same versions, after asking.
- Downloaded zips stay in the cache, so reinstalling needs no network.

### Tool data

Some tools write their own data into the home folder as they run. Where a tool lets its data location be chosen, its launcher points it at the box's `tooldata/<tool>/` folder from the first run, so the data is in the box all along. For tools that cannot be redirected, `finish` copies the data into the box and then deletes it, checking both root's home and the user's. If that home folder existed before the tool was installed, it is left alone and a warning is printed.

### First packages

One for each way a tool can install:

| Tool | Kind | Tests |
|---|---|---|
| kerbrute | kali | One binary |
| Certipy | kali | Python package in a private environment |
| targetedKerberoast | kali | Python script from git, with dependencies |
| ligolo-ng | both | Two halves: proxy on Kali, agent on the target |
| pspy | upload | Binaries for a Linux target |
| PEASS-ng | upload | Multi-file kit that updates often |

Rubeus, Seatbelt and SharpHound wait: their authors publish source only.

### Accepted trade

`/opt/pwn-broker/bin` is writable by my user and on root's path, so anything running as me could place a command that root later runs. On a single-user lab VM where I have full `sudo` anyway, that is acceptable. It would not be on a shared machine.

## 9. What finish puts back

Whatever a box changes on Kali, `finish` undoes. Each change is recorded in `box.toml` when it is made.

| Change | Phase | Undone by |
|---|---|---|
| Lines in `/etc/hosts` | 2 | Removing the lines marked with the box ID |
| Installed tools | 3 | Removing each tool's folder and link |
| Tool data in the home folder | 3 | Copying it into the box, then deleting it |

Not undone: system packages installed with `apt`, the PATH line, the `sudo` settings file, and the download cache. Those belong to the app, not to a box.

## 10. To verify on Kali

These could not be checked while designing. Each must be confirmed before the part that depends on it is built.

- The terminal reports focus changes to vim, so the note can save on leaving and reload on return. Fallback: a short reload timer.
- `x-terminal-emulator` exists and accepts a command to run.
- How vim signals unsaved changes in a way the app can detect before `finish`.
- Which of `uv` and `pipx` is present by default, and the exact options for installing into a chosen folder from a pinned lock file.
- Which `asciinema` version to pin, that it writes to disk as it records, and whether it can produce the plain-text copy itself.
- Where the recording indicator can be shown reliably: window title or shell prompt.
- Kali's default `sudo` path settings, for the `sudo <tool>` fix.
- Which of the first six tools Kali already packages.
- Each first package's licence allows redistribution.

## 11. Not yet confirmed

These are choices made while writing this document. They stand unless changed.

- The target's name is asked as a fourth question, defaulting to the hostname or IP.
- Box IDs are random UUIDs.
- The secret is visible while typing in `cred add`, and leading or trailing spaces prompt a keep-or-trim question.
- Credential kinds: password, hash, token, other. Keys and tickets are files in `creds/`, not list entries.
- A multi-line paste into `cred add` is refused.
- `cred edit` exists.
- The order of the `cred add` questions: username, domain, secret, kind, found on, note.
- List entries count as duplicates only on an exact, case-sensitive match.
- A username containing a colon is left out of the colon-separated files.
- The line-matched pair files are named `pair-users.txt` and `pair-passwords.txt`.
- The lists folder is box-wide and called `lists`.
- Confirming a credential is the command `cred works <n> [target ...]`, and the per-target lists are named `works-<target>-userpass.txt` and `works-<target>-userhash.txt`.
- A credential is confirmed against a target only, not against a service or port. That detail goes in the note field.
- `path [folder]` exists as the way to get a target's path into my own terminal.
- `target edit` exists, and is the only way to change a target's IPs, hostnames or scope.
- The app refuses to start for any user other than the one who installed it.
- A box's status is only active or finished. Whether an archive is an export is recorded in its manifest.
- A finished box left on disk can be reopened from the launch menu.
- The platform default is last used, then the setting, then `htb`.
- The installer adds the PATH line without asking, and prints that it did.
- A new export replaces the previous export of the same box without asking. Finished archives always ask.
- A settings file is carried to a new VM with `--config <path>` on the installer.
- Nightshift is the only theme.
- History is kept per box.
- `target rename` and `target remove` exist.

## 12. Left to implementation

- Module layout and internal interfaces.
- How file changes are detected between prompts, and the size above which checksums are deferred.
- The exact wording of messages, within the voice rules in `BRAND.md`.
- The test layout. Logic is kept apart from terminal and file-system access so it can be tested without a Kali machine, and anything that touches privileges is tested as both root and a normal user.
- The release workflow for the app itself: SemVer tags, `vX.Y.Z`.
