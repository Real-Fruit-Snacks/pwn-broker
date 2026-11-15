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
| Tool releases | One release holding every tool · one release per tool version | Per tool version, plus an index | A tool can be updated alone and an old version can be pinned. GitHub allows 1,000 files per release and states no limit on the number of releases |
| Where the index lives | A file committed to the repo · a file published by CI · a location set in settings | Published by CI, with the location settable | CI builds the packages, so only CI knows their checksums, and nothing but me commits to the repo. A settable location lets a folder on disk stand in for the published index, with no network |
| How packages are made | Zips built by hand · recipes built by CI | Recipes | No binary is committed, every file traces to its upstream release, and an update is a change to a recipe |
| Tool isolation | Own folder per tool with links in a shared `bin` · containers · install into the system | Own folder | Containers complicate the VPN, raw sockets and file access. Installing into the system is what this exists to avoid |
| Python tools | `uv` or `pipx` · Python's own `venv` and `pip` with the dependencies bundled | `venv` and `pip`, dependencies bundled | `uv tool install` does not check dependency hashes; `pip` does. `venv` and `pip` are already required by the installer, and bundled wheels install with no network |
| `sudo <tool>` | A `sudo` settings file adding the app's folder to its search path · print the full path | Print the full path | Such a file replaces the whole search path, and a wrong value could break `sudo`. The full path always works |
| Tool data in my home folder | Clean up at `finish` · redirect into the box from the first run | Redirect, with cleanup as the fallback | Nothing to delete afterwards, and two boxes cannot mix results |
| Boxes open at once | One · several | One | `record` and tools run from any terminal and must know their box. Two boxes can share an IP |
| Recorder | `script` · `asciinema` | `asciinema` | Better playback. The cost is one more thing to install on a fresh VM, which the installer covers |
| Install location | `/opt/pwn-broker` · under my home folder | `/opt/pwn-broker` | The customary place for add-on software on Kali, and the same path for root and a normal user |
| Build order | Organiser, recording, tools · tools earlier · all at once | Organiser, tools, recording | Usable on a real box after phase 1. Tools moved ahead of recording once the organiser was built, so tool installs could be tested while both repos are private |

## 5. Overall shape

Three phases. Each is usable when it is done.

| Phase | Contents |
|---|---|
| 1. Organiser | Install, launch checks, new box questions, targets and folders, notes window, the prompt, creds, file records, flags, `finish`, `export`, `import` |
| 2. Recording and Kali changes | `record`, `replay`, `/etc/hosts` management, VPN check, ping on target add |
| 3. Tools | The `pwn-shop` repo and its release workflow, the first six packages, the `tool` commands |

Phase 1 is built and specified in full below. Phase 3 is built next and is specified in full in section 8. Phase 2 is specified to the level decided so far and gets its own detailed design before it is built.

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

- Dependencies present: vim, a terminal emulator, tar. The tools phase adds a working `python3 -m venv`; the recording phase adds `asciinema`.
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
- The vimrc carries the Nightshift colours so the note and the prompt match. IP addresses are Amber and `<Placeholder>` text is Ember wherever they appear, the box included. The note has its own filetype, so no markdown highlighting applies.
- The note starts from `templates/notes.md`: a box with the box details and the targets at the top, then one section per target, each wrapped in a fold:

```
################################################################
#  Box:         forest                                         #
#  Platform:    htb                                            #
#  Date:        2026-11-14                                     #
#  OS:          windows                                        #
#  Difficulty:  easy                                           #
#                                                              #
#  Targets:                                                    #
#    dc01   10.10.10.161   forest.htb.local   external         #
################################################################

##########@@@@@@@@@@
Target: dc01   10.10.10.161   forest.htb.local   external

## enumeration

## foothold

## privilege escalation

@@@@@@@@@@##########
```

- The box belongs to the app. It is redrawn in full whenever the targets change, and the note is written only when that changes something. The box starts and ends with a line of `#`; if that is missing or damaged, the app leaves the note alone and says so.
- Adding a target appends its section at the end of the note. Removing a target leaves its section where it is.
- A section's `Target:` line, just under the fold's start marker, is its title. `target rename` and `target edit` rewrite it, but only while it is still exactly the line the app wrote; once I change it, it is mine.
- Apart from the box and those title lines, the app never changes anything in the note.
- The folds use the markers `##########@@@@@@@@@@` and `@@@@@@@@@@##########` and can nest. The note opens with every fold closed. A closed fold shows only the line under its start marker, or `(empty fold)` when that line is blank.
- `F8`, in normal or insert mode, adds an empty fold below the current line, open, with the cursor inside it in insert mode.
- The vimrc saves the note when I leave the window and reloads it when I come back, so the app and vim never overwrite each other. Vim checks the file every second and when I come back to the window, and reloads it only when it changed on disk; if I have unsaved changes too, it asks, as vim always does. Across a reload, open folds stay open, a fold the app just added starts closed, and the cursor stays on the same text. The check waits while I am partway through something: a selection, a command line, an operator or a count. Vim writes no swap or backup file into the box folder.
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
| `target rename <name>` | Renames the target everywhere: its folder, its row in the note's box and its section's `Target:` line, its file records, and the "found on" of its credentials |
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
- `cred list` shows the table and puts `*` after the number of a row whose secret a table cannot show exactly (a tab, another control character, or a space at either end). `cred show <n>` prints one secret alone on a line, ready to copy.
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

Built before phase 2. It spans two repositories: `pwn-shop` holds the packages, and `pwn-broker` gains the `tool` commands that install them.

The aim: `tool install <name>` puts a tool on the machine without touching Kali's own copy of anything, records that this box used it, and `finish` takes it off again.

### 8.1 What a package is

One zip per build of a tool version, named `<name>-<version>-<build>.zip`, stored without compression:

```
manifest.toml         what the tool is and how to install it
LICENSE               the upstream licence text
files/                the tool's own files, exactly as upstream published them
wheels/               Python tools only: every dependency, as wheels
wheels.lock           Python tools only: each bundled wheel pinned with its SHA-256
```

A package holds no install script. Nothing in it is executed while it is installed, apart from `pip` installing the bundled wheels, and wheels run no code on install.

`version` is upstream's. `build` is mine: it starts at 1 and goes up each time I repackage the same upstream version, for example to re-pin a dependency. A published build is never changed or replaced.

`manifest.toml`:

```toml
schema = 1
name = "ligolo-ng"
version = "0.9.2"
build = 1
kind = "both"                      # kali, upload or both
description = "Tunnelling and pivoting into internal networks"
tags = ["pivoting", "tunnel", "linux", "windows"]
upstream = "https://github.com/nicocha30/ligolo-ng"
licence = "GPL-3.0"
arch = "x86_64"
needs_root = true
examples = ["ligolo-proxy -selfcert", "agent -connect {lhost}:11601 -ignore-cert"]

[[command]]                        # a command on PATH; kinds kali and both
name = "ligolo-proxy"
type = "binary"                    # binary, python-entry or python-script
path = "files/proxy"

[[upload]]                         # a file meant for the target; kinds upload and both
path = "files/agent"
as = "agent"
note = "Linux x86_64"

[[upload]]
path = "files/agent.exe"
as = "agent.exe"
note = "Windows x86_64"

[data]                             # where the tool keeps state of its own
home = [".ligolo-proxy"]           # paths under the home folder it writes to
```

Every command in `/opt/pwn-broker/bin` is a small launcher script, never a bare link. What it runs depends on the type:

| Type | The launcher runs |
|---|---|
| `binary` | The file named by `path` |
| `python-entry` | The console script named by `entry`, inside the tool's own virtual environment |
| `python-script` | The file named by `script`, with the environment's Python |

A Python tool also carries:

```toml
[python]
versions = ["3.12", "3.13"]        # the Python versions the bundled wheels cover
lock = "wheels.lock"
wheels = "wheels"
```

A command may carry `env` (a table of environment variables) and `args` (arguments put before the user's own). In both, `{data}` stands for the open box's `tooldata/<tool>/` folder.

In `examples`, `{ip}`, `{hostname}` and `{domain}` are filled from the current target and `{lhost}` from the VPN address when one is known. A placeholder with no value is shown as `<ip>`, `<hostname>` and so on.

The app refuses a manifest or an index whose `schema` it does not know, and says to upgrade pwn-broker. A change to either format ships in the app first and in packages afterwards.

### 8.2 The pwn-shop repository

```
recipes/<tool>/recipe.toml         version, build, and where upstream publishes each file, with size and SHA-256
recipes/<tool>/manifest.toml       the manifest that goes into the package
recipes/<tool>/requirements.in     Python tools: the tool and its direct dependencies
recipes/<tool>/requirements.lock   Python tools: every dependency pinned, with the SHA-256 of each upstream file
build.py                           builds packages and an index from the recipes
fetch.sh                           downloads the published index and zips into a folder
dist/                              build output, not committed
```

No tool binary is ever committed. A recipe names the exact upstream file:

```toml
version = "1.0.3"
build = 1

[[source]]
url = "https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64"
size = 8286607
sha256 = "..."
to = "files/kerbrute_linux_amd64"
```

- A source may be a bare file, or one member taken out of a `tar.gz` or `zip` (`member = "proxy"`).
- A tool with no releases is pinned to a full commit hash, and its files are fetched from that commit.
- `build.py` downloads each source, refuses it if the size or SHA-256 differs, lays the files out, and writes the zip.

**Python dependencies are pinned in the repository, not resolved by CI.** `requirements.lock` lists every dependency at one version with the SHA-256 of each upstream file, wheels and source archives alike, for Python 3.12 and 3.13 on x86_64 Linux. I produce it with `build.py lock <tool>` and commit it. A build only downloads what the lock names and checks each hash. Where upstream publishes only a source archive, the build makes a wheel from that pinned archive. The package's own `wheels.lock` is then written from the wheels that went into it.

`build.py` also writes `dist/index.toml` describing everything it built. That folder is what `tools_index` points at when testing without a network.

**Releases.** One release per build, tagged `<tool>-v<version>-<build>`, holding three files: the zip, a `SHA256SUMS.txt`, and a card (`<name>-<version>-<build>.toml`) that repeats the manifest's descriptive fields with the zip's size and SHA-256. This is the exception to the SemVer-only release rule in `BRAND.md`, limited to this repository.

**The index** is published as the single file of a standing release tagged `index`. CI rebuilds it from the cards of every published release and replaces it. Nothing is committed by CI. The repository must not have GitHub's immutable releases turned on, or that file could not be replaced.

**CI**, on Ubuntu:

1. For each recipe whose build is already published: download the published zip. For each that is not: build it.
2. Check each package: the manifest's schema, every listed file present, the zip's layout.
3. Install each one with `pwn-broker`'s own code into a temporary folder, and run each command once to show it starts. A published build is tested from the published bytes, so CI and a user never see different files under one tag.
4. On `main` only: publish a release for each build that has none, then rebuild the index and replace the published one.

A recipe that changes without its `build` going up fails CI, because the published build cannot be replaced.

CI tests against `pwn-broker`'s `main`. While both repositories are private, it reads `pwn-broker` through a read-only deploy key.

**Withdrawing a build** is deleting its release. The next index leaves it out.

### 8.3 The index

```toml
schema = 1

[[tool]]
name = "kerbrute"
description = "Kerberos user enumeration and password spraying"
tags = ["ad", "kerberos"]
licence = "Apache-2.0"
upstream = "https://github.com/ropnop/kerbrute"
latest = "1.0.3-1"

[[tool.build]]
version = "1.0.3"
build = 1
kind = "kali"
needs_root = false
commands = ["kerbrute"]
file = "kerbrute-1.0.3-1.zip"
url = "https://github.com/Real-Fruit-Snacks/pwn-shop/releases/download/kerbrute-v1.0.3-1/kerbrute-1.0.3-1.zip"
size = 8301234
sha256 = "..."
```

- The tool-level fields come from its most recently published build, and `latest` names that build.
- A new setting, `tools_index`, says where the index is: a URL, or a folder on disk. The default is the published index file.
- In a folder, the index is `index.toml` and each zip is looked for by its `file` name in the same folder. The `url` is not used.
- The app keeps a copy in `/opt/pwn-broker/cache/`. It refreshes the copy when it is more than a day old and the source answers within two seconds; otherwise it uses what it has. `tool refresh` fetches it now.
- With no index and no cached copy, every `tool` command prints one `fail` line that says where it looked and how to set `tools_index`. It never shows an empty list as if there were no tools.

**While `pwn-shop` is private**, its release files cannot be downloaded without signing in, so the folder form is the only route. A folder is filled in one of two ways: `python build.py build` in a clone, which builds `dist/` (with no subcommand, `build.py` prints its help); or `sh fetch.sh <folder>`, which uses a signed-in `gh` to download the published index and zips.

### 8.4 Commands

| Command | Does |
|---|---|
| `tool list` | Every tool in the index: name, latest version, kind, whether it is installed for this box, whether Kali already has a command of that name. `--installed` shows only this box's |
| `tool search <words>` | Tools whose name, description or tags match every word |
| `tool info <name>` | What it does, its versions, licence and upstream, how to run it, where its files are, and its examples filled in |
| `tool install <name>[@version]` | Fetches, checks and installs it, then prints how to run it. With `@version` it takes that version's highest build |
| `tool remove <name>` | Asks first |
| `tool refresh` | Fetches the index now |
| `tool cache clear` | Empties the download cache, after asking |

```
forest/dc01 > tool install kerbrute
ok    kerbrute 1.0.3 installed
run   kerbrute              from any terminal

forest/dc01 > tool install ligolo-ng
ok    ligolo-ng 0.9.2 installed
run   ligolo-proxy          from any terminal
      sudo /opt/pwn-broker/bin/ligolo-proxy
files /opt/pwn-broker/upload/ligolo-ng/   agent  agent.exe
```

`list`, `search` and `info` work without a network, from the cached index.

### 8.5 Installing

1. Find the tool and build in the index.
2. If another unfinished box already has this tool: at the same build, this box is added to the tool's users and nothing is installed again; at a different build, stop and name that box.
3. Get the zip: from the cache when its SHA-256 matches the index, otherwise from the index's location. A zip whose size or SHA-256 does not match is deleted and the install stops.
4. Unpack it into `/opt/pwn-broker/tools/<name>/<version>-<build>/`, refusing any entry that would land outside it and any link. Check the manifest: its schema, that its name, version and build are the ones asked for, and that its `arch` is this machine's.
5. For a Python tool: check the system Python is one of the listed versions; create a virtual environment in the tool's folder with `python3 -m venv`; install the bundled wheels with `pip`, using no index, wheels only, and hash checking on. No network is used. The environment is made in its final place, because a virtual environment cannot be moved.
6. Write each command's launcher into `/opt/pwn-broker/bin`. If another installed tool already owns that command name, stop. If the name exists elsewhere on PATH, print a `warn` line that gives the other one's path and says this one wins.
7. Copy each upload file to `/opt/pwn-broker/upload/<tool>/`.
8. Record the tool in the box's `box.toml` (name, version, build, the zip's SHA-256, when) and in the app's own list of installed tools and the boxes that use each.
9. Print how to run it. For a tool that needs root, print the full path to use with `sudo`.

If any step fails, everything that step and the ones before it created is removed and nothing is recorded.

`sudo` is never reconfigured. `sudo` searches its own list of folders, not PATH, so `sudo <tool>` never finds an installed tool: it finds nothing, or Kali's own command of that name. The full path always runs the installed one, and the app prints it. When another copy of one of a root tool's commands is on PATH, install also prints a `warn` line naming the copy a bare `sudo <command>` would run.

No package in the first batch needs a system package, so the manifest has no field for one yet.

### 8.6 Removing, finishing, importing

**One build of a tool is installed on the machine at a time.** Several unfinished boxes may use it. Only one box is open at a time, so "two boxes use a tool" means one of them was left unfinished and the other was opened later. The tool stays installed, and on PATH, until the last of those boxes finishes or removes it.

- `tool remove` takes this box off the tool's users. When no box is left, it deletes the tool's launchers, its upload folder and its folder under `tools/`. It refuses to delete anything outside `/opt/pwn-broker`, whatever a manifest says. When no box is left and the tool writes to the home folder, `tool remove` also does what `finish` does with that data: it lists the paths before asking, copies them into the box, and deletes those copied in full (section 8.7).
- A launcher notes that its tool is running, in `/opt/pwn-broker/run`. `finish` and `tool remove` stop, as `finish` does for an unsaved note, while one of this box's tools is still running, and name it.
- `finish` lists on its confirmation screen the box's tools and every path under the home folder it will delete (section 8.7). Before archiving, it copies each tool's data into the box. After the archive is written and verified, it removes the tools, then the home data.
- If removal fails after the archive is verified, the box stays finished: the archive is good. Each failure is one `fail` line, and the working folder is kept. At the next launch, the app finds tools whose only users are finished or missing boxes and offers to remove them.
- `export` copies the tool data into the box too, and removes nothing.
- `import`, and reopening a finished box, list the tools the box had and ask whether to install them again. They install the same builds, checked against the SHA-256 the box recorded. A build the index no longer lists is a `warn` line, and the import carries on.
- Data collected from the home folder stays in the box as a record. It is not put back into the home folder on import.
- Tools stay installed while a box is active, across `quit` and `resume`.

### 8.7 Tool data

- A tool whose data location can be chosen is pointed at the box's `tooldata/<tool>/` folder by its launcher. Its data is in the box from the first run, and belongs to whichever box was open when the tool ran.
- A launcher finds the open box through a short file the app keeps in `/opt/pwn-broker/run`: the box's folder and the prompt's process ID. If that process is no longer running, or no box is open, the tool runs with its own defaults.
- For a tool that cannot be redirected, the manifest lists the paths under the home folder it writes to. At install, the app records which of them already existed. At `finish` and `export`, it copies those that did not exist before into `tooldata/<tool>/home/`. At `finish`, after the archive is verified, it deletes them. A `tool remove` by the last box that uses the tool copies and deletes them the same way.
- A path is deleted only if this run copied it into the box in full. A file or folder that could not be read or copied (one left by a `sudo` run, say) leaves the path in place, with a `warn` line naming it. A partial copy never replaces a full one already in the box.
- A path that existed before the tool was installed is never deleted. `finish` prints a `warn` line naming it.
- Each tool's copy in the box carries a stamp, `tooldata/<tool>/.install`, holding when the box's record of the tool was installed. A copy made by an earlier install (before an `export` and `import`, or before a box was reopened) is kept as `home-<n>` beside the new `home/`, and is never deleted. Within one install, a full new copy replaces the last one.
- When another unfinished box also uses the tool, its home data may hold both boxes' results. Installing the tool for the second box says so. `finish` on either box copies the data and leaves it in place for the other.
- Run as a normal user, the app checks both that user's home and root's, since a tool run with `sudo` may write to either. At install it records, for each home separately, which paths already existed; root's home is only checked when it is a different folder from the user's and can be read, and a path with no answer for a home counts as having existed there (copied, never deleted). Copies from root's home go to `tooldata/<tool>/home-root/`. At `finish`, and at a `tool remove` by the last box, when root's home is a different folder that cannot be read (as for a normal user on Kali, where `/root` is 0700), a `warn` line says that root's home could not be checked for that tool's data.

### 8.8 First packages

| Package | Version | Kind | On Kali | For the target | Source |
|---|---|---|---|---|---|
| `kerbrute` | 1.0.3 | kali | `kerbrute` | | One binary. Apache-2.0 |
| `pspy` | 1.2.1 | upload | | `pspy64`, `pspy32`, `pspy64s`, `pspy32s` | Four binaries. GPL-3.0 |
| `certipy` | 5.1.0 | kali | `certipy` | | PyPI `certipy-ad`, needs Python 3.12 or later. MIT |
| `targetedkerberoast` | 2024.12.16 | kali | `targetedKerberoast` | | One script at commit `ebed079`; upstream has no releases, so the version is the commit's date. GPL-3.0 |
| `ligolo-ng` | 0.9.2 | both | `ligolo-proxy` | `agent`, `agent.exe` | Three archives, one file taken from each. Needs root for the tunnel. GPL-3.0 |
| `peass-ng` | 2026.11.14 | upload | | `linpeas.sh`, `winPEASx64.exe`, `winPEASany.exe`, `winPEAS.bat` | Upstream tag `20261114-5ac9329e`. GPL-2.0 or later, with extra clauses |

- Kali already packages `pspy`, `certipy-ad`, `ligolo-ng` and `peass`. Installing mine never changes Kali's; mine wins on PATH while it is installed.
- `kerbrute` publishes no checksums. Its recipe pins the SHA-256 of the file as first downloaded.
- Upstream's proxy binary is called `proxy`. On PATH it is `ligolo-proxy`.
- Kali's own `ligolo-ng` package installs a command also named `ligolo-proxy`. While mine is installed, a bare `ligolo-proxy` runs mine, because the app's `bin` is first on PATH. A bare `sudo ligolo-proxy` runs Kali's, because `sudo` searches its own folders. Mine runs as root only as `sudo /opt/pwn-broker/bin/ligolo-proxy`.
- `targetedKerberoast` lists its dependencies without versions. The package pins them.
- PEASS-ng publishes several releases a day. The recipe pins one; taking a later one from the same day is a new build.
- PEASS-ng's licence has clauses of its author's own. Read it before this repository is made public.

### 8.9 What changes in pwn-broker

- A `tools_index` setting.
- `/opt/pwn-broker/tools/`, `upload/` and `cache/` come into use, with the app's list of installed tools and their users.
- `box.toml` records each tool: name, version, build, SHA-256 and when it was installed.
- The status bar and `status` show how many tools the box has.
- `finish` and `export` gain a step before archiving, and `finish` a step after, for tool data and removal. `finish` checks for running tools before it asks.
- The launch checks warn when `python3-venv` is missing (Python tools need it; nothing else does), and offer to remove tools left behind by finished boxes and files left by an interrupted install.

### 8.10 Testing

- The unit tests build small stand-in packages (a shell script as a binary, a hand-made wheel) and install, list and remove them in a temporary folder. They cover every kind and command type, a wrong hash, a package for another processor, an entry that would escape the folder, a command name already taken, a failed step cleaning up after itself, a tool shared by two boxes, a tool still running at `finish`, and leftovers offered at launch.
- `pwn-shop`'s CI installs the six real packages on Ubuntu and starts each command.
- The Kali checklist gains: fill a folder with `fetch.sh` and point `tools_index` at it; install each of the six; run each command; `sudo` with the printed path for `ligolo-proxy`; `finish` leaves no command, no upload folder and no tool data behind; `import` on a fresh VM puts the tools back.

### 8.11 Accepted trade

`/opt/pwn-broker/bin` is writable by my user and first on my PATH, so anything running as me could place a command I later run. On a single-user lab VM that is acceptable. It would not be on a shared machine.

## 9. What finish puts back

Whatever a box changes on Kali, `finish` undoes. Each change is recorded in `box.toml` when it is made.

| Change | Phase | Undone by |
|---|---|---|
| Lines in `/etc/hosts` | 2 | Removing the lines marked with the box ID |
| Installed tools | 3 | Removing each tool's commands, upload files and folder |
| Tool data in the home folder | 3 | Copying it into the box, then deleting it |

Not undone: the PATH line and the download cache. Those belong to the app, not to a box.

## 10. To verify on Kali

These could not be checked while designing. Each must be confirmed before the part that depends on it is built.

- The terminal reports focus changes to vim, so the note can save on leaving and reload on return. Fallback: a short reload timer.
- `x-terminal-emulator` exists and accepts a command to run.
- How vim signals unsaved changes in a way the app can detect before `finish`.
- `python3 -m venv` works on a fresh Kali, and its Python is 3.12 or 3.13, the versions the bundled wheels cover.
- Which `asciinema` version to pin, that it writes to disk as it records, and whether it can produce the plain-text copy itself.
- Where the recording indicator can be shown reliably: window title or shell prompt.
- Kali's own `ligolo-ng` package installs a command named `ligolo-proxy`. Confirm it, and that with mine installed a bare `ligolo-proxy` runs mine and a bare `sudo ligolo-proxy` runs Kali's.
- What `ligolo-proxy` writes, and where, on its first run, so its package lists the right data paths.
- PEASS-ng's licence, read in full, before `pwn-shop` is made public.

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

For the tools phase:

- Python tools use Python's own `venv` and `pip` with every dependency bundled as a wheel. This replaces the earlier choice of `uv` or `pipx`.
- Packages are stored zips with no install script; a manifest says what to run and what to copy.
- Every package has a build number beside upstream's version, and a published build is never replaced.
- Python dependencies are pinned in a lock file I commit to `pwn-shop`; CI resolves nothing.
- The index is rebuilt by CI from a card published with each release, and published as the one file of a standing release tagged `index`. CI commits nothing.
- The cached index refreshes after a day, with a two-second limit, and `tool refresh` forces it.
- While `pwn-shop` is private, a folder filled by `build.py` or `fetch.sh` is the only way to reach the packages.
- One build of a tool is installed on the machine at a time, shared by the unfinished boxes that use it. A different build is refused until the other box lets go.
- Every command is a launcher script, so the app can tell when a tool is running. `finish` and `tool remove` stop while one is.
- A removal that fails after the archive is verified leaves the box finished, and the next launch offers to remove what is left.
- Home-folder data is copied into the box and not put back on import.
- A tool with no version numbers of its own takes its upstream date as its version: `targetedkerberoast` 2024.12.16, `peass-ng` 2026.11.14.
- ligolo-ng's proxy is installed as the command `ligolo-proxy`, the name Kali's own `ligolo-ng` also uses; mine wins for a bare name, Kali's for a bare `sudo`.
- `pspy` carries all four upstream binaries. `peass-ng` carries `linpeas.sh`, `winPEASx64.exe`, `winPEASany.exe` and `winPEAS.bat`.
- While both repositories are private, `pwn-shop`'s CI reads `pwn-broker` through a read-only deploy key.
- The manifest has no field for system packages until a tool needs one.
- A tool's data is collected into the box at `export` as well as at `finish`.

## 12. Left to implementation

- Module layout and internal interfaces.
- How file changes are detected between prompts, and the size above which checksums are deferred.
- The exact wording of messages, within the voice rules in `BRAND.md`.
- The test layout. Logic is kept apart from terminal and file-system access so it can be tested without a Kali machine, and anything that touches privileges is tested as both root and a normal user.
- The release workflow for the app itself: SemVer tags, `vX.Y.Z`.
