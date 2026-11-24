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
| Python tools | `uv` or `pipx` · Python's own `venv` and `pip` with the dependencies bundled | `venv` and `pip`, dependencies bundled | `uv tool install` does not check dependency hashes; `pip` does. `venv` and `pip` come with the Python a tool runs on, and bundled wheels install with no network |
| `sudo <tool>` | A `sudo` settings file adding the app's folder to its search path · print the full path | Print the full path | Such a file replaces the whole search path, and a wrong value could break `sudo`. The full path always works |
| Tool data in my home folder | Clean up at `finish` · redirect into the box from the first run | Redirect, with cleanup as the fallback | Nothing to delete afterwards, and two boxes cannot mix results |
| Boxes open at once | One · several | One | `record` and tools run from any terminal and must know their box. Two boxes can share an IP |
| Recorder | `script` · `asciinema` | `asciinema` | Better playback. The cost is one more thing to install on a fresh VM, which the release file covers |
| Install location | `/opt/pwn-broker` · under my home folder | `/opt/pwn-broker` | The customary place for add-on software on Kali, and the same path for root and a normal user |
| Build order | Organiser, recording, tools · tools earlier · all at once | Organiser, tools, recording | Usable on a real box after phase 1. Tools moved ahead of recording once the organiser was built, so tool installs could be tested while both repos are private |

## 5. Overall shape

Three phases. Each is usable when it is done.

| Phase | Contents |
|---|---|
| 1. Organiser | Install, launch checks, new box questions, targets and folders, notes window, the prompt, creds, file records, flags, `finish`, `export`, `import` |
| 2. Recording and Kali changes | `record`, `replay`, `/etc/hosts` management, starting and checking the VPN, ping on target add |
| 3. Tools | The `pwn-shop` repo and its release workflow, the first six packages, the `tool` commands |

Phases 1 and 3 are built. Phase 2 is built last, is specified in full in section 7, and ships with the other two in the first release.

### On disk

```
/opt/pwn-broker/                 owned by the installing user
  python/                        the app's own Python, from the release file
  app/                           the application, in a virtual environment made with that Python, and the pinned asciinema
  bin/                           on PATH: pwn-broker, record, tool links and launchers
  templates/notes.md             note template, editable
  vim/vimrc                      loaded with vim -u
  vim/nightshift.vim             Nightshift colours for vim
  run/                           which box is open and its lock, running tools, recording windows, the running VPN
  state.toml                     last-used values and the answers about new boxes' playbooks and report tool, rebuilt when missing
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

Everything the app owns is under `/opt/pwn-broker`. Uninstalling it is deleting that folder and one PATH line. Upgrading replaces only `python/` and `app/`. My boxes are never inside `/opt`, so removing the app can never remove my work.

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
  vpn/                  phase 2: the VPN file this box started, never archived
  tooldata/             phase 3: data that tools write while they run
```

The folder name is `<date>_<platform>_<name>`. If that name is taken, a number is added.

## 6. Phase 1: the organiser

### 6.1 Install

```
curl -fsSL https://github.com/Real-Fruit-Snacks/pwn-broker/releases/latest/download/install.sh | sh
```

- Creates `/opt/pwn-broker`, using `sudo` once if it is not root, and gives it to the user who ran the install.
- Unpacks the release's own Python into `python/`, creates a virtual environment in `app/` with it and installs the app and its dependencies from the release file, which it has checked against `SHA256SUMS.txt`. Nothing goes into Kali's system Python.
- Writes the `pwn-broker` launcher into `bin/`.
- Adds `/opt/pwn-broker/bin` to the front of PATH in the user's shell config, and prints that it did.
- Asks no questions. Defaults are good enough to start a box immediately.

Section 6.13 is how the second step is built: a release is one file that carries its own Python, its dependencies and asciinema. The first design of this section made the environment on Kali's `python3` and let `pip` fetch the dependencies.

### 6.2 Root and normal user

Root and a normal user are two ways of setting up a VM. They are not two users sharing one box.

- No path is hard-coded to `/root`. Boxes live under the home folder of the user who installed the app.
- The app runs as the user who installed it. Started as anyone else, including through `sudo pwn-broker`, it refuses and names the user to run it as.
- Which box is open is recorded in `/opt/pwn-broker/run`, not under a home folder. Tool launchers may run under `sudo`, where the home folder is root's, and they still have to find the box.
- One helper runs privileged steps: directly as root, or through `sudo` otherwise.
- As a normal user, tools run with `sudo` leave root-owned files in the box. `finish` and `export` correct ownership before archiving.
- Every feature is tested as root and as a normal user.

### 6.3 Launch

`pwn-broker` with no arguments prints its header, runs the checks, then offers:

```
Boxes
  1  new box
  2  import a box from a file
  3  resume forest (htb, started 2026-11-14)
  4  reopen sauna (htb, finished 2026-11-13)

  choice       >
```

Choice 3 appears once per active box on this VM, and choice 4 once per finished box whose working folder was kept. `pwn-broker new`, `pwn-broker import <file>` and `pwn-broker resume [name]` go straight there. Launching from inside a box folder resumes that box.

Only one box is open on the VM at a time, enforced by a lock in `/opt/pwn-broker/run`. Other boxes stay on disk and can be resumed after quitting the current one. `record` and installed tools always belong to the open box, so nothing can be filed under the wrong machine.

**Checks, every launch.** Fast, and quiet when they pass:

```
pwn-broker 0.1.12

  ok    7 checks passed
  warn  display   no desktop session
        run vim by hand: vim -u /opt/pwn-broker/vim/vimrc notes.md
```

- Dependencies present: vim, a terminal emulator, tar. The recording phase adds the pinned `asciinema` (section 7.10). The tools phase once added a working `python3 -m venv`; section 6.13 removed that check.
- A VPN tunnel is up (section 7.8).
- A desktop session exists.
- The PATH line is present.
- The home folders exist. The app makes `active/` and `wrapped/` itself, at setup and at launch, without asking; the check speaks only when it cannot.
- `/opt/pwn-broker` is owned by the current user. If it is not, the app refuses to start (section 6.2).
- A newer release of the app exists. This never blocks, stays silent when offline, and never updates anything.

A check that can repair its problem offers to, with `fix it now? [Y/n]`. One that cannot prints the exact command to run. `check` in the prompt reruns them.

### 6.4 New box

```
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
```

- Date defaults to today. Platform defaults to the last one used on this VM, then the `default_platform` setting, then `htb`.
- OS and difficulty may be left blank.
- A target needs an IP or a hostname. Either may be blank, not both. Each takes several values separated by spaces.
- Scope is `external` or `internal`, defaulting to external.
- The target's name defaults to its hostname, or its IP when there is no hostname. The name is the folder name and what I type in the prompt.
- After each target it asks whether there is another.
- When the questions end, the folders are created, the note is written from the template, and the note window opens.
- The folder is `<date>_<platform>_<name>`. When that name is taken by a folder in `active/` or by an archive in `wrapped/`, the box gets the next free `-<n>`, and its archives carry it too.

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
- A box has one note window. The app knows it by its vim, found in `/proc`: a running `vim -u <the app's vimrc> <that box's notes.md>`, whatever terminal opened it. While it runs, opening the box, importing it or `note` prints `ok    the note is already open` and opens nothing. Outside Linux nothing is found, and a window opens as before.
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
- `,t`, `,i` and `,c` in normal mode put text after the cursor, as `a` would, without typing it, so a password holding a key name, `|` or a backslash goes in as it is. `,t` is the date and time, `%Y-%m-%d %H:%M`. `,i` is the first IP on the nearest `Target:` line above the cursor, so the target whose section the cursor is in; with none, it says so and puts nothing in. `,c` lists the lines of `lists/userpass.txt` and `lists/userhash.txt`, which the app rebuilds whenever a credential changes, numbered, and puts the chosen one in; with no lists it says there are no credentials yet.
- `,h` in normal mode lists what the vimrc adds and the fold keys, in a popup titled `note keys` that any key closes. A vim without popups prints the list instead.
- The vimrc saves the note when I leave the window and reloads it when I come back, so the app and vim never overwrite each other. Vim checks the file every second and when I come back to the window, and reloads it only when it changed on disk; if I have unsaved changes too, it asks, as vim always does. Across a reload, open folds stay open, a fold the app just added starts closed, and the cursor stays on the same text. The check waits while I am partway through something: a selection, a command line, an operator or a count. Vim writes no swap or backup file into the box folder.
- `note` in the prompt reopens the window if I closed it.
- When `finish` removes the working folder, it closes the note window: TERM to the note's vim, then to the vim's parent only when that parent's command line ends with `-e` and the note's vim command, which is a terminal started only to run it, and only when that parent has no child process left once the vim is gone. A terminal that keeps one process for several windows (Konsole in single-process mode, an alacritty instance that later opened more windows) can have that command line and still hold my other shells; it gets no signal and nothing is said. On Kali's qterminal a program ended by a signal leaves its window open, so that second signal is what closes the window; xterm closes by itself.

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
- `install.sh` prints its `ok` and `fail` lines in the same colours, chosen by the same rule: Mint and Raspberry for the word and the text colour for the rest, at the terminal's depth, and plain when the output is not a terminal, with `NO_COLOR`, or when `TERM` is `dumb`. The lines `pwn-broker setup` prints in the middle of an install then look like the installer's own.

**Feel.**

- Tab completion for commands, target names and file paths.
- History with the up arrow and Ctrl-R, kept per box, with a muted suggestion from the last matching command.
- A mistyped command gets a suggestion. Every error says what to do next. A wrong argument gets the command's usage line under the `fail` line.
- A yes or no question takes only `y`, `yes`, `n`, `no`, in any case, or Enter for its default. Anything else gets `fail  answer y or n` and the question again. The console enforces this for every such question in the app.
- The layout is section 6.14's: a header at launch, headings over groups of questions, one indent, one blank line around what each command prints.
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
| `exit` | Does what `quit` does |
| `clear` | Clears the screen |

### 6.8 Credentials and lists

One record for the whole box, in `creds.toml`. A password found on one machine often works on another, so the record is not split by target. Each entry says where and when it was found.

```
forest/dc01 > cred add

New credential
  username     > svc-alfresco
  domain       [htb.local] >
  secret       > p@ss "word" with spaces\
  kind         [password] >
  found on     [dc01] >
  note         >

  ok    cred 3 saved, found on dc01
  ok    lists updated: 3 usernames, 2 passwords, 2 pairs
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

  box      forest (htb), started 2026-11-14
  targets  2
  files    47
  archive  ~/pwn-broker/wrapped/2026-11-14_htb_forest.finished.tar.gz
  report   none: tool install report adds the tool that builds one

  finish this box? [y/N] >
```

The labels pad to the longest one in the list, and the phases' rows (`tools`, `runtimes`, `hosts`) join it, one tool or runtime per row. The `report` row says whether the report is built at step 7 (section 8.15).

Nothing happens before a yes. Then, in order:

1. If vim has unsaved changes to the note, stop and say so.
2. Record every file and its checksum. Write `manifest.toml` at the top of the box: the box's identity, whether it was packed as a finished box or an export, and every file with its target, times, size and checksum.
3. Set the status to finished and stamp the end time.
4. Correct file ownership if needed.
5. Write the archive under a temporary name, read it back, and compare it with the manifest. Only then give it its final name.
6. Copy it to the `copy_to` folder, if one is set, and verify the copy.
7. Build the report beside the archive, when the box has the report tool, and copy it to `copy_to` too (section 8.15).
8. Undo what the box changed on Kali (phases 2 and 3).
9. Ask whether to remove the working folder. The default is no. On yes, the folder is kept, with a `warn` line, when the note has unsaved changes or when the note on disk is no longer the file that was archived (`warn  the note changed after the archive was made; the folder was kept`). Otherwise the note window is closed (section 6.6) and the folder removed. If the window does not close (its vim, or the terminal started for it, is still running), the folder is kept: `warn  the note window did not close; the folder was kept`.

If any step up to 6 fails, nothing after it runs, nothing is removed, and the box goes back to active. Step 7 is the exception: a report that fails is a `warn` line, and the finish goes on. A finished archive is never overwritten without asking.

A finished box whose working folder I kept shows in the launch menu as a box to reopen. Reopening sets it back to active. Finishing it again asks before replacing the earlier archive. A new box of the same name on the same day has its own `-2` archive (section 6.4), so that question is only ever about the same box.

### 6.11 Export and import

`export` packs the box as it stands into `wrapped/<box>.exported.tar.gz`. It does not close the box or undo anything: the box stays open and its status stays active. It does bring the file records up to date, rewrite `manifest.toml` and correct ownership first, exactly as `finish` does. An exported box and a finished archive are the same format; `manifest.toml` says which one it is. A new export of the same box replaces the previous one, after the new file has been verified.

`import <file>` on any VM:

```
# pwn-broker import /mnt/share/2026-11-14_htb_forest.exported.tar.gz
  ok    8 checks passed

  ok    unpacked to ~/pwn-broker/active/2026-11-14_htb_forest
  ok    2 targets

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

### 6.13 A self-contained release

Built. This section is the design, with what was built where it differs; the differences are listed at its end. It is how section 6.1 installs the app and how section 7.10 gets asciinema. CI has built the release file twice to the same bytes, installed it with the network off in Kali and with no Python and no network in Debian, and run the whole cycle on its bundled Python; the release workflow has never run and the installer's download has never run against a real release.

**The rule.** The Kali machine only ever downloads files I built and pinned, and nothing inside them fetches anything else. Section 8.12 does this for the tools. This section does it for the app.

**Why.** The first installer downloaded a small wheel and let `pip` fetch the app's four dependencies from PyPI, at whatever version is newest and with no checksum. It then fetched asciinema from asciinema's own release. The app also ran on Kali's `python3`, so a new Kali Python could break it: the Kali image moved to 3.14 and one of the app's own tests failed there.

**Approaches.**

| Decision | Options | Chosen | Why |
|---|---|---|---|
| What a release is | A wheel, with dependencies from PyPI · one file holding everything | One file | No third-party site is contacted at install, every byte is pinned, and a fresh VM installs the same thing every time |
| The app's Python | Kali's own · its own, inside the release | Its own | A Kali upgrade cannot break the app, and the app needs only `sh`, `tar`, `gzip` and `sha256sum` from Kali, and `curl` only without `--from`. The cost is a larger file and that Python fixes are mine to ship |
| The app's Python and the tools' runtime | One shared copy · separate copies | Separate | Sharing would make the app need pwn-shop to be reachable, and the two repositories were split so neither shares the other's fate. The cost is a second 100 MB once a Python tool is installed |

**The release file.** One file per release, `pwn-broker-<version>-linux-x86_64.tar.gz`, about 47 MB:

```
pwn-broker-<version>/
  python.tar.gz        the upstream Python build, byte for byte
  wheels/              the app's wheel and the wheel of every dependency
  wheels.lock          each of those wheels pinned with its SHA-256
  asciinema            the pinned asciinema binary
  licences/            the licence of each thing in the file, and where its source is
```

- The Python is the same upstream build a runtime package carries (section 8.12): `install_only_stripped` for `x86_64-unknown-linux-gnu` from `astral-sh/python-build-standalone`, pinned in this repository by size and SHA-256.
- The app's dependencies are pinned in a lock file committed to this repository: every dependency at one version, with the SHA-256 of its wheel. All of them are pure Python, so one set of wheels serves.
- `wheels.lock` has the strict form the tools' lock has: one exact pin with its hashes per line, and nothing else.
- asciinema is the binary section 7.10 pins.
- A release publishes three files: the release file, `SHA256SUMS.txt` naming it, and `install.sh`.
- The file now distributes other people's programs: CPython, asciinema (GPL-3.0-or-later), `pyte` (LGPL-3.0) and the other dependencies. `licences/` holds each one's licence text and a note naming the exact upstream source each was built from, with its address.

**Installing.**

```
curl -fsSL https://github.com/Real-Fruit-Snacks/pwn-broker/releases/latest/download/install.sh | sh
sh install.sh --from pwn-broker-0.1.12-linux-x86_64.tar.gz
```

The installer comes from the release it installs, not from `main`, so the two always match.

1. Without `--from`, the installer downloads `SHA256SUMS.txt` and the release file from the latest release and checks the file against it. With `--from`, it uses the file on disk and contacts nothing.
2. It unpacks the Python into `/opt/pwn-broker/python/`.
3. That Python makes the virtual environment in `/opt/pwn-broker/app/`, and `pip` installs from `wheels/` with no index, binaries only and every hash required.
4. It copies asciinema into `app/bin/`.
5. It runs the app's setup, which checks asciinema against its pin, writes the launchers and the data files as now, and fails if asciinema is missing or wrong.

- The installer needs `sh`, `tar`, `gzip` and `sha256sum`, and `curl` only without `--from`. It no longer needs `python3` or `python3-venv`.
- An upgrade replaces `python/` and `app/` and nothing else.
- The release file is what is trusted. Downloaded, it is checked against `SHA256SUMS.txt`. Given with `--from`, it is for whoever gives it to vouch for: the installer prints its SHA-256 to compare with the release page. The installer holds no pins of its own and does not check the Python inside the file again. The wheels are checked by `pip` against `wheels.lock`, and asciinema by the app's setup against the app's pin.
- `--from` no longer takes a source folder or a wheel. To install from a checkout, build a release file from it first; a script in the repository does that, and CI uses it.
- `--no-asciinema` goes away: asciinema is always in the file.

**What changes in the app.**

- Setup no longer downloads asciinema, and the launch check for it no longer offers to. Setup fails on a missing or wrong asciinema; the launch check only warns, and says to run the installer again.
- The launch check that Kali's `python3` can make virtual environments goes away. Tools get their Python from a runtime (section 8.12); a schema 1 Python tool that still needs Kali's Python says so when it is installed.
- The check for a newer release stays. It asks GitHub about this repository's own releases, never updates anything, and `check_updates = false` turns it off.

**What still reaches out, and to where.**

| When | What | Where |
|---|---|---|
| Install without `--from` | The release file and its checksum | This repository's release |
| `tool install` | Packages and the index | pwn-shop's releases, or a folder on disk |
| Launch | Whether a newer release exists | This repository's releases; can be turned off |

Nothing else. With `--from` and a folder index, the install and the tool commands contact nothing; the check for a newer release is the one thing left, and `check_updates = false` turns it off.

**Building it.**

- A script in the repository builds the release file from a checkout: it fetches the pinned Python, the pinned wheels and the pinned asciinema, checks each against its pin, builds the app's own wheel, and writes the file. The same inputs give the same file, byte for byte.
- The tools that build the app's wheel are pinned too. CI builds the release file twice and fails if the two differ.
- CI builds the release file on every push. The Kali job prepares its container, switches the container's network off, installs from that file, switches the network back on, and runs the whole cycle as now. A separate `installer` job installs the file in a Debian container that has no Python and no network. That proves on every push that an install reaches nothing.
- The Kali job still runs the unit tests on Kali's own Python as well, as an early warning of the next one. The cycle runs the app on its bundled Python.
- The release workflow builds the file itself with the same script, in an environment installed from the repository's locks only, and records the file's SHA-256 straight after. It sets aside the file, `install.sh` and the release notes, with the SHA-256 of each, before anything unpinned runs. It installs the file, and runs the unit tests against the release's own wheels: the app's wheel and its pinned dependencies, taken from the file and installed into an environment made by the Python it carries. Then it publishes the file with `SHA256SUMS.txt` and `install.sh`, from a second job that runs none of the repository's code and refuses the file, `install.sh` or the notes if its SHA-256 is not the one recorded. The release is made as a draft first and then made public. Started by hand, the workflow is a dry run: every step runs but the one that publishes.

**Accepted trades.**

- A release is about 47 MB, not a wheel of a few hundred kilobytes, and the app takes about 100 MB more on disk.
- The app's Python and its OpenSSL are fixed when I ship a new release, not when Kali updates.
- Installing from a checkout takes one more step, and the build runs on x86_64 Linux only.
- x86_64 with glibc only.

**What differs from the first design.**

- The release file is gzip with stored blocks, written by the build script itself, so its bytes depend on no compression library. Its contents are already compressed.
- `setup` fails on a missing or wrong asciinema, so the installer fails; the launch check only warns.
- The installer's work folder is inside the install folder (`.install.<random>`), and a failed or interrupted install puts the previous `python/` and `app/` back. Only those: if `setup` had already started, the launchers in `bin/` and the vim and template files it may have rewritten stay as the new release wrote them. After a kill or a power cut the folder can be left behind. The installer refuses an install folder that belongs to another user.
- `setup` and the launchers run Python with `-I`.
- The release workflow has a manual dry run that runs every step but the one that publishes, and publishes from a second job that runs none of the repository's code, as a draft first. Its build environment is installed from the locks only, and the publish job checks the release file, `install.sh` and the notes against the SHA-256 each had before anything unpinned ran.
- The wheels' licence texts are taken from the wheels themselves at build time. Python's is the file pwn-shop's runtime carries. `licences/README.txt` is written by the build from `release/licences/sources.toml`.
- CI's `installer` job proves the install in a Debian container with no Python and no network. The Kali job installs with the network off and connects it again for the cycle.

**Not tested.** The release workflow, and the installer's download against a real release.

**Run by hand.** On 2026-11-16, at commit cf585e7, in Kali 2026.2 under WSL 2, as root, with Kali's own Python 3.14.7: an install made by the installer from before the release file (`sh install.sh --from .` at commit b1f66bd, an environment on Kali's Python) was upgraded with `sh install.sh --from` the release file. Every `ok` line printed, the app was then on Python 3.13.18 at `/opt/pwn-broker/python/bin/python3.13`, `config.toml` and a box folder under `~/pwn-broker/active` were untouched, and `python/.pwn-broker` was there. A second run over that install succeeded. With `python/.pwn-broker` removed, the installer refused `/opt/pwn-broker/python` as not a pwn-broker Python, and the install still worked.

### 6.14 Layout, and the fixes from the first hands-on test

Built. This section is the design, corrected where the build or a second hands-on run changed it. It changes how sections 6.3, 6.4 and 6.7 look on screen, and fixes what a full pass over every command on a real Kali showed.

**Why.** The app worked, and it did not look finished. Every line sat flush against the next: the launch checks, the menu, a string of one-word questions and the results read as one block. The words are right. What is missing is rhythm and alignment.

**Goals.**

- It opens and reads like a finished tool: a header, sections, space between them, one indent and one alignment everywhere.
- Everything it prints still copies cleanly into a note and looks right in a recording.
- The wording, the commands and the colours of section 6.7 stay. `ok`, `warn` and `fail` still start every status line.

**Non-goals.** No new commands beyond `exit` and `clear`. No change to what is stored on disk. No change to the installer or the tools.

**Anti-goals.** Boxes, frames, rules across the screen, banner art, anything that breaks in a narrow terminal or ends up as noise in copied text. Nothing that makes output depend on the terminal's width to be readable.

**Approaches.**

| Approach | What it is | Chosen | Why |
|---|---|---|---|
| Blank lines only | Today's output with blank lines between sections | No | Fixes the crowding, but the questions stay an unlabelled string and nothing lines up |
| Spacing and headings | Blank lines, a header at launch, a quiet heading over each group of questions, one indent, aligned columns | Yes | Reads as designed while staying plain text that copies and records cleanly |
| Rules and panels | Lines across the screen and a framed summary | No | Striking in a screenshot; the frames land in copied text and recordings and break in narrow terminals |

**What it looks like.**

```
pwn-broker 0.1.12

  ok    7 checks passed
  warn  vpn   no VPN tunnel is up
        start one with: vpn start

Boxes
  1  new box
  2  import a box from a file

  choice       > 1

New box
  box name     > forest
  platform     [htb] >
  date         [2026-11-16] >
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
  ok    10.10.10.161 answered in 31 ms
  ok    box forest created

forest/dc01 > status

  box         forest (htb)
  started     2026-11-16
  targets     1
  tools       0
  vpn         not up
  ...

forest/dc01 >
```

The sketch shortens `status`; it keeps every row it has now. It is what the app prints, as `tests/test_launch_layout.py` holds it for a whole launch. The first sketch had one space less after each question's label and called the first question `name`; the app kept its one space after the label padded to 12, and `box name`.

**The rules.**

- **Indent.** Everything the app prints is indented two spaces: status lines, questions, tables, lists. These are not: the prompt line (`forest/dc01 >`), the launch header, headings, output that exists to be copied or piped whole (`cred show`, `path`), `vpn log`'s lines, and the usage text and lines that stay flush left as before (`--help`, `--version`, `record --help`, `setup`).
- **Detail lines.** A line that belongs to the status line above it (the hint under a `warn`, the hosts lines under `/etc/hosts updated`, the paths under `recording saved`) is aligned under that line's text.
- **Blocks.** What one command prints is one block, with one blank line above it and one below. A command that prints nothing adds no blank line. There are never two blank lines in a row.
- **Headings.** A group of questions gets a heading, flush left, in the text colour and bold, with a blank line above: `New box`, `Target 1`, `Target 2`, `New target`, `Edit <target>`, `New credential`, `Edit credential <n>`. The start menu gets `Boxes`. A single question on its own gets no heading. Headings are sentence case and never coloured Ember.
- **Questions.** Every question is `  <label padded to 12> [default] > `, as before but indented: `  box name     > forest`. A yes or no question stands on its own, with a blank line above and below, and the console places both, so no caller can forget one.
- **Control characters.** Every line but output meant to be copied (`cred show`, `path`) shows a control character from a value as `?`, table cells included, so a hostname or credential taken from a target cannot move the cursor or change the terminal.
- **Header.** At launch, and only there, the first line is `pwn-broker <version>`, then a blank line, then the checks. `pwn-broker import <file>` is a launch with no header: it prints the checks and the import's own lines, nothing above them.
- **Lists of fields.** `status`, `target show`, `tool info`, the summary before `finish` and every other label-and-value list are printed by one function that pads the labels to the longest one. No command pads its own.
- **Help.** `help` groups the commands by their first word with a blank line between groups, both columns aligned across every group. A group's name alone (`tool`, `cred`, `host file`) prints that group the same way. Before this they were ragged.
- **Long values.** A table cell that would wrap is cut and ends in `...`; the command that shows the whole value is one step away (`cred show <n>`, `tool info <name>`). The summary before `finish` lists one tool per line.
- **No colour, no terminal.** With `NO_COLOR` the layout is the same without colour. When output is not a terminal the same lines and blank lines are written; nothing depends on the width.
- **The prompt line and the status bar** are unchanged.

**Where it applies.**

- The app itself: launch, the start menu, every question and every command at the prompt.
- `record` prints inside the window it records. It gets the indent and the aligned detail lines, with one blank line above and below what it says, and no header.
- `--help`, `--version` and `record --help` stay as they are, flush left: they are usage text, and scripts read them.
- `pwn-broker setup` prints flush left, with no header and no blank lines, as before: it runs inside the installer, whose lines are flush left.
- The installer is not part of this.

**Who leaves the space.**

- At the prompt it is automatic: whatever a command prints becomes one block, with the blank line above written before its first line and the one below after its last. A command that prints nothing gets neither.
- Outside the prompt (launch, the menu, a new box, an import) the flow asks the console for a gap or a heading where the sketch shows one. No code prints an empty line by hand.
- The console knows whether the last thing on screen was a blank line, a question included, so two never follow each other. Besides the gaps and headings it has `header`, for the launch's first line; `typed`, which the prompt calls once a command line is on screen, since the console did not write it; `handover`, called just before another program writes to the window (the shell `record` starts, a replay's playback), so that program starts below a blank line even when nothing came before it; and `clear`.

**Cutting long values.**

- Only when the output is a terminal, and at that terminal's width. Piped output and the Kali job see every value whole.
- Each table names the one column that may be cut (the secret in `cred list`, the file in `files`, the hostnames in `target list`, the run command in `tool list --installed`, the description in `tool search`). `tool list` has no long column and names none. No other column is cut; if the table still does not fit, it wraps as now.

**Headings, in full.** `Boxes` (the start menu), `New box`, `Target <n>` (counting the targets added while the box is made), `New target` (`target add`, and when `record` adds one), `Edit <target>`, `New credential`, `Edit credential <n>`, `Import usernames` (`cred import`). Yes or no questions and single questions (`vpn start`, `flag`, `import`) get none.

**Help, in full.** The commands that are one word (`check`, `export`, `files`, `finish`, `help`, `note`, `path`, `quit`, `exit`, `clear`, `replay`, `status`) come first as one group, then each family (`cred`, `flag`, `host`, `target`, `tool`, `vpn`) as its own, with a blank line between groups. `help` shows each command's one-line description. Usage lines appear when an argument is wrong.

**Fixes from the test.** Each of these was seen on a real Kali (2026.2 under WSL, as root, installed from `main`), running every command.

| Seen | Fix |
|---|---|
| Every `note`, every box opened and every import opened another vim on the same note; windows of a finished box stayed open. Four windows on one file, no swap file, so the last one to save wins | One note window per box. The app finds a box's note window by looking for the vim it starts: a running `vim -u <the app's vimrc> <that box's notes.md>`. That works whichever terminal program opened it; the app reads `/proc` for it, so on any other system nothing is found and a window opens as before. While one is running, opening the box, importing it or `note` says `ok    the note is already open` and opens nothing. `finish` already refuses to start while the note has unsaved changes. When the working folder is then removed, the app sends TERM to that vim, then to the vim's parent only when that parent's command line ends with `-e` and the note's vim command and it has no other child left, so the terminal started for it goes too and a terminal that still holds other windows stays. If the note gained unsaved changes in between, or the note on disk is no longer the file that was archived, it says so, closes nothing and keeps the folder. If the window does not close, it says so and keeps the folder too |
| Two boxes with the same name on the same day got the same archive name; `finish` asked `replace the existing archive?` and yes destroyed the earlier box's archive | A new box's folder name is checked against the archives in `wrapped/` as well as the folders in `active/`, so the second box is `..._abc-2` and its archives are too. `replace the existing archive?` is then only ever asked about the same box |
| `import` with no file given: `import failed: .: cannot open as a gzip tar ([Errno 21] Is a directory: '.')` | An empty answer asks again, with `fail  give the path of an exported box`. A folder gets `fail  <path> is a folder, not an exported box` |
| `exit` answered `did you mean: export`; `clear` answered `did you mean: cred clear` | `exit` does what `quit` does. `clear` clears the screen |
| At a yes or no question, anything that was not yes counted as no, silently: `2` at `fix it now? [Y/n]` skipped the fix | Only `y`, `yes`, `n`, `no` and an empty answer (the default) are accepted, in any case. Anything else: `fail  answer y or n`, and the question again |
| Wrong arguments got no hint: `target rename old new` said `too many arguments: new` | Every command has a usage line. An argument error prints it under the `fail` line: `usage: target rename <target>` |
| A fresh install's first launch warned `box folders are missing` and asked to fix it | The app makes `~/pwn-broker/active` and `wrapped` itself, at setup and at launch, without asking. The check stays for a folder it cannot make |
| `vpn log` and the tools row before `finish` wrapped in the middle of words | Covered by the layout rules above; `vpn log` prints OpenVPN's lines flush left and unwrapped, because they are a log to copy. The log carries text the VPN server sends, so a control character in it is shown as `?` like everywhere else, and a tab stays a tab |

**Constraints.**

- Layout lives in the console layer, not in the commands. Commands say what a line is (a status, a detail, a heading, a field list, a table, a gap); the console decides how it is spaced. A command never prints a blank line or pads a label by hand.
- The console the tests use records the same calls, so a test can check that a heading or a gap was asked for without knowing how it is drawn.
- Output that other programs or my own notes rely on does not change: `cred show` prints the secret and nothing else, `path` prints the path and nothing else, the text copy of a recording keeps its format.
- The Kali job in CI reads the app's output; it is updated in the same change and must stay green.

**Left to the builder.** How the console tracks whether the last thing printed was a blank line; the exact names of the new console methods; how a command declares its usage line; where each existing hand-padded list moves to the shared function.

**Checked by hand afterwards.** On 2026-11-16, the whole flow in the Kali under WSL (2026.2, as root, Kali's qterminal), every command, as in the test that found the above. Seen: the layout as the sketch shows it; one note window, with `ok    the note is already open`, and neither the vim nor its terminal left after `finish` removed the folder; the `-2` folder and archive for a second box of the same name on the same day; both `import` messages; `exit` and `clear`; `fail  answer y or n` at a yes or no question; the usage line under a wrong argument; a first launch that asked nothing about folders; a long hash cut with `...` in `cred list`. Not seen by hand: `vpn log`'s lines, the tools rows before `finish` with several tools, and a note that gained unsaved changes or changed on disk between `finish`'s two questions. On qterminal a program ended by a signal leaves its window open, which is why the app also signals a terminal started only for the note's vim.

**Known, and left.** After Ctrl-C at a yes or no question, the next line follows directly under the question. `--help` and `--version` are printed without colour. On a terminal that hosts all its windows in one server process (gnome-terminal), the app closes the note's vim and cannot close the window; whether that terminal then closes the window by itself has not been tried.

## 7. Phase 2: recording and Kali changes

Ships in the first release, with phases 1 and 3. It adds `record` and `replay`, the box's lines in `/etc/hosts`, the `host` and `vpn` commands, a VPN check and a ping for each new target.

### 7.1 Approaches

| Decision | Options | Chosen | Why |
|---|---|---|---|
| Times in the text copy | On every line · marker lines · none | On every line | One grep answers both what happened and when |
| When the text is written | When the window closes · while recording | When the window closes | The text is always the settled screen, and there is no second process per window. The cost: a window that is still open has no text yet |
| How lines are worked out | A terminal model from `pyte` · a model of my own · asciinema's own text output | `pyte` (my call) | zsh redraws the command line as I type, and a home-made reader gets that subtly wrong. asciinema's own text output carries no times |
| `finish` with a window recording | Warn · refuse | Refuse (my call, changed from "warn") | Anything recorded after the archive is made would be deleted with the box folder. A running tool already stops `finish` the same way |
| An unknown address given to `record` | Send me to the prompt · add it from `record` | Add it from `record` | Decided earlier. It makes `record` a second writer of the box, which section 7.3 deals with |

### 7.2 record

`record [target]`, typed in any terminal window:

```
# record 10.10.10.161

  ok    recording this window for dc01 (forest)
        targets/dc01/recordings/2026-11-14_1432.cast
        exit this shell to stop

[rec dc01] ┌──(root㉿kali)-[~]
└─# exit

  ok    recording saved, 14 min
        targets/dc01/recordings/2026-11-14_1432.cast
        targets/dc01/recordings/2026-11-14_1432.txt
```

- The target can be given as an IP, a hostname or a name, matched the way `target use` matches. With no target, it records for the box's last-used target and says which.
- It always files under the box that is open. With no box open it says so, records nothing and exits with status 1.
- Recording starts only when I type the command, and ends when I exit that shell.
- Every window gets its own file, named by its start time to the minute. If that name is taken, `-2`, `-3` and so on are added.
- Inside a window that is already recording, `record` refuses and names the target that window records for.
- An argument that starts with `-` is never taken as a target: `record --help` prints the usage, and any other option is refused with it.
- It starts my own shell (`$SHELL`) under the pinned `asciinema`, quietly, with a title of the box name, the target name and the box ID. That title is the recording's header naming the box.
- Keystrokes are never captured, only what the terminal shows. A password typed at a hidden prompt is not recorded. One typed on a command line is, and goes into the archive.
- asciinema is run with an empty settings folder of the app's own, so nothing in my home folder changes how it records. Recordings are only ever written to a local file. Nothing is uploaded.
- While recording, the shell's prompt starts with `[rec <target>]`. This is done for zsh and bash, by starting the shell with a small startup file of the app's that loads my own and then adds the prefix. Any other shell records without the prefix.
- A marker in `/opt/pwn-broker/run/recordings/` says which windows are recording: one file per window, holding the process start time, the target and the file. A marker whose process is gone is ignored and cleared, as for tools.
- `record` runs only as the user who installed the app, the same rule as the prompt (section 6.2). Run through `sudo` by a normal user, it refuses and says to run `record` first and `sudo` inside it. Otherwise root would own the note and the new target's folder, and the prompt could no longer write them.
- Read from asciinema's source, each event is written to the file as it happens. CI has shown it: the `recording` job records a real zsh session and a real bash session through a pseudo-terminal, and in both the output is in the file while the window is still recording. Had it held output back, a killed window would lose what was held and an export would hold slightly less. Nothing else here would change.
- If `asciinema` is missing or does not match its pinned checksum, `record` says to run `check` in the prompt, which says to run the installer again, and starts nothing.
- If `asciinema` ends with an error, `record` says so with its status, and still writes the text copy from whatever is on disk.
- A window that is closed or killed leaves its `.cast` as far as it was written. Its text copy is written later (section 7.4).

### 7.3 An address that is not a target

```
# record 10.10.10.200

  10.10.10.200 is not a target of forest. add it? [y/N] >
```

On yes, `record` asks the same questions as `target add`, with the address filled in, and creates the target exactly as `target add` does: folders, note section, lists, the `/etc/hosts` offer and the ping. Then it records. The prompt's current target does not change.

That makes two programs that can change a box, so:

- A lock file in `/opt/pwn-broker/run` is held by the prompt for the length of each command, and by `record` while it adds a target.
- `record` waits up to five seconds for the lock. If the prompt is in the middle of a command, it says so, adds nothing and records nothing.
- At the start of each command, the prompt reloads the box, its targets and its credentials from disk if any of them changed since it last read them.

`record` writes box data only to add a target. Everything else it writes is its own recording.

### 7.4 The text copy

Beside each `.cast` the app writes a `.txt` of the same name, for reading in vim and for grep:

```
box      forest  6f9c1e0a-52c1-4b7e-9d0c-1a2b3c4d5e6f
target   dc01
started  2026-11-14 14:32:07
cast     2026-11-14_1432.cast

14:32:07  ┌──(root㉿kali)-[~]
14:32:15  └─# nmap -sC -sV 10.10.10.161
14:32:15  Starting Nmap 7.95
14:32:41  PORT    STATE SERVICE
14:32:41  88/tcp  open  kerberos-sec
14:40:12  [full-screen program until 14:43:30, see the cast]
---- 2026-11-15 ----
00:01:10  └─# evil-winrm -i 10.10.10.161 -u svc-alfresco
```

- Every line of text starts with the time its last character was drawn, in the VM's local time, then two spaces. An empty line stays empty.
- A line of dashes with the date appears wherever the date changes.
- The text is made by replaying the recording through a model of the terminal at the recorded size, following every resize. A line is taken when it scrolls off the top of the screen, when the screen is cleared (`clear`, Ctrl-L), when a resize leaves no room for it, and at the end for whatever is still on the screen. A command half typed when the screen is cleared is taken as it stood, and appears again when it is finished.
- Colours and control sequences are dropped. A redrawn line (a progress bar, a command edited before Enter) appears once, as it last stood.
- A line the terminal wrapped is joined back into one, so a long hash is one line to grep.
- A full-screen program (vim, less, a menu) draws on the terminal's alternate screen. Its content is left out and one line says when it ran. The `.cast` still holds it.
- Trailing spaces are removed. Nothing else is changed.
- It is written by `record` when its window closes. `export`, `finish` and `replay` write it for any recording whose text is missing or older than its `.cast`, so a killed window still gets one. For a window still recording, `export` writes the text as far as the recording has got.
- It is written to a temporary file and renamed, so a half-written text never stands in for a whole one.
- Making it needs no `asciinema`: the app reads the `.cast` itself. It reads the format the pinned `asciinema` writes (asciicast v3). An incomplete last line, as a power cut leaves, is ignored. A file it cannot read gets a `warn` line naming it, and no text.
- It has a time limit, counted from the recording's size: 30 seconds for each megabyte, its own from when it starts, and a base of up to 10 seconds from one minute that all the recordings one `export`, `finish` or `replay` writes share as it goes by (`record` gives its recording the whole minute). The terminal model's work is counted in the screen's cells, not in the recording's bytes: a few bytes fill or clear a 1000 by 1000 screen, and a crafted recording of a few hundred bytes took minutes. Crafted recordings therefore spend the shared minute and never another recording's time by size. The time is looked at before each call to the screen and before each piece of 256 characters an event is fed in, so a run of text drawn in one call, or an escape sequence that never ends, is stopped too. A recording past its time gets a `warn` line and a text copy that says so, newer than the recording, so it is not tried again; deleting it tries again.

### 7.5 replay

```
forest/dc01 > replay

  n  started           length         size
  1  2026-11-14 14:32  14 min         212 KB
  2  2026-11-14 15:10  recording now

forest/dc01 > replay 1

<the recording plays here>

forest/dc01 >
```

| Command | Does |
|---|---|
| `replay [target]` | Lists the recordings of the current target, or the named one, oldest first |
| `replay [target] <n>` | Plays one in the prompt window. Idle gaps longer than two seconds are cut to two. Space pauses, Ctrl-C stops and returns to the prompt |

The playback starts below a blank line and the prompt comes back below another, as around the shell `record` starts; a `warn` line about asciinema's status goes under the second. Playing needs `asciinema`. Listing does not. A recording whose window is still recording is listed as `recording now` and is not played until that window exits.

### 7.6 Finish, export, import, status

- `finish` refuses while a window is recording for the box, and names the targets: `fail  2 windows are still recording (dc01, web01). exit them, then finish again`.
- `export` goes ahead and warns that a window is still recording. It writes the missing text copies first. A recording still being written is packed up to its last whole line, and `files.toml` and the manifest hold the size and checksum of exactly that much, so the archive verifies like any other. A recording only ever grows at its end, so that much of it cannot change.
- `quit` warns if a window is still recording. The window keeps recording into the box.
- Recordings are files in the box like any other, so `files.toml` and `manifest.toml` record them and `import` restores them. Between commands, a `.cast` that is still being recorded is not hashed again each time it grows. Its checksum is filled in when its window closes, or at `export` for the part that is packed.
- `status` gains a `recordings` line. The status bar shows `rec 2` while windows are recording, and nothing when none are.

### 7.7 /etc/hosts

A target with an IP and a hostname can have one line in `/etc/hosts`:

```
10.10.10.161 forest.htb.local dc01.htb.local  # pwn-broker 6f9c1e0a-52c1-4b7e-9d0c-1a2b3c4d5e6f
```

- `target add` (at launch, in the prompt or from `record`) and `target edit` ask `add dc01's hostnames to /etc/hosts? [Y/n]` when the target has both and has no line yet. The default is yes, because a line is easy to take back and nearly every box needs one.
- The line is the target's first IP and all its hostnames, ending with a marker that holds the box ID.
- `box.toml` records which targets have a line. The box's lines in the file are always rewritten as a set from that record, so `target edit` changes the line and `target remove` takes it out.
- `finish` removes exactly the lines marked with the box's ID, after the archive is verified. If it cannot, the box is still finished, the lines are printed, and the next launch offers to remove them.
- Opening a box (new, resumed, reopened or imported) puts its recorded lines back if they are missing, and says so.
- `import` asks first. The names in an archive's `box.toml` are whatever it says, and opening the box writes them with `sudo`, so an archive from someone else could point `github.com` anywhere. When the file does not already hold exactly those lines, `import` shows each one and asks `this box wants these lines in /etc/hosts. add them? [y/N]`. The default is no, unlike the question at `target add`, because I did not type these names. On no or Ctrl-C the box forgets its lines and says how to add one later; on yes, opening the box writes them as for any box. A name whose last label is not one labs use (`htb`, `local`, `lan`, `internal`, `corp`, `home`, `lab`, `localdomain`, `localhost`, `test`, `example`, `invalid`, `arpa`, `vl`, `thm`, `offsec`) is named after its line: `(not a lab name: github.com)`.
- At launch, lines marked with the ID of a box that is finished or no longer on disk are offered for removal, one question per box, default yes like the question that added them. While another prompt has a box open, launch does not look.

**Clashes.** The first line in `/etc/hosts` that names a host wins, so a second one would do nothing.

- A hostname already on a line marked for another of my boxes: that line is taken out, with a `warn` naming the box. It returns when that box is opened again.
- A hostname already on an unmarked line with the same IP: nothing is added for that name, and the app says it already resolves.
- A hostname already on an unmarked line with a different IP: nothing is added, and the `warn` shows the line, its number and the command to run once I have removed it. Unmarked lines are never changed.

**Hostnames found later.** A domain, a subdomain or a virtual host on the same IP is one more hostname of the same target. `/etc/hosts` has no wildcards, so each is added by name:

```
forest/web01 > host add crm.board.htb dev.board.htb

  ok    web01 now answers to 3 names
  ok    /etc/hosts updated
        10.10.11.5 board.htb crm.board.htb dev.board.htb
```

| Command | Does |
|---|---|
| `host add <name> [name ...]` | Adds hostnames to the current target. Its `/etc/hosts` line, `lists/hosts.txt` and the note follow |
| `host remove <name> [name ...]` | Takes hostnames off the current target. Tab completes the names it has |
| `host` | Every hostname in the box by target, and whether each is in `/etc/hosts` now |
| `host file on [target]` | Puts the line for the current or named target into `/etc/hosts` |
| `host file off [target]` | Takes it out and forgets it. The target keeps its hostnames |

- If the target has a line, `host add` and `host remove` rewrite it without asking. If it has none and has an IP, `host add` asks the `/etc/hosts` question once.
- A name the target already has is skipped, and the app says so. A name another target of the box has is refused, naming that target: within a box a hostname belongs to one target.
- Only a plain hostname is accepted, the same rule as for writing the file.
- Removing the last hostname takes the target's line out. A target with no IP keeps at least one hostname.
- A subdomain I want kept apart, with its own folders, is its own target with the same IP. It gets its own line.
- `target edit` still works for hostnames, and still replaces the whole list.

**Writing the file.**

- The whole file is read, changed in memory and written back in place, not renamed over: the file can be a mount, and its owner and mode must not change. Every byte that is not one of my marked lines is kept as it was, apart from a line break added before my line when the file does not end with one. My lines always go at the end.
- Just before writing, the file is read again. If it changed, the app starts over once, then gives up with a `warn`.
- As root the app writes it directly. As a normal user it writes the new content under `/opt/pwn-broker/run` and copies it into place with `sudo`. If that fails or I decline, nothing is changed and the line is printed for me to add.
- Only a plain hostname is written: letters, digits, hyphens and dots, 253 characters at most. Anything else is refused with a `warn`, so a hostname can never carry a second entry or a comment into the file.
- If `/etc/hosts` is missing, a link, or not a regular file, nothing is written and the app says why.

### 7.8 VPN

**The check.**

- A launch check, `vpn`: `warn  vpn   no VPN tunnel is up`, then `start one with: vpn start` on the next line, when no interface named `tun<n>` has an IPv4 address. It never blocks.
- With several tunnels, the lowest-numbered one with an address is used.
- The status bar shows `vpn 10.10.14.7`, or `no vpn`. It is read again with each command, and at most every ten seconds while the bar redraws. A read that fails counts as no VPN and never holds the prompt up.
- `status` shows the same.
- `{lhost}` in `tool info` examples is filled from this address.

**Starting one.**

```
forest > vpn start

  vpn file     [/root/Downloads/lab_user.ovpn] >
  ok    copied to vpn/lab_user.ovpn
  ok    vpn up, 10.10.14.7 on tun0
```

| Command | Does |
|---|---|
| `vpn start` | Asks for the `.ovpn` file, copies it into the box, starts OpenVPN in the background and waits for the tunnel |
| `vpn stop` | Stops the VPN the app started |
| `vpn status` | Whether a tunnel is up, its address and interface, since when, from which file, and which box started it. For a tunnel the app did not start, only that one is up |
| `vpn log` | The last 20 lines of OpenVPN's log |

- The question takes a full path, with Tab completing it. Its default is the file used last time, on any box, so the next box is one Enter.
- The file is copied into `vpn/` in the box, readable only by me. A copy of the same name with the same content is reused; with different content the new one gets `-2`, `-3` and so on. A file larger than 1 MiB is refused: no `.ovpn` file is that big.
- OpenVPN runs in its own background mode, not in a window and not in tmux. Closing any window, or quitting the prompt, does not end it. Nothing extra has to be installed.
- What the running VPN needs lives in `/opt/pwn-broker/run/vpn/`, not in the box: a second copy of the file that OpenVPN is started from, its log, its process ID, and a marker holding the process start time, the box that started it, the file's name and its SHA-256. A VPN therefore outlives the box that started it.
- OpenVPN is started with the original file's folder as its working folder, so a file that names a certificate or key beside it still works.
- As root the app starts it directly. As a normal user it starts it through `sudo`.
- `vpn start` waits up to 15 seconds for a `tun` interface with an address. If OpenVPN ends before that, the app says so and prints the last lines of the log. If it is still trying, the app says so and names `vpn log`.
- A file that asks for a username or password is asked for it in the prompt window, by OpenVPN itself, before it goes to the background.
- If the VPN the app started is already up, `vpn start` says so, starts nothing, and this box records that it used it. To change to another file, `vpn stop` first: the app keeps track of one VPN at a time.
- If a tunnel is up that the app did not start, `vpn start` says so and asks before starting another. The default is no.
- `vpn stop` stops only a process the app started: the process ID must be alive, have the recorded start time and be `openvpn`. It waits up to five seconds and says whether the tunnel is gone. A tunnel I started by hand is reported and never touched.
- A marker whose process is gone is cleared, as for tools.
- With no `openvpn` on the machine, `vpn start` says how to install it and starts nothing.

**The box's record.**

- `box.toml` records each VPN the box started or used: the file's name, its SHA-256 and when.
- The `vpn/` folder is left out of `files.toml`, the manifest and every archive, because the file holds my VPN key. An archive carries only the record above. `finish` deletes the folder with the rest of the box.
- `import` restores the record and starts nothing.

**Finish.**

- If a VPN the app started is still up, `finish` says so with its address and asks `stop it? [y/N]`. The default keeps it, so the next box can use it. `export` and `quit` never touch it.

### 7.9 Ping

- Each new target with an IP is pinged once at its first IP, with a two-second wait, from wherever it was added.
- `ok  10.10.10.161 answered in 43 ms`, or `warn  10.10.10.161 did not answer a ping; Windows targets often do not`.
- Ctrl-C during the wait cancels the ping and nothing else.
- With no `ping` on the machine, the app says once per session that it did not check.

### 7.10 Install and launch checks

- Section 6.13 supersedes the first design of this section, in which the installer downloaded `asciinema` 3.2.1 from asciinema's own GitHub release and `install.sh --no-asciinema` skipped it. Now the release file carries the static x86_64 Linux build, the installer copies it to `/opt/pwn-broker/app/bin/`, and the app's `setup` checks it against a SHA-256 pinned in the app. That folder is not on PATH, so Kali's own `asciinema`, if there is one, is untouched.
- There is no `--no-asciinema`: asciinema is always in the file.
- If asciinema is missing or does not match, `setup` fails and so does the installer. Later, the launch check only warns, and everything but `record` and `replay` works.
- `record` is a launcher in `/opt/pwn-broker/bin`, written by setup and put back by the launch check if it is missing.
- `pyte` 0.8.2 becomes a dependency of the app, pinned exactly because the text copy leans on how it works inside.
- New launch checks: `asciinema` (present and matching its pin; a `warn` says to run the installer again) and `vpn`.
- `record`, `asciinema`, `openvpn`, `ping` and `ip` join the command names a tool package may not use, in both repositories. The app runs each of them by name, and a tool's command would be found first.
- asciinema is GPL-3.0-or-later and is never shipped in this repository; the release file carries it, with its licence text and the address of its source. `pyte` is LGPL-3.0 and is installed by `pip` as a dependency.

### 7.11 What changes in pwn-broker

- The box lock and the reload at the start of each command (section 7.3).
- The target commands call the `/etc/hosts` offer and the ping.
- `finish`, `export` and `import` gain recording and hosts steps through the same hook lists the tools use.
- The status bar and `status` gain the VPN address and the recording count.
- The file scan and the archive leave the box's `vpn/` folder out.
- CI installs the pinned `asciinema` from the release file, with zsh and bash, on Ubuntu and runs real recordings there.

### 7.12 Testing

- The text copy is plain Python over a `.cast`, tested everywhere. Its cases: hand-written files for a wrapped line, a redrawn line, a full-screen program, a cleared screen, a resize to a shorter window, midnight, and a cut-off last line.
- `/etc/hosts` is tested against a file in a temporary folder, as root and as a normal user, including that every other byte survives.
- The VPN read, the ping, `openvpn` and `asciinema` are each run through a seam the tests replace. No test starts a real VPN. The real `asciinema` runs only in CI on Linux, where a zsh session and a bash session are recorded through a pseudo-terminal and their text copies checked; those tests skip elsewhere.
- The prompt prefix, the window behaviour and Kali's own zsh settings are checked by hand on Kali, and `docs/kali-checks.md` gains those steps.

### 7.13 Accepted trades

- A window that is still open has no text copy until it closes or the box is exported.
- A full-screen program appears only in the `.cast`.
- A password typed on a command line is recorded.
- The `[rec]` prefix exists for zsh and bash only.
- Only `tun` interfaces count as a VPN.
- An archive holds no copy of the VPN file, only its name and checksum.
- Only OpenVPN files are started. WireGuard is not handled.

### 7.14 Serving files

Sending a file to a target is a chore on every box: start a web server in the right folder, work out the tunnel address, type the download line. `serve` does it from the prompt.

- **What is served.** The current target's `upload/` folder, for my own files, and `/opt/pwn-broker/upload/`, where tools already put their target-side files. Tool files are under the tool's name; a top-level name that is also a tool's folder is the tool's. Each request is looked up afresh, so a file dropped in later is served.
- **Where.** The tunnel's address by default. An interface name or an address of this machine can be given; with neither a tunnel nor a name, nothing starts, so files are never offered to the whole LAN by accident. `0.0.0.0` is taken only when typed, with a `warn` line.
- **Port.** 80 as root, for the shortest line, and 8000 for a normal user, who cannot bind 80. The prompt binds the socket itself, so a port in use or an address the machine does not have is a `fail` line at once, then passes the socket to the server.
- **Nothing to find.** No listing, of `/` or any folder, and every URL starts with a random part of six letters and digits, new each run (62^6, about 57 billion). Other players on the same VPN can reach the tunnel address; without the random part, even a known tool path gets `404`. Dot names, links and anything outside the two folders are never sent. The download lines carry the random part, so it is never typed.
- **Background.** The server runs as a child of a short-lived middle process, in a session of its own, so it outlives `quit`, a closed window and Ctrl-C, and when it ends it is reaped by init rather than lingering as a zombie whose ID still looks alive. The prompt reports it started only once the server has written its own `listening` line. `/opt/pwn-broker/run/serve/marker.toml` records its process ID, start time, box, target, address, port and random part; like the VPN's marker, a process is only taken as the server while its ID, start time and command line all match.
- **Lines.** `serve` says how many files it offers and lists none: with a few tools installed the list is long, and one line is wanted at a time. `serve files` prints them, and `serve files <word>` only the paths holding the word, any case: `iwr <url> -OutFile <name>` on a box whose OS starts with `win`, `wget <url>` on Linux and the BSDs, both otherwise.
- **Taking files back.** Getting a file off a Windows target usually means another server (smbserver, uploadserver). A `PUT` to `/<random part>/<name>` saves into the target's `loot/` instead, written to a temporary name the file scan leaves out, then linked into place under the name or `name-2` and on, so nothing is replaced and a cut transfer leaves nothing. It needs a `Content-Length` (`411` otherwise), one plain name (`404` otherwise), at most 4 GiB (`413`) and 1 GiB left free after it (`507`). The server speaks HTTP/1.1, so a client's `Expect: 100-continue` is answered at once. `loot/` is never served.
- **Log.** One line per request in `serve.log` (mode 600): time, client address, the request line with anything unprintable shown as `?`, and the status. `serve log` shows the last 20.
- **Finish.** The summary lists a server this box started, `(will be stopped)`, and `finish` stops it. One started by another box is left alone. A server that will not stop is a `warn` line naming `serve stop`; the box is finished anyway.

### 7.15 Scans

The first scans of a box are the same every time: a quick look, every port, sometimes UDP. `scan` runs them in the background into the target's `scans/` folder.

- **Modes.** `quick` is `-sC -sV` on nmap's top 1,000 ports. `full` is two stages, `-p- --min-rate 5000` for every TCP port, then `-sC -sV -p <the ports found>`, so scripts run only where something answers; with no open port the second stage is skipped. `udp` is `-sU --top-ports 100` and needs root, so a normal user is refused before anything starts. A bare `scan` is quick then full. Each mode's options are a setting, `scan_quick`, `scan_full` and `scan_udp`, split as a shell would.
- **Output.** `-oA` into `targets/<target>/scans/<date>_<time>-<mode>`, so nothing is overwritten and the files sort by when they started.
- **Background.** The prompt starts a runner of its own, `pwn_broker.scanning`, through a short-lived middle process in a session of its own, as `serve` does; it runs each nmap in turn. `/opt/pwn-broker/run/scans/<box>/<target>.toml` is its marker, checked by process ID, start time and command line. `scan stop` signals the runner's whole session, so the nmap it is waiting on stops too. One scan per target at a time.
- **Being told.** When a mode is done the runner writes a record beside the marker. The prompt reads the records after each command, says each once (the open ports and the `.nmap` file, or a `warn` with nmap's status) and deletes it. After the command, not before, so a `clear` does not wipe it. A record waits for the box's next prompt if none is open. The status bar shows `scan <target>` while one runs.
- **Finish.** A running scan of the box blocks `finish`, as a recording does: what it wrote after the archive was made would be lost, and the folder would be kept as changed.
- **Log.** `<target>.log` beside the marker holds each command as `$ nmap ...` and what nmap printed; `scan log` shows the last 20 lines.

### 7.16 Searching

The one place a password, a hostname or a share name turned up is often a file I saved hours ago, or something a recording caught on screen. `search` finds it.

- **Scope.** The current target by default: its folder and its section of the note, found by its `Target:` line below a fold start and taken to the fold's matching end, nested folds included. `search <target> <text>` for another target, `search all <text>` for the whole box. A first word is a scope only when it is `all` or a target's exact name and more follows, so a single word is always what is looked for.
- **What is read.** Regular files only, no links and no dot names. Binary files (a NUL in the first 8 KiB) are skipped. Recordings are searched through their `.txt` copies; the `.cast` beside each is skipped. `vpn/` is never read, since it holds the VPN key. A file over 16 MiB is skipped and named.
- **Output.** Hits grouped by file, path relative to the box, each with its line number and the line, trimmed, with anything unprintable shown as `?` and cut at 200 characters. At most 200 hits, then a count of the rest.

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

Section 8.12 replaces `[python].versions` with a required runtime, in schema 2.

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

CI tests against `pwn-broker`'s `main`. While both repositories were private, it read `pwn-broker` through a read-only deploy key; both are public now and the key is gone.

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

**While `pwn-shop` was private**, its release files could not be downloaded without signing in, so the folder form was the only route. It is public now, and the folder form is for working with no network. A folder is filled in one of two ways: `python build.py build` in a clone, which builds `dist/` (with no subcommand, `build.py` prints its help); or `sh fetch.sh <folder>`, which uses a signed-in `gh` to download the published index and zips.

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
  run   kerbrute   from any terminal

forest/dc01 > tool install ligolo-ng

  ok    ligolo-ng 0.9.2 installed
  run   ligolo-proxy   from any terminal
        sudo /opt/pwn-broker/bin/ligolo-proxy
  files /opt/pwn-broker/upload/ligolo-ng   agent  agent.exe
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
- The launch checks warned when `python3-venv` was missing, which section 6.13 removed; they offer to remove tools left behind by finished boxes and files left by an interrupted install.

### 8.10 Testing

- The unit tests build small stand-in packages (a shell script as a binary, a hand-made wheel) and install, list and remove them in a temporary folder. They cover every kind and command type, a wrong hash, a package for another processor, an entry that would escape the folder, a command name already taken, a failed step cleaning up after itself, a tool shared by two boxes, a tool still running at `finish`, and leftovers offered at launch.
- `pwn-shop`'s CI installs the seven real packages, the six tools and the `python-3.13` runtime, on Ubuntu and starts each tool's commands.
- The Kali checklist gains: fill a folder with `fetch.sh` and point `tools_index` at it; install each of the six; run each command; `sudo` with the printed path for `ligolo-proxy`; `finish` leaves no command, no upload folder and no tool data behind; `import` on a fresh VM puts the tools back.

### 8.11 Accepted trade

`/opt/pwn-broker/bin` is writable by my user and first on my PATH, so anything running as me could place a command I later run. On a single-user lab VM that is acceptable. It would not be on a shared machine.

### 8.12 Python runtimes

Built and tested in both repositories. pwn-shop published the `python-3.13` runtime and build 3 of `certipy` and `targetedkerberoast` on 2026-11-15. Where the build differs from the first design, this section describes what was built.

**Why.** A Python tool runs on Kali's own `python3`, from wheels bundled for a fixed list of versions. That has two faults. A tool that needs a Python Kali does not have cannot be packaged. And every time Kali moves to a new Python, the Python tools are refused until I rebuild them: the Kali image went to 3.14 and refused both.

**Approaches.**

| Decision | Options | Chosen | Why |
|---|---|---|---|
| Where a tool's Python comes from | Kali's own · bundled inside each tool · a shared runtime package · fetched at install by `uv` or `apt` | A shared runtime package | A stripped Python build is about 34 MiB. Inside each tool, twenty Python tools would carry 680 MiB of the same files; shared, it is 34 MiB per Python version in use, and a fix to Python is one rebuild. Fetching at install needs the network and is not pinned by my checksums, and `apt` changes Kali |
| Which tools use one | Every Python tool · only those Kali's Python cannot run | Every Python tool | A Kali upgrade can then never break a tool, a tool carries wheels for one Python, and there is one way to build a Python tool |
| What a tool may depend on | Runtimes only · other tools too · version ranges | Runtimes only, by name | Tool-to-tool dependencies and ranges are where package managers get complicated. A list leaves room for another kind of runtime later |
| How the runtime is carried | The upstream archive as one file · its files unpacked into the zip | The upstream archive, byte for byte | The archive is about 34 MiB and holds about 95 MiB of files, a thousand of them links. Kept whole, the package stays small and its checksum is upstream's own |

**A runtime package.** A package of kind `runtime`, named for its Python series:

```
manifest.toml
LICENSE                     Python's licence, and the notices of what the build bundles (below)
files/python.tar.gz         the upstream build, byte for byte
```

```toml
schema = 2
name = "python-3.13"
version = "3.13.18"                  # CPython's own version
build = 1
kind = "runtime"
description = "CPython 3.13, for the tools that require it"
upstream = "https://github.com/astral-sh/python-build-standalone"
licence = "PSF-2.0 and others (see LICENSE)"
arch = "x86_64"

[runtime]
archive = "files/python.tar.gz"
python = "python/bin/python3.13"     # the interpreter, inside the unpacked archive
series = "3.13"                      # the Python the requiring tools' wheels are built for
```

- The source is the `install_only_stripped` build for `x86_64-unknown-linux-gnu` from `astral-sh/python-build-standalone`, pinned in the recipe by size and SHA-256. Upstream publishes its own checksums, so the pin has a second source.
- The archive carries no licences for the libraries it bundles, so the package's `LICENSE` holds: CPython's licence from the archive; the licence files the build's own `PYTHON.json` names for CPython and for the libraries it links, from upstream's full distribution; CPython's `Doc/license.rst` at the tag `v3.13.18`, which includes mimalloc's notice; the HACL* notice from the source CPython vendors at that tag; and the licences of `pip` and of the libraries it vendors. A search of the interpreter library found mimalloc and HACL* compiled in, and both have their notices there. The binary was not otherwise audited. The manifest's `licence` is `PSF-2.0 and others (see LICENSE)`.
- A runtime has no `[[command]]`, no `[[upload]]`, no `[data]` and no `[python]`. A manifest with any of them is refused.
- A runtime puts nothing in `/opt/pwn-broker/bin`. Kali's own `python3` is never shadowed, and the reserved command names do not change.
- Package names may now hold a dot, so `python-3.13` is a name: lower-case letters, digits, hyphens and dots, starting with a letter or digit, with no two dots together and none at the end. Both repositories apply the same rule.

**A tool that requires one.**

```toml
schema = 2
requires = ["python-3.13"]

[python]
lock = "wheels.lock"
wheels = "wheels"
```

- `requires` names runtime packages. A Python tool names exactly one. A tool that is not Python names none.
- `[python].versions` is gone from schema 2: the bundled wheels cover the runtime's series and nothing else.
- A package has schema 2 only if it is a runtime or requires one. Every other package stays schema 1, so the builds already published still rebuild byte for byte.
- The index gains the same two things: an entry's kind may be `runtime`, and a build may carry `requires`. Its schema becomes 2.
- The app reads both schemas. A schema 1 Python tool installs as before, on Kali's own Python, where that Python is one it lists. Builds 1 and 2 of `certipy` and `targetedkerberoast` were such tools; they were withdrawn on 2026-11-15, before any box had used them, so none is published.

**Installing.** `tool install certipy`:

```
forest/dc01 > tool install certipy

  ok    python-3.13 3.13.18 installed (runtime, 34 MB)
  ok    certipy 5.1.0 installed
  run   certipy   from any terminal
```

The size is the runtime's zip in mebibytes, rounded to a whole number: 34 for this build.

1. The app picks the tool's build and reads what it requires from the index. The checks that do not need the package (a runtime's name, another build already on the box or in use by another box, a command name taken) run first, so a tool that would be refused costs no download.
2. For each runtime it requires that is not on the machine, the app takes the latest build of that name from the index, downloads it, checks its size and SHA-256 as for any package, unpacks the zip into `tools/<runtime>/<version>-<build>/`, and unpacks the archive under the rules below into a `root/` folder inside it. The interpreter must be a regular file inside `root/`, links followed. The archive file is then deleted; the zip stays in the download cache. A runtime that is already there, at any build, is used as it is. One whose files are missing or damaged is removed and installed again. While installed tools require it, it is installed again at the build their environments were made by, in the same folder, because they point there. The runtime's own row names that build, and stays until the new row replaces it, so a failed attempt leaves the next one the same choice. With no runtime row, each tool's row in the installed list names the build it was made on, and for a row from before that, the records of the boxes that use it do. If the index no longer lists that build, or the tools name different builds, the install is refused and nothing is removed: a `fail` line names the runtime and the tools that require it, and says to remove those tools and install them again.
3. The tool's virtual environment is made by the runtime's interpreter, and `pip` installs the bundled wheels into it exactly as now: no index, binaries only, every hash required.
4. If any step fails, everything the command created is removed, a runtime it installed for this tool included, and nothing is recorded or logged. The app says so for the runtime: `ok    python-3.13 3.13.18 removed (runtime)`, then the line that says why the install failed. A runtime that was there before the command is left alone. So is a damaged runtime the command put back because other installed tools require it.

Making the environment runs the runtime's interpreter. That is the one new thing that runs during an install, and it is the pinned upstream Python. The interpreter and `pip` run isolated from the caller: with `-I`, and `pip` with `--isolated`; in the tool's own folder, not the folder the prompt was started in; with every `PYTHON*` and `PIP_*` variable taken out of the environment and `PIP_CONFIG_FILE` set to the null device, so no user or system `pip` configuration is read. Kali's `python3`, which still makes the environment of a schema 1 Python tool and reports its version first, runs the same way.

**Unpacking the archive.** The app does this itself, and refuses the whole runtime if any member breaks a rule:

- Only regular files, folders and symbolic links. No hard links, devices, pipes or sparse files.
- A link's target is relative and stays inside the runtime's folder once resolved, through the archive's other links too, in at most 40 links.
- No absolute names, no name that leaves the folder, no backslash, colon or control character in a name or a link's target, no empty or `.` part, and no name twice. Nothing is written through a link or inside a file.
- Names and link targets are at most 4,096 bytes, and each part of one at most 255.
- At most 20,000 members and 1 GiB unpacked.
- Every header is read and checked before anything is written. A damaged or cut-short archive is refused then: the tar must end as a tar does, and the gzip stream's checksum and length must match. What is decompressed is bounded too: no more than each entry's declared size plus a small allowance for its headers is ever read, so an archive cannot make the app decompress more than 1 GiB and that allowance per entry.
- Modes become 644 or 755, and everything belongs to me.
- It is unpacked into a temporary folder beside `root/` and renamed in, so a half-unpacked runtime is never used. If anything fails, the temporary folder is removed.
- The app writes each file itself rather than through `tarfile`'s extraction, whose filters differ across Python 3.11 patch releases.

**Sharing and removal.**

- One build of a runtime is on the machine at a time, shared by every tool that requires it.
- A runtime is needed while any installed tool requires it. The app works that out from the installed tools; a runtime has no list of users of its own.
- `finish` says what became of each tool the box held: `ok    kerbrute 1.0.3 removed` when its files were deleted, `ok    kerbrute 1.0.3 kept; forest still uses it` when another unfinished box has it. A tool the box no longer held gets no line.
- At `finish` and at `tool remove`, after the tools are gone, any runtime no installed tool requires is removed: `ok    python-3.13 3.13.18 removed (runtime)`. While a box folder cannot be read, it may hold a tool that requires the runtime, so nothing is removed and a `warn` line names the box. The launch checks offer to remove a runtime no installed tool requires, and the check for files left behind covers runtimes too.
- `box.toml` records, with each tool, the runtime it was built on: name, version, build and SHA-256. It is a note of what ran, not a pin: any build of a runtime serves any tool built for its series.
- `import`, and reopening a finished box, install the tools again as now, and with them whatever runtime they require: the one already on the machine, or the latest build in the index. When that is not the build the box recorded, the app says so and carries on: `ok    certipy now runs on python-3.13 3.13.18-2; this box used 3.13.18-1 before`.
- A newer build of a runtime in the index does not replace one that is installed. It is used the next time none is.

**Commands.**

- `tool list` and `tool search` show tools, not runtimes. `status` counts tools.
- `tool info <tool>` gains a line: `requires    python-3.13 (34 MB, not installed)`. It names what the build this box has installed requires, or, when the box does not have the tool, what the latest build requires.
- `tool install` and `tool remove` refuse a runtime's name: `python-3.13 is a runtime; it is installed with the tools that need it`.
- `finish`'s summary lists the runtimes it will remove beside the tools: `runtimes  python-3.13 3.13.18   (will be removed)`.
- The summary says of each tool what `finish` will then do with it, judged the way the removal is. A tool another unfinished box has reads `tools  kerbrute 1.0.3   (will be kept; forest still uses it)`, and its data in the home folder is not listed. A tool the box records but does not hold has no row: one the machine lacks because the offer to install it again was declined, or one only other boxes hold.

**In pwn-shop.**

- A recipe for each runtime, `recipes/python-3.13/`, with the source pin and the manifest. `build.py` builds kind `runtime`: no wheels, the archive carried as it is.
- A Python tool's recipe names its runtime in its manifest. `build.py lock` resolves for that runtime's series alone, and the build refuses a wheel that does not fit it. The fixed list of Python versions goes away.
- The first runtime is `python-3.13`, at CPython 3.13.18. `certipy` and `targetedkerberoast` become build 3, each requiring it.
- CI builds the runtime with the other packages and installs every tool through pwn-broker's own code, which now installs the runtime from the built index first.
- A new CI job installs each recipe's current build inside the official Kali image, from a folder index and with the container's network switched off, and starts each command with `--help`. So the real tools are run on a real Kali, and an install is shown to reach nothing. Publishing waits for it: a published build can never be replaced, so a build that fails on today's Kali is not published. Older builds are not tested there.

**Testing.**

- The archive rules, one test per refusal, on every platform.
- `requires` in a manifest and in the index; the install order and what is removed when a step fails; removal after the last tool; a runtime left behind; `import`.
- On Linux, a stand-in runtime: a small archive whose `python3` is a script that runs the machine's own Python, so a real environment is made from it.
- The real upstream archive has been installed and used on Kali by this repository's `kali` job, which wraps it in a test runtime package and installs a small Python test tool on it: the archive passed the unpacking rules, and the tool ran on the runtime's Python 3.13 while Kali's own was 3.14. pwn-shop's CI on its `runtimes` branch (run 43768259174) passed every job. Its `kali` job, in a container whose network was confirmed off, on Kali 2026.3 with Python 3.14.8, installed through this app's own code the `python-3.13` runtime (3.13.18, build 1), `certipy` 5.1.0 build 3 and `targetedkerberoast` 2024.12.16 build 3, each on the runtime and each answering `--help`, and `kerbrute`, `ligolo-ng`, `peass-ng` and `pspy`. The runtime zip CI built on Ubuntu has the same SHA-256 as the one built on Windows. The same jobs passed on pwn-shop's `main` (run 43772170454), and that run published the runtime and build 3 of the two tools and replaced the index, which is now schema 2.

**Accepted trades.**

- The first tool that requires a runtime costs that runtime: a download the app shows as 34 MB (the zip in mebibytes, rounded), about 100 MB unpacked, and the zip, which stays in the download cache.
- The runtime carries its own OpenSSL and other libraries. They are fixed when I publish a new build of the runtime, not when Kali updates.
- The runtime's interpreter runs during an install.
- x86_64 with glibc only, as for every other package.
- A tool has one Python runtime. No tool depends on another tool.

### 8.13 Tool history

Built. Where the build differs from the first design, this section describes what was built.

**Why.** A box records the tools it has, and that record goes into its archive. But `tool remove` deletes the tool's line, so a tool I tried and took off leaves no trace. And nothing spans boxes: to find which boxes used a tool, and at which version, I would have to open every archive.

**In the box.**

- A removed tool stays in `box.toml`, with the time it was removed. A box therefore shows every tool it ever used.
- A tool installed again after a removal gets a new line; the removed one stays.
- Everything that asks what the box has now (the lists, the count, `finish`, `import`) looks only at the lines with no removal time.
- `finish` does not mark anything removed. A finished box keeps its tools on record as current, so reopening it can offer them again.
- The same build installed again while its line is current (reopening the box, `import`) keeps that line, with the new install's time and runtime. The install time stamps the tool's data in the box, so each install's copy of that data is kept apart from the others. The log keeps a line for every install.
- `tool history` shows the box's whole record: each tool with its version and build, when it was installed (for a current line, the latest install), when it was removed, and the runtime it ran on.

**Across boxes.** One log, `~/pwn-broker/tools.log`, beside `active/` and `wrapped/`:

```
2026-11-15T14:32:07+00:00  install  forest (4412e505-2998-424f-855d-1fbaaabe2894)  python-3.13 3.13.18-1  sha256:9c1e...  runtime
2026-11-15T14:32:09+00:00  install  forest (4412e505-2998-424f-855d-1fbaaabe2894)  certipy 5.1.0-3  sha256:a380...
2026-11-15T16:05:41+00:00  remove   forest (4412e505-2998-424f-855d-1fbaaabe2894)  certipy 5.1.0-3  sha256:a380...
```

- One line for each tool installed, each one removed with `tool remove`, and each one taken off at `finish`, with the runtimes installed and removed beside them. A runtime's line ends in `runtime`.
- Only what a box did is logged. A `finish` line is written only for a tool the box still held on the machine, not for one a declined reopen left uninstalled. A runtime installed for a tool that then failed, and taken away again, gets no line, and nor does the tool. A runtime is logged as removed by a box only when a tool the box took off required it; one that no tool required before the command is still removed, with no line. Removals by the leftover checks at launch are not logged: they belong to no box.
- Each line holds the time, what happened, the box by name and ID, the tool with its version and build, and the package's SHA-256. In the box's name, a control or format character (a bidirectional override, a zero-width space) is written as `?` and a run of spaces as one, since the name may come from someone else's archive.
- It lives with my boxes, not under `/opt/pwn-broker`, so reinstalling or removing the app does not lose it. It follows the `home` setting.
- It is only ever added to. The app never reads it back, and never trims it.
- If it cannot be written, the app warns once a session and carries on: a log must never stop an install.
- It is readable only by me: mode 600, set again each time a line is added. Each line is added in one write, not through the app's usual replace-the-file save.

### 8.14 Playbooks

My notes are a large reference written for reading, not for working from mid-box. I want a smaller set cut from them: short playbooks, one per job, that I read straight into the box's note and fill in. I improve them between boxes, so a box takes the current playbooks like a tool and gives them back at `finish`, and the next box gets the newer ones.

**Goals**

- `tool install playbooks` gets them, checked and pinned like any tool, with or without a network.
- One command in the note window reads a playbook into the note, below the cursor.
- Every value I must supply is a `<Placeholder>`, and each playbook carries the lines that fill them in throughout that playbook and nowhere else.
- I find a playbook by phase, OS or service, whichever I am thinking of at the time.
- A box records which playbooks build it was worked with, and reopening it installs that build again.

**Non-goals**

- Filling placeholders for me. The app knows a few values (the target's IP, `tun0`), but most it cannot, and I fill them by hand.
- Keeping a playbook already in a note in step with later releases. Once read in it is a copy, and the note records what I did on that box.
- Converting my notes automatically. Playbooks are written by hand from them.

**Anti-goal:** playbooks that make the note harder to work in, because they bury my own notes, break the box header or the target folds, or flood `search` with template text.

#### Approaches considered

| Approach | Trade |
|---|---|
| **A repository of its own, `pwn-playbooks`, with a `pwn-shop` recipe pinning each release (chosen)** | Gets the index, the size and SHA-256 checks, the cache, `fetch.sh` and import for free, and keeps `pwn-shop`'s rule that its packages are upstream's own files. Each improvement is two releases: the playbooks, then the recipe |
| The playbook source committed in `pwn-shop` | One repository fewer, but it breaks that rule, and a typo fix would run the whole tool CI |
| A repository of its own with its own `playbooks update` command in pwn-broker | One release per change, but a second download path, cache and offline story beside the one tools already have |

#### The playbooks repository

`Real-Fruit-Snacks/pwn-playbooks`, public, so its README and Pages follow the same standard as the other pwn repositories. The playbooks are licensed CC BY 4.0, since they are writing, not code.

```
playbooks/                  the playbooks, one file each, in the tree below
placeholders.toml           every placeholder name a playbook may use, each with one line on what it means
build.py                    checks the tree and builds the release zip
```

```
playbooks/
  01-checklists/      ad.md  standalone.md  web.md
  02-enum/            smb.md  ldap.md  mssql.md  snmp.md  nfs.md ...
  03-web/             sqli.md  lfi.md  upload.md ...
  04-foothold/        shells.md  file-transfer.md ...
  05-passwords/       spraying.md  hashcat.md ...
  06-privesc/
    linux/            sudo.md  suid.md  cron.md ...
    windows/          services.md  tokens.md  credential-hunting.md ...
  07-ad/              kerberoasting.md  asrep.md  adcs.md ...
  08-pivoting/        ligolo.md  chisel.md ...
```

The folders go by phase, with OS and service folders only where they help. Finding a playbook goes by file name, wherever it sits, so the tree never has to guess which of the three I will think of.

**A source file** is a title line and a body:

```
# Windows privesc: services

## Find a service I can change
...
```

The body is plain markdown that reads well raw in vim: headings, lists, `- [ ]` checklists and commands. Commands take values only as placeholders.

**`build.py check` refuses**, naming the file and line:

- a file name used twice anywhere in the tree, since lookup is by name;
- a folder or file name that is not lowercase letters, digits and hyphens;
- the reserved word `<Replace>` anywhere in a body;
- a `<Name>` that differs only in case from a listed placeholder (`<TargetIp>`), since that is a typo.
- in a body: a fold marker, a line of 20 or more `#` (the box header's rule), an Obsidian callout (`> [!`), a `[[link]]`, or front matter.

**Placeholders** are written `<Name>` in PascalCase, from one list: `<TargetIP>`, `<Domain>`, `<DCIP>`, `<Username>`, `<Password>`, `<Hash>`, `<LHOST>`, `<LPORT>` and so on. One name per meaning: my notes use both `<User>` and `<Username>`, and the playbooks use only `<Username>`.

Only a name on the list is a placeholder. Anything else in angle brackets is literal text, so an XML payload, an Apache `<Directory>` block or a PowerShell `List<String>` is written as it is. The list avoids names that are common tags.

**`build.py build`** wraps each source file and zips the tree. A built playbook reads:

```
##########@@@@@@@@@@
Playbook: Windows privesc: services   06-privesc/windows/services   2026.11.19
my
/^\%>'yEND OF services PLAYBOOK$
mz
:'y,'zs/<TargetIP>/<Replace>/ge
:'y,'zs/<Username>/<Replace>/ge
:'y,'zs/<Password>/<Replace>/ge
'y

Fill in:  <TargetIP>  <Username>  <Password>

## Find a service I can change
...

END OF services PLAYBOOK
@@@@@@@@@@##########
```

- The whole playbook is one fold, and its `Playbook:` line is what the fold shows when closed: title, path and release.
- The run block comes first, with one replace line per placeholder, then a blank line.
- `Fill in:` follows it and lists the same placeholders in the same order: every one the body uses, in order of first use, each once. It sits below `my`, so it is inside the range the block replaces.
- `END OF <name> PLAYBOOK` is the last line inside the fold. `<name>` is the file name without `.md`, unique across the tree.

**Filling one in**, entirely in plain vim:

1. Over each `<Replace>`, type the value: `ca>` on it removes the word and its angle brackets and starts insert mode. Delete with `dd` each line I am not filling.
2. On the `my` line: `V}` selects the run block down to its blank line, then `"qy` copies it into register `q`.
3. `@q` runs it. It marks the block's first line `y`, finds this playbook's end line, marks it `z`, replaces each placeholder between the two, and goes back to `y`.

The `Fill in:` line is inside the range, so afterwards it shows the values used, and any placeholder still on it is one not yet filled. The search is forward from the block, so the same playbook read in for two targets fills only the copy it belongs to.

Fixed parts of this, and why:

- **Marks `y` and `z`**, not `a` and `b`, so marks I set myself are rarely overwritten.
- **Pasting the block from the terminal does not run it.** Vim's bracketed paste inserts pasted text as text, which is why the block goes through a register.
- **The end line is anchored** with `^` and `$`, or the search would match its own line in the block.
- **The search looks only below mark `y`** (`\%>'y`). Vim's searches wrap round the end of the file, so with this playbook's end line deleted, a plain search would find an earlier copy's end line above. Every replace line would then be a backwards range, which interactive vim offers to swap, taking its answer from the rest of the register, and the fill would rewrite everything between the two copies. Limited to lines below `y`, the search fails, vim stops the register there, and nothing changes.
- **Both ends are marked**, because `:s` leaves the cursor on the last line it changed and a range ending at the cursor would shrink with each line.

**Releases.** One per change. I tag it by hand, `v<YYYY.MM.DD>`; a second release on the same day adds `.1`, `.2`. That is a date-based exception to the SemVer rule in `BRAND.md`, limited to this repository, as `pwn-shop`'s tags are. On a tag, CI runs the check, builds with the version taken from the tag, and publishes the release. Each release holds `playbooks-<version>.zip` and `SHA256SUMS.txt`. A published release is never changed.

#### The `notes` package kind

`pwn-shop` gains a recipe, `recipes/playbooks/`, whose single source is the release zip, unpacked whole into `files/`. That is a new source form for `build.py`: today a source is a bare file or one member of an archive. Its manifest:

```toml
schema = 3
name = "playbooks"
version = "2026.11.19"
build = 1
kind = "notes"
description = "Playbooks to read into the note and fill in"
tags = ["notes", "playbooks"]
upstream = "https://github.com/Real-Fruit-Snacks/pwn-playbooks"
licence = "CC-BY-4.0"
arch = "any"

[notes]
root = "files/playbooks"
```

- A `notes` package has no commands, no uploads, no tool data and no requirements, and `needs_root` is false. `arch = "any"` is new and is accepted on every machine.
- Manifest schema 3 and index schema 3 bring the kind in, the way schema 2 brought in runtimes, because an older pwn-broker rejects a whole index containing a kind it does not know. With schema 3, an older app says to upgrade instead of failing on the kind.
- **Installing** unpacks it into `/opt/pwn-broker/tools/playbooks/<version>-<build>/` like any tool, writes nothing to `bin/` or `upload/`, and records it in `box.toml` like any tool.
- **One build at a time, as for any tool** (section 8.6). If an unfinished box still holds an older build, `tool install playbooks` stops and names that box: finish it or remove the playbooks there first, or install that build to share it. Letting builds sit side by side was considered and dropped, because the installed list is keyed by name throughout and reworking that is not worth it for an unfinished box.
- **The note window finds the open box's playbooks** through `/opt/pwn-broker/run/notes`: one folder per line, the `root` of each `notes` package installed for the open box. The app writes it at launch, resume, `tool install` and `tool remove`, and empties it at `quit` and `finish`.
- `tool install playbooks` prints, after its `ok` line, how many playbooks it holds and how to read and list them (the `list` line since 0.1.11):

```
forest/dc01 > tool install playbooks

  ok    playbooks 2026.11.19 installed (64 playbooks)
  read  :Pb <name>      in the note window
  list  playbook list   at the prompt
```

- `finish`, `export`, `import` and reopening a box treat it as they treat any tool. Reopening an archived box installs the same build, so the playbooks it was worked with come back with it.
- `pwn-shop`'s CI step 3 has no command to run for a `notes` package. It checks instead that `root` exists, holds at least one `.md` file, and that every file starts with a fold marker and a `Playbook:` line.

#### In the note window

- **`:Pb <name>`** reads the playbook with that file name, from the folders in `run/notes`, into the note below the cursor. Tab completes names from every installed playbook, matching any part of the name. Like F8, it never lands inside the box header: on a box line it reads below the box, and on a closed fold it reads below the fold. The new fold is left open with the cursor on its `my` line.
- **`:Pb`** with no name lists every playbook, grouped by folder, to pick one by number, as `,c` does for credentials.
- With nothing in `run/notes`, `:Pb` prints `no playbooks for this box: tool install playbooks at the prompt`, and reads nothing.
- When two installed `notes` packages hold the same file name, completion and the list show each with its package's name, and `:Pb <name>` asks which.
- **`,x`** toggles `[ ]` and `[x]` on the current line.
- The note's syntax file already shows `<Placeholder>` text in Ember (section 6.6), `<Replace>` included, so what is still to fill stands out with no change.
- `,h` lists `:Pb` and `,x`.

#### At the prompt

Added in 0.1.9, because the note window was the only place to see which playbooks a box had, and picking one by number from `:Pb`'s list is a slow way to browse 88 of them.

- **`playbook list [<word>...]`** lists every playbook installed for the open box, from the same packages `run/notes` names, sorted by path as `:Pb` lists them: name, folder and title, the title taken from the `Playbook:` line. A package column is added only when two packages are installed, since only then can a name be in both. Words keep the playbooks with every word in the name, folder or title, in any case, as `tool search` matches. The last line gives the count and the release.
- **`playbook show <name>`** prints one in the terminal: the `Playbook:` line, then the playbook without its fold markers, its run block and its `END OF` line, which only mean something in vim. It takes the name `:Pb` takes, the path, or the package and path; a name two packages hold fails and names both. A file that does not start as a built playbook is shown whole under its path.
- The text is a package's, so it goes out the way `scan log` and `vpn log` lines do: flush left so a command copies cleanly, with a control character shown as `?`. Placeholders are left as they are, in keeping with the non-goal above: filling in is the note's job.
- Tab after `playbook show` completes the name from any part of it, in any case, as `:Pb` does, from the folders on disk only.

#### In new boxes

Added in 0.1.10, because nearly every box wants the playbooks and `tool install playbooks` was a step to remember in each one.

- **Asked once, at the first new box, not by the installer.** `curl … | sh` gives the installer the script itself on stdin, so it has no terminal to ask on unless it opens `/dev/tty`, and an install with none, in CI or a script, would have to guess. `--from` contacts nothing, and the playbooks come from the index. And no box exists yet: playbooks belong to a box, which records their build and gives them back at `finish`.
- **The question comes once the box is made**, `install playbooks in this box and every new box? [Y/n]`, naming both, since the box just made is the first to get them, and the answer goes in `state.toml` beside the last platform and VPN file. An install that is upgraded asks at its first new box, too. Interrupting the question saves nothing, installs nothing and opens the box; the next new box asks again.
- **With yes, the install is `tool install playbooks`, run by the launch**, after the box holds the open lock, so no other launch sweeps a half-made install as leftovers, and before the note window opens, so its vim has them from the start. A failed install is a `warn` line with the reason and `try again with: tool install playbooks`; the box opens all the same, and the answer stays, so the next new box tries again.
- **`playbooks = true` or `false` in `config.toml` wins** over the saved answer, and with it set nothing is asked.
- **The answer is confirmed before the install starts**, on an `ok` line, `saved: new boxes get the playbooks` or `saved: new boxes start without playbooks`, so it shows while the download runs. Under it, detail lines in the form the launch checks use (`start one with: vpn start`) say what to type to change it: the setting, and after a no, `tool install playbooks` for the one box. An answer that cannot be saved is a `warn` line instead, with `the next new box asks again`.
- **Only `new`.** A resumed box is already set up, and a reopened or imported box offers the tools it recorded, at their builds.

#### search

`search` skips, in the note only, lines inside a playbook's fold (from its `Playbook:` line to its `END OF` line) that still contain a `<Placeholder>`, as the note's highlighting finds them, and the run block in full. Inside a playbook every such line is template text, so the list of names is not needed here and `search` works the same once the box's playbooks are removed. A line I have filled in is my work and is searched like any other. When lines were skipped, the output ends with one mute line saying how many.

#### Order

1. pwn-broker: manifest and index schema 3, the `notes` kind, `run/notes`, `:Pb`, `,x` and the `search` skip, released.
2. `pwn-playbooks`: the repository, `build.py`, `placeholders.toml`, and a first release, even a small one. Writing the playbooks themselves is separate work, done by hand from my notes once the tooling works; the count in the `tool install` example above is only an example.
3. `pwn-shop`: the whole-archive source form, the recipe, CI's check for `notes`, and the index at schema 3.

#### Testing

- `pwn-playbooks`' CI runs `build.py check` and a build on every change, and its unit tests cover each refusal above.
- pwn-broker's unit tests build a stand-in `notes` package and cover install, remove, two builds for two boxes, `run/notes` at each point where it is written, finish and import, an older-schema index, and the `search` skip.
- `tests/test_vim.py` runs vim headless on a note: `:Pb` lands below the box and below a closed fold; the run block, filled in and run through a register, replaces only inside its own playbook; the same playbook read in twice fills only the copy it belongs to; a deleted line leaves its placeholder in place.
- The Kali checklist gains: `tool install playbooks` from a `fetch.sh` folder, `:Pb` from the note window, fill one in, `finish` removes it, `import` puts the same build back.

#### Accepted trades

- Each improvement is two releases, the playbooks and then the recipe. Automating the second (a playbooks release opening the `pwn-shop` change) can come later.
- A value containing `/`, `&`, `\` or `~` breaks or changes the replacement unless I escape it (`\/`, `\&`). That matters mostly for passwords.
- An unfilled replace line, if I forget to delete it, turns that placeholder into `<Replace>` throughout the playbook. It stays visible, but which placeholder it was is lost.
- Marks `y` and `z` are overwritten each time a run block runs.

#### Left to the builder

- `placeholders.toml`'s full list beyond the names above, and its format.
- How `:Pb`'s list is laid out on screen, within the note window's existing popup style.
- How `pwn-shop`'s whole-archive source refuses links and entries that would escape `files/`, matching section 8.5's rules.

### 8.15 The report at finish

Added in 0.1.12. [pwn-report](https://github.com/Real-Fruit-Snacks/pwn-report) turns a finished or exported archive into a private report folder; pwn-shop packages it as `report`, and `tool install report` puts its `pwn-report` command on the box like any tool.

- **Built by `finish`, from the finished archive.** After the archive is written and copied, and before the undo steps, which take the report tool off with the rest. So the report needs no step of its own, and always matches the final archive.
- **Run, never imported.** `/opt/pwn-broker/bin/pwn-report build <archive> -o <folder>`, with no shell, the environment other tool runs get, the archive's folder as its working folder, and 600 seconds. Status 0 with the folder in place is a report built; anything else is one not built, and pwn-report's `fail  <reason>` line, when there is one, is the reason given. No pwn-report code runs in pwn-broker's process, so its Python and its version are its own.
- **Only when the box has it.** The box's current tools include `report` and its command is in `/opt/pwn-broker/bin`. `finish`'s summary says which, before the archive is made: `report  will be built beside the archive`, or `report  none: tool install report adds the tool that builds one`.
- **Beside the archive, never replacing one.** `<archive minus .tar.gz>.report`, or the first free `.report-2`, `.report-3`, ... for a box finished again after it is reopened or imported. With `copy_to`, the folder is copied there through a `.part` folder renamed into place, as the archive is; a `.part` folder left by a copy that was cut off is replaced, and a `copy_to` that is `wrapped/` itself gets no copy, as the report is there already. pwn-report runs in the archive's folder and is given whole paths.
- **A report never fails, hangs or undoes `finish`.** A `fail` line, a status with no line, a folder said built but not there, a command that cannot run and a bug in this code are each a `warn` line, `the report was not built: <why>`, and `finish` goes on to its undo steps; the archive is not touched. Past 600 seconds the run gets SIGTERM, which pwn-report answers by removing its staging folder, then SIGKILL after 5 seconds, and any `.<report>.tmp-*` folder left beside the archive is removed. Ctrl-C while it runs stops the report the same way, and a Ctrl-C anywhere else in the report step, its copy to `copy_to` included, is a `warn` line too: none of them stops the finish or skips its undo steps.
- **New boxes**, as for the playbooks: the 0.1.10 question is now one per offered package, playbooks then report, each asked, saved and installed in turn, with its own setting (`report = true` or `false`) and saved answer (`new_box_report` in `state.toml`). The playbooks' question and lines are unchanged. For the report tool: `install the report tool in this box and every new box? [Y/n]`, then `saved: new boxes get the report tool` or `saved: new boxes start without the report tool`, with the same detail lines worded for it. An index without a `report` package is a `warn` line, `report tool not installed: <why>`, as a failed playbooks install is.
- **Not at `export`, and no `report` command at the prompt.** Both can come later; the report is for the box as finished.

## 9. What finish puts back

Whatever a box changes on Kali, `finish` undoes. Each change is recorded in `box.toml` when it is made.

| Change | Phase | Undone by |
|---|---|---|
| Lines in `/etc/hosts` | 2 | Removing the lines marked with the box ID |
| A VPN the app started | 2 | Asking whether to stop it. The default keeps it for the next box |
| The file server, `serve` | 2 | Stopping it when this box started it |
| A running scan | 2 | Nothing: `finish` waits until no scan of the box runs |
| Installed tools | 3 | Removing each tool's commands, upload files and folder |
| Tool data in the home folder | 3 | Copying it into the box, then deleting it |

Not undone: the PATH line and the download cache. Those belong to the app, not to a box.

## 10. To verify on Kali

These could not be checked while designing. Each was meant to be confirmed before the part that depends on it was built; the parts were built and tested on Windows and on Ubuntu in CI first. CI's `kali` job now runs one whole box in the official Kali image (`kalilinux/kali-rolling`, Kali 2026.3 when it first passed), as root, in a container, with a virtual display and `xterm`, the container's gateway as the target and an OpenVPN file with no server behind it. Each line below says what that run confirmed and what is still open; anything that needs a real desktop, a Hack The Box tunnel or a normal user with `sudo` is still open. The steps for every line are in `docs/kali-checks.md`.

- The terminal reports focus changes to vim, so the note can save on leaving and reload on return. Fallback: a short reload timer. Still open: the Kali run has no real desktop.
- `x-terminal-emulator` exists and accepts a command to run. Confirmed in the Kali image, where it is `lxterm`, Debian's wrapper around xterm, and takes `-e`. Still open for the terminal a Kali desktop opens by default.
- How vim signals unsaved changes in a way the app can detect before `finish`. Still open: the Kali run never leaves the note unsaved.
- `python3 -m venv` works on a fresh Kali, and its Python is 3.12 or 3.13, the versions the bundled wheels cover. Overtaken by section 6.13: the app no longer runs on Kali's Python, so neither half matters to the install. In the Kali 2026.3 image Kali's Python was 3.14.10 and the app's own was 3.13.18, and the release file installed with the network off. Build 3 of each Python tool, published on 2026-11-15, requires the `python-3.13` runtime and does not use Kali's Python at all (8.12); builds 1 and 2 were withdrawn that day. This repository's `kali` job installs a small Python test tool on a runtime package it builds around the same upstream archive.
- The pinned `asciinema` runs on Kali, and writes to disk as it records rather than at the end. Confirmed in the Kali image: the real-asciinema tests pass there as root against the asciinema installed from the release file, and the run records a window and plays it back.
- The `[rec <target>]` prefix shows with Kali's own zsh settings, survives its prompt toggle, and leaves the rest of my shell setup as it was. That it shows, in front of Kali's own two-line prompt, is confirmed in the Kali image. The prompt toggle and the rest of the shell setup are still open.
- The text copy of a real session on Kali reads cleanly: command lines as typed, with zsh's suggestions and highlighting gone. Still open: the Kali run records two short commands, and its text copy has the timed output line, but not a session with suggestions and highlighting.
- Writing `/etc/hosts` in place works on Kali, as root and through `sudo`. As root, confirmed in the Kali image: the line is written and removed, and every other byte stays as it was. Through `sudo`, still open.
- The VPN interface on Hack The Box is `tun0`. Still open: the Kali run's tunnel is `tun0`, but it has no Hack The Box server behind it.
- `vpn start` with a real Hack The Box file: the tunnel comes up, survives closing every window and quitting the prompt, and `vpn stop` ends it. With a file that has no server, confirmed in the Kali image: the tunnel comes up on `tun0` with OpenVPN 2.7.8, OpenVPN runs with PID 1 as its parent and no controlling terminal, and `vpn stop` ends it and takes `tun0` away. A real Hack The Box file, closing the windows and quitting the prompt with the tunnel up are still open.
- OpenVPN asks for a username and password in the prompt window before it goes to the background. Still open.
- What `asciinema play` returns, and how it leaves the terminal, after Ctrl-C during `replay`. Still open for Ctrl-C. Played to the end in the Kali image, it returns without a status warning and the prompt takes the next command.
- Whether Kali's Ctrl-P prompt toggle drops the `[rec <target>]` prefix until the next command. Still open.
- Kali's own `ligolo-ng` package installs a command named `ligolo-proxy`. Confirm it, and that with mine installed a bare `ligolo-proxy` runs mine and a bare `sudo ligolo-proxy` runs Kali's. Still open.
- What `ligolo-proxy` writes, and where, on its first run, so its package lists the right data paths. Still open.
- PEASS-ng's licence, read in full, before `pwn-shop` is made public. Still open; this one is not about Kali.

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

For recording and Kali changes:

- `record` with no target records for the last-used target.
- `record` refuses to run through `sudo` as a user other than the one who installed the app.
- An export packs a recording that is still being written up to its last whole line.
- The text copy takes the lines on the screen when it is cleared.
- `finish` refuses while a window is recording, where the earlier outline said it warns.
- The recording indicator is a `[rec <target>]` prefix on the shell prompt, for zsh and bash.
- The recording's header names the box through its title: box name, target name, box ID.
- asciinema runs with an empty settings folder of the app's own.
- The text copy leaves out full-screen programs and joins wrapped lines.
- `replay` plays in the prompt window, with idle gaps cut to two seconds.
- `pyte` is the terminal model, pinned to one version.
- The `/etc/hosts` question defaults to yes, because a line is easy to take back.
- A target's line uses its first IP.
- An open box's hostname wins over another of my boxes' lines; an unmarked line is never changed.
- `host add`, `host remove`, `host`, `host file on` and `host file off` exist, and act on the current target.
- Within a box a hostname belongs to one target.
- Only `tun` interfaces count as a VPN, and there is no setting for it.
- OpenVPN runs in its own background mode, not in tmux.
- The running VPN's files live in `/opt/pwn-broker/run/vpn/`, so it outlives the box that started it; the box's `vpn/` folder holds only the copy of the file.
- `vpn log` and `vpn status` exist beside `vpn start` and `vpn stop`.
- The `vpn start` question defaults to the file used last time.
- A tunnel the app did not start is never stopped.
- The app keeps track of one VPN at a time; while its own is up, `vpn start` starts nothing.
- A new target is pinged wherever it is added, including from `record`.
- A missing or wrong asciinema stops the install, because `setup` fails; later, the launch check only warns.
- The asciinema pin lives in the app, not in `install.sh`, so `setup` and the launch check share it.
- The release file is the one thing the installer trusts, and it holds no pins of its own beyond the file's checksum.
- The release file is built on x86_64 Linux only, and installing from a checkout means building one first.
- The app's Python is its own, separate from the tools' runtime, even though both are the same upstream build.
- The prompt and `record` share a lock, and the prompt reloads the box from disk when it has changed.

For the tools phase:

- Python tools use Python's own `venv` and `pip` with every dependency bundled as a wheel. This replaces the earlier choice of `uv` or `pipx`.
- Packages are stored zips with no install script; a manifest says what to run and what to copy.
- Every package has a build number beside upstream's version, and a published build is never replaced.
- Python dependencies are pinned in a lock file I commit to `pwn-shop`; CI resolves nothing.
- The index is rebuilt by CI from a card published with each release, and published as the one file of a standing release tagged `index`. CI commits nothing.
- The cached index refreshes after a day, with a two-second limit, and `tool refresh` forces it.
- `tool install` from the published index has not been run on Kali; CI installs from a folder.
- One build of a tool is installed on the machine at a time, shared by the unfinished boxes that use it. A different build is refused until the other box lets go.
- Every command is a launcher script, so the app can tell when a tool is running. `finish` and `tool remove` stop while one is.
- A removal that fails after the archive is verified leaves the box finished, and the next launch offers to remove what is left.
- Home-folder data is copied into the box and not put back on import.
- A tool with no version numbers of its own takes its upstream date as its version: `targetedkerberoast` 2024.12.16, `peass-ng` 2026.11.14.
- ligolo-ng's proxy is installed as the command `ligolo-proxy`, the name Kali's own `ligolo-ng` also uses; mine wins for a bare name, Kali's for a bare `sudo`.
- `pspy` carries all four upstream binaries. `peass-ng` carries `linpeas.sh`, `winPEASx64.exe`, `winPEASany.exe` and `winPEAS.bat`.
- The manifest has no field for system packages until a tool needs one.
- A tool's data is collected into the box at `export` as well as at `finish`.

## 12. Left to implementation

- Module layout and internal interfaces.
- How file changes are detected between prompts, and the size above which checksums are deferred.
- The exact wording of messages, within the voice rules in `BRAND.md`.
- The test layout. Logic is kept apart from terminal and file-system access so it can be tested without a Kali machine, and anything that touches privileges is tested as both root and a normal user.
- The release workflow for the app itself: SemVer tags, `vX.Y.Z`.
