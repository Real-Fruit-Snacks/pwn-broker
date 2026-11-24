# Changelog

## v0.1.13 (unreleased)

Fixed: with a relative `home` or `PWN_BROKER_HOME`, `finish` warned that the report was not built, because pwn-report runs in the archive's folder and was given paths from where pwn-broker was started. With `copy_to` set to `wrapped/` itself, every `finish` warned that the report was there already; it now makes no copy, as the report is already there. A `.part` folder left in `copy_to` by a report copy that was cut off, by a power cut for instance, made every later copy of that report fail; it is now replaced, as the archive's `.part` file is.

Fixed: a box read from disk, an imported one included, is now refused when its id is not one plain name, or when a target's name is not the name of its folder or not one the app makes, or a target's address is not an IP address. A crafted archive could otherwise name a target `../../escaped`, so that `scan`, `rename` and other commands wrote outside the box, or give it the address `--script=<file>`, which `scan` handed to nmap as an option. `tool info` fills its examples only with a hostname, domain or address that is a plain name or address, so text from an imported box cannot reach a line you paste.

Fixed: the note's vim kept a `~/.viminfo` with its registers and command history, so a password put into a playbook's run block stayed in your home folder after `finish`. The vimrc now keeps none.

Fixed: a recording's text copy could take hours to make from a crafted `.cast` of a few hundred bytes, in an imported box for instance, and `finish` waited for it. It now gets 60 seconds and 30 more for each megabyte of the recording, which is far more than a real recording needs, shared by all the recordings one `export`, `finish` or `replay` writes; one past that gets a `warn` line and no text copy, and `replay` still plays it.

Fixed: `serve files` printed a PowerShell line with the file name bare after `-OutFile`, so a name with a space, `;` or `$` in it broke the line you paste on the target, or ran the rest of it there. Such a name is now quoted.

## v0.1.12

With the `report` tool in the box, `finish` builds a private report from the finished archive and puts it beside it, `<box folder>.finished.report`, after the archive is written and before the tools come off. `tool install report` gets [pwn-report](https://github.com/Real-Fruit-Snacks/pwn-report) from pwn-shop. `finish`'s summary says whether a report will be built. A box finished again after it is reopened or imported puts its report beside the first, as `.report-2`; one is never replaced. With `copy_to` the report is copied there too. A report that fails, or takes longer than 600 seconds, is a `warn` line, and `finish` goes on.

After the playbooks' question, the first new box on a machine asks `install the report tool in this box and every new box? [Y/n]`, with the same `saved:` and detail lines worded for it, and keeps the answer in `state.toml` as `new_box_report`; `report = true` or `false` in `config.toml` decides instead. The playbooks' question is unchanged.

## v0.1.11

The playbooks question and the lines after it read more plainly. It now asks `install playbooks in this box and every new box? [Y/n]`, and the answer gets an `ok` line, `saved: new boxes get the playbooks` or `saved: new boxes start without playbooks`, with what to type to change it under it: the `config.toml` setting, and after a no, `tool install playbooks` for this box alone. A failed install ends `try again with: tool install playbooks`. Installing the playbooks, by `tool install playbooks` or in a new box, now also prints `list  playbook list   at the prompt` under the `read` line.

## v0.1.10

The first `pwn-broker new` on a machine asks `install playbooks in new boxes? [Y/n]` once the box is made, and keeps the answer in `/opt/pwn-broker/state.toml`, so it is asked once. With yes, that box and every later new box get the playbooks before the note window opens, as `tool install playbooks` installs them. An install that fails, with no network for instance, is a `warn` line, and the box opens all the same. `playbooks = true` or `false` in `config.toml` decides instead, and then nothing is asked. A box that is resumed, reopened or imported is never asked: it already offers the tools it had.

Fixed: making a new box saved only its platform to `state.toml`, so `vpn start` stopped offering the last VPN file it was given.

## v0.1.9

`playbook list` at the prompt lists the box's playbooks by name, folder and title, and words after it keep only the playbooks with every one of them in those, such as `playbook list windows`. `playbook show <name>` prints one in the terminal, from its `Playbook:` line and without its run block, flush left so its commands copy cleanly. It takes the name `:Pb` takes or the playbook's path, and Tab completes the name from any part of it.

## v0.1.8

Fixed: after Kali restarted, `start` could refuse with `<box> is open in another prompt; quit that prompt first` when no prompt was running. The open box was known only by its prompt's process ID, and after a restart another process can be given the same number. pwn-broker now also records when that process started, so a reused number no longer counts as an open box for `start` and `record`, or for a tool installed from this version on. A box left open by an earlier version is still judged by its number alone.

## v0.1.7

`tool install playbooks` installs playbooks for the box: a package of the new kind `notes`, which comes with manifest and index schema 3 and, like a tool, comes off at `finish`. In the note's vim, `:Pb <name>` reads one in below the cursor as its own fold, with Tab completing the name and `:Pb` alone listing them; the run block at its top, copied with `V}` `"qy` and run with `@q`, puts your values in place of its `<Placeholder>`s in that playbook only. `,x` ticks or unticks a `[ ]` box. `search` skips a playbook's unfilled lines in the note and says how many it skipped.

## v0.1.6

`search <text>` finds text in the current target's files, its recordings' text copies and its section of the note; `search <target> <text>` in another target, and `search all <text>` in the whole box. Case is ignored; binary files and `vpn/` are skipped.

## v0.1.5

`scan` runs nmap against the current target in the background, with `-oA` output in its `scans/` folder: `scan quick` (`-sC -sV`), `scan full` (every TCP port, then scripts and versions on those it found), `scan udp` (the top 100 UDP ports, as root), and quick then full for a bare `scan`. A line in the prompt says when each is done, with the open ports. Each mode's options are a setting. `scan stop` stops it, `scan log` shows what nmap printed, and `finish` waits while one runs.

In the note's vim, `,t` puts the date and time after the cursor, `,i` the IP of the target whose section the cursor is in, and `,c` one of the box's `user:password` or `user:hash` pairs, picked from a numbered list. `,h` lists them.

`serve` offers files to the targets over HTTP, in the background: the current target's new `upload/` folder and the files the box's tools put in `/opt/pwn-broker/upload/`. It listens on the tunnel's address unless given an interface or address, on port 80 as root or 8000 otherwise, and says how many files it offers; `serve files` prints the `iwr` or `wget` line for each, and `serve files <word>` only the matching ones. Every URL starts with a random part chosen each run, and nothing is listed, so other players on the VPN cannot browse or guess what is offered. It also takes files back: a `PUT` from the target, `iwr -Method PUT` or `curl -T`, saves into the target's `loot/` folder, never over a file that is there. `serve log` shows each request, `serve stop` ends it, and `finish` stops the one its box started.

## v0.1.4

`,h` in the note's vim lists the keys the note has: `F8` for a new fold, the fold keys, and how the note saves and reloads by itself. Any key closes the list.

Fixed: opening an imported box wrote its `/etc/hosts` lines with `sudo` without asking. The names come from the archive, so a box from someone else could point any name, `github.com` say, at any address. `import` now shows the lines and asks `this box wants these lines in /etc/hosts. add them? [y/N]`, and names any hostname that is not under a lab domain. On no the box keeps no lines; `host file on` adds one later. Importing over a box whose lines are already in the file asks nothing.

## v0.1.3

The installer prints its `ok` and `fail` lines in the app's colours. Three lines in the middle of an install come from the app and were green, while the installer's own were plain, so one install looked like two programs. Piped output, `NO_COLOR` and a terminal with no colour still get plain text.

Fixed: the summary `finish` shows before it asks said `(will be removed)` for every tool in the box's record, whatever `finish` then did.

- A tool another unfinished box has is now listed as `kerbrute 1.0.3   (will be kept; forest still uses it)`, which is what the line after the archive has said since 0.1.2.
- A tool the machine does not have is not listed. That is the case after `import` or a reopen where the offer to install the tools again was declined.
- While a box folder cannot be read, a tool's data in the home folder was listed as `(will be deleted)` though `finish` keeps it. It is no longer listed.

## v0.1.2

`finish` prints a line for each tool it takes off, as it does for a runtime: `ok    kerbrute 1.0.3 removed`, or `ok    kerbrute 1.0.3 kept; forest still uses it` when another unfinished box has the tool. It used to say nothing about the tools after the summary.

Fixed, in `finish`, `export` and `import`:

- `finish` deleted files that were made or changed after the archive was written: a scan still running in another terminal, say. Only the note was looked at again. Now every file's size and time is, the command history's included, and the folder is kept, with a line naming a file that changed.
- `import` over a box that was already there deleted the old box before it knew the new one could be opened. An archive with a `box.toml` that could not be read left a broken folder in its place. The new box is now loaded where it was unpacked, and the old one is not touched until that works.
- A tool's data in the home folder could be deleted with no copy kept, when a file in it was named like one of the app's own temporary files (`.pwn-broker-*.tmp`): it counted as copied, and the archive leaves that name out. Such a file is now left where it is, and the folder with it.
- A file name that is not UTF-8, which loot from a Windows share often has, stopped every command with `unexpected error`. The file is now left out of the box's list with a `warn` line and is still archived under the name it has.
- A box that held two names for one file (a hard link) could not be exported or finished: the second name was written as a link and the check then missed it. Each name is now packed as a file.
- A `box.toml`, target, credential or file record with a value of the wrong kind (`started = "yesterday"`) was loaded and broke the list of boxes at every launch. It is now refused where it is read, so the box is listed as one that cannot be read.
- Importing a box that is already here under another folder name is refused. Tools are held by a box's id, so finishing either one took the other's tools off the machine.

What `import` accepts, made stricter. An archive the app wrote is not affected, up to 300,000 files and folders or a manifest of 64 MiB, which is about 190,000 to 300,000 files depending on how long their paths are.

- An archive entry that is a sparse file is refused: 300 bytes could stand for 16 GiB.
- An extended header or long name of more than 64 KiB is refused before it is read. One of 800 MB, in an archive of 815 KB, cost 3.2 GiB of memory. So is an entry with more header than its name needs: a sparse file's map is read a block at a time for as long as the archive says there is more, and a header of hundreds of short records is slow to read, so an entry may have 16.
- A manifest that lists a file twice is refused. Each row was hashed, so 8,000 rows naming one file, in an archive of 5 KB, took 13 seconds.
- Whatever goes wrong reading an archive is one `fail` line. A size too large to seek to was a Python error.
- More than 300,000 entries, a name longer than 4,096 bytes, a global extended header, a file or folder entry that names a link target, a folder that gives a size, an owner number above 4,294,967,295, or a top folder whose name starts with a dot is refused, and the entries are checked as they are read. 10,000 entries with a 60,000-byte link target each, in an archive of 1.5 MB, cost 599 MiB. `export` and `finish` refuse a box of more files and folders than that, before writing anything.
- `import` checks that the archive fits in the free space before it unpacks.
- A `manifest.toml` or `box.toml` nested too deeply is refused with a message, not a Python error, and none of a box's files is read past 64 MiB, `box.toml` and a target's file not past 1 MiB.
- `import` over a box closes that box's note window only once the new box has been unpacked and loaded. An archive that was refused used to close it first.

A tool package's command or name `config`, `local` or `cache` no longer lets it claim what is inside `.config`, `.local` or `.cache`: a command named `config` could list `.config/google-chrome` as its own data, to be copied into the box and deleted at `finish`. No published package is affected.

## v0.1.1

Fixed: `finish` refused with "the note has unsaved changes" after vim had saved the note by itself, on losing focus or after a pause, and went on refusing until `:w` was typed. The note was saved; only the mark that says so was left standing.

What a tool package is checked for, made stricter. No published package is affected.

- A package's commands may not take the name of a program the app runs itself: `chown` and `x-terminal-emulator` were missing, so with `/opt/pwn-broker/bin` first on PATH the app would have run a package's copy, as root when the app is. More names that ask for a password, manage the system, fetch something to run, or that other programs start to show or edit something (`less`, `pager`, `editor`) are reserved too, and so are Python and pip under a versioned name such as `python3.13` or `python3.13t`.
- A zip whose list of entries is larger than 4 MiB is refused before the list is read. A zip of nothing but two million entries cost 800 MiB of memory before the limit of 10,000 entries was applied.
- A tool's files and folders get their modes set at unpack (755, and 644 for what is not run), as a runtime's do. They used to follow the umask, so under a loose one a file a launcher runs was writable by anyone on the machine. A folder is made closed and then opened, so it is at no moment looser than it ends up, and a link that turns up where a folder goes is not followed.
- A package or index version has to start with a letter or digit and hold only letters, digits and `. _ + ~ -`, 100 characters at most. It used to be refused only for a slash, a backslash or a space.
- A zip entry's name may not hold a colon or a control character, or be longer than a path may be, as a runtime archive's may not. No name or link target in a package may have more than 64 parts: 20 files under a name 1,900 parts deep took six seconds to unpack, and a tree that deep could not always be removed again. A stored zip entry whose two sizes differ is refused.
- A runtime archive's extended header records are dropped as each entry passes its checks. Kept, a 15 KiB record on each of 20,000 entries held 300 MiB. An archive with a global extended header that holds anything is refused: Python's tarfile keeps them all in one table and goes through it again for every later entry, so one before each of 2,000 entries made an unpack take a minute.
- The folders on the way to an entry count towards the limit on entries, in a zip and in a runtime archive. A name of 64 parts makes 63 folders that no entry accounts for: 20,000 such names made 1.26 million folders.
- A manifest may not claim more of the home folder: places that hold keys or sign-ins (`.aws`, `.kube`, `.docker`, `.netrc`, `.git-credentials` and others), places that run something at login or in every shell (`.bash_aliases`, `.xprofile`, `.config/fish` and others), the folders a desktop makes (`Pictures`, `Music` and the rest), and anything under `.local/bin`.
- A manifest may claim only a folder in the home folder that is named after the tool: `.<name>`, or `<name>` under `.config`, `.local/share`, `.local/state` or `.cache`, where `<name>` is the tool's name or one of its commands'. `finish` moves what a tool claims into the box and deletes it from the home folder, and no list of places to refuse can name everything that is someone else's. The list stays, so a tool named `ssh` still may not claim `.ssh`.
- A runtime archive that ends after one block of zeros is refused; a tar ends with two.
- A manifest on disk that is nested too deeply, or holds a number too long to read, is refused with a message, not a Python error.

## v0.1.0

The first release. pwn-broker keeps a Hack The Box machine in order on Kali Linux: it builds a folder for the box and each target, opens the note in vim, keeps the credentials and the lists made from them, and stays open as a prompt for the whole session. When the box is done, `finish` packs it into one archive and takes its `/etc/hosts` lines and tools off the machine again. This release is one file with its own Python, for x86_64 Linux with glibc. The [guide](https://github.com/Real-Fruit-Snacks/pwn-broker/blob/main/docs/guide.md) has every command, and [docs/tested.md](https://github.com/Real-Fruit-Snacks/pwn-broker/blob/main/docs/tested.md) what it has run on.

### The organiser

- `pwn-broker new`, `import <file>` and `resume [name]`, a start menu, launch checks, and one box open at a time.
- A folder per box under `~/pwn-broker/active/` and per target, with `files.toml` recording every file and its SHA-256. Each new target with an IP is pinged once.
- The note, `notes.md`, in vim in a window of its own, with the box's details at the top and a fold per target. One note window per box.
- `finish` archives the box to `~/pwn-broker/wrapped/` and closes it, `export` writes a snapshot and keeps working, and `import` unpacks either.

### Credentials

- Kept exactly as typed, in one list per box, with `cred add`, `edit`, `list`, `show`, `works`, `import`, `clear` and `remove`.
- `lists/` is rebuilt from them for other tools: usernames, passwords, pairs, hashes, IPs and hostnames.

### Recording

- `record [target]` records a terminal window into the target's `recordings/` folder under a pinned asciinema 3.2.1, with `[rec <target>]` on the zsh or bash prompt.
- A text copy beside each recording, with the time on every line, for grep. `replay` lists and plays them.

### Hosts and VPN

- One `/etc/hosts` line per target, marked with the box ID, kept in step with the target and removed at `finish`. Other lines are never changed.
- `vpn start`, `stop`, `status` and `log` for OpenVPN. The `.ovpn` file is copied into the box and never archived, and `vpn stop` stops only the process the app started.

### Tools

- `tool install`, `remove`, `list`, `search`, `info`, `history`, `refresh` and `cache clear`, from the packages in `pwn-shop`: kerbrute, pspy, certipy, targetedkerberoast, ligolo-ng and peass-ng.
- Every package is checked against the size and SHA-256 in the index, and nothing from it runs during install. Kali's own copies of a tool are never changed.
- The published Python tools bring their own Python, a shared runtime package such as `python-3.13`, so Kali's is never used or shadowed.
- `finish` removes the box's tools, unless another unfinished box still uses them, and copies their data from the home folder into the box first.

### Install

- `install.sh` downloads the release file, checks it against `SHA256SUMS.txt` and installs into `/opt/pwn-broker`. With `--from <file>` it contacts nothing. It needs no Python from the machine.
- Running it again upgrades, and a failed or interrupted upgrade puts the previous install back.

### Known limits

- x86_64 Linux with glibc only. The app's Python and OpenSSL are as new as the release, not as Kali.
- Every Kali run so far is root, in CI's container and by hand under WSL: not a normal user with `sudo`, not a full Kali desktop, not a real Hack The Box connection.
- Nothing is signed: `SHA256SUMS.txt` comes from the same release, and the tool index is not signed.
- Close pwn-broker before you upgrade; the installer does not check.
- The installer's download from a release and the release workflow's publish step run for the first time with this release. Before it, the download had run only against a stand-in in the unit tests, and the workflow only as a dry run that publishes nothing.
