# Changelog

## v0.1.16 (unreleased)

Changed: the SHA-256 an index first gives for a build is kept on the machine, in `/opt/pwn-broker/tools/seen.toml`, and an index that later gives that build another is refused. The index is not signed and was the only thing trusted: when its hash for a build changed, the cached zip was dropped as a bad copy and the package was downloaded again without a word, though pwn-shop never changes or replaces a build it has published. Every index is now held to the builds kept each time it is read: the published one, a mirror or a folder set with `tools_index`, the cached copy and the one `tool refresh` fetches, and with them a box whose tools are installed again when it is opened or imported. The `fail` line names the build and both hashes; nothing is installed from that index, it does not replace the cached copy, and no cached zip is dropped for it. For a package of your own built again under the same build number, the new `tool forget <name>@<version>-<build>` shows the SHA-256 kept, asks, and forgets that one build; nothing else does, and no setting turns the check off. Nothing is kept before the first index is read, so the first one read after this upgrade is taken as it is. The lines for a box's row or an installed copy that disagrees with the index (`... the box recorded ...; skipped`, `... the installed copy has ...`) name the build and both hashes too.

Changed: what holds a box's secrets is readable by you alone, whatever the umask. `creds.toml`, the files in `lists/`, `notes.md`, the prompt's `.history` and the archives in `wrapped/` were left to the umask, mode 644 for most, while `vpn/`, `tools.log`, `serve.log` and uploaded loot were already forced to 600. They are now mode 600, and a box's folder, its `lists/` and `wrapped/` mode 700; the copy `copy_to` gets of an archive or a report is made the same way, and an archive is never readable by others while it is being written. The note's vim keeps `notes.md` at 600 each time it saves, also when it is started by hand, and its terminal starts with a umask of 077. A box or archive from an earlier version is tightened when the box is opened, resumed or imported, without a line; what cannot be changed gets one `warn` line. A mode that is already tighter is kept, and the other files in a box keep the mode they had.

Changed: `export` packs what is there. It hashed every file, then packed them, and when a scan running in the background wrote to its output in between, the export failed with `size differs from the manifest`; `quit` exports by default, and a scan outlives `quit`. Each file is now packed as it is when the packing reaches it, and `manifest.toml` is written from what went in and packed last, so it gives every file the size and SHA-256 it has in the archive. A scan still running gets a `warn` line naming its target and plan, the manifest names it under `running_scans`, and `import` of such an archive says so. A file removed meanwhile is left out, and one that gets shorter while it is read starts the packing again, once. `finish` writes its archive the same way and still refuses while a scan runs. The archive is read as before by `import`, by earlier versions and by pwn-report, which find the manifest by its name; reading one costs them a pass more through the archive, the manifest being at its end.

Fixed: a value typed into a playbook's run block was part of a vim command. The block's lines, which pwn-playbooks writes, are `:s` commands, and `@q` typed them into vim as keys: a `/` in a value ended the replacement and vim ran what followed it, so `x/|!touch /tmp/x|/` over a `<Replace>` ran `touch`, and `&`, `~` and `\` each changed what went in. The docs said to escape them; nothing stopped it. In the note's vim, `@` now takes a register that holds a run block for itself: it reads the block's lines as what they say, never runs them, and puts each value in as the text it is, whatever characters it holds. A value needs no backslashes any more, and one typed is kept, so `\/` now puts `\/` in. A block with a line that is not its own, which is what a value of two lines leaves, fills nothing in and says which line. Every other register runs as before, and the keys are the same: `ca>`, `V}`, `"qy`, `@q`. The playbooks are as published; all 122 run blocks of playbooks 2026.11.27.1 are read.

Changed: `docs/design.md`, the design written before the app was built, is no longer in the repository. What it was read for now stands where it is used: the things a change must never do are in `CONTRIBUTING.md`, what each command does is in `docs/guide.md`, and the package and index format is in pwn-shop's guide. Dependabot opens one pull request a month for the actions the workflows pin, and the Kali job installs pwn-shop's `report` 0.1.1 build 1.

## v0.1.15

Fixed: the package backends `tool install <name> --full` selected were kept only in the machine's list of installed tools, which `finish` empties and an archive does not carry. A box reopened, or imported on another machine, got its tools back without the selection, so its backends were left as automatic dependencies no tool needed, and the next `tool remove` of any other tool printed `automatic dependencies no longer needed: netexec` and deleted them. The selection is now the box's own, on its row for the tool in `box.toml` (`optional`), and reopen and import select the same backends again. A box that installed the same tool without `--full` stays without them, where one selection used to serve every box on the machine, and `tool doctor` shows the open box's selection. A box or archive from 0.1.14 or earlier loads as before; in one from 0.1.14 that used `--full`, run `tool install <name> --full` once more to record it.

Fixed: `tool install <name> --full` showed only the apt packages a recipe names and then ran `apt-get install` with its output captured and without `-y`. When apt needed even one more package, its own `Do you want to continue? [Y/n]` went where nothing showed it, and the install looked hung; a package's set-up question did the same. The plan is now apt's own, from `apt-get install --simulate`: every package it would install, the ones the named packages need included, any it would upgrade, and the exact command. After a yes, apt runs with `-y` and `DEBIAN_FRONTEND=noninteractive` and has nothing to read, so it cannot stop to ask; `sudo` still asks for a password on the terminal. A plan that would remove a package is not offered, and the command has `--no-remove`. A settings file you have edited is kept.

Fixed: a backend's apt package names could end in `-`, `+` or `.`. `apt-get install nmap-` removes nmap, and a name with a dot that matches no package is taken as a regular expression, so a wrong index or manifest could put the removal of a system package, as root, behind a question about installing one. A name must now start and end with a letter or digit, in a manifest and in the index, and `apt-get` is told to take each name as it stands.

Fixed: the installer ran `sha256sum`, `tar`, `gzip`, `stat`, `mktemp` and the rest by name with `/opt/pwn-broker/bin` still on its PATH, first, as it is in the shell an upgrade is run from. Tool packages put their commands in that folder, and none of those names was reserved, so a package with a command named `sha256sum` would have answered for the check of the next release file. The installer now takes that folder off its own PATH before it runs anything, under any spelling of it or a link to it.

Fixed: a package download had a time limit only between reads that could each wait five minutes, so a server sending a byte now and then held `tool install` for as long as it liked. The whole download now gets five minutes. And the size the index gives for a package, at which the download is cut off, had no limit of its own: an index may now give no more than a package can be, 1 GiB and 8 MiB for its lists of entries.

Fixed: installing a newer build over one left by a finished box deleted the old build before the new zip was checked, and when the install then failed, the list of installed tools was put back naming the old build, whose folder and launchers were gone. The old build now stays until the new zip has passed every check, and a failure after that leaves no row for files that are not there.

Fixed: `tool install <name>@<version>-<build>` looked for a version of that whole name before the build, and a version may hold a hyphen. With builds `1.0-1` and `1.0-1-2`, `name@1.0-1` gave the second, and a box reopened asked for its build and was offered the other. The exact build is now looked for first.

Fixed: `serve` kept a connection open for as long as the client liked, and held the room for an upload from the moment its `Content-Length` arrived. Two uploads that each announced 4 GiB and sent nothing made every later upload fail with `507` on a disk with 9 GiB free, left their temporary files in `loot/`, and each idle connection held a thread for good. A connection that sends or takes nothing for 30 seconds is now closed; an upload that goes quiet is answered `408`, its room is free again and its temporary file is gone.

Fixed: `serve.log` was not one line per request. A client that hung up part of the way through a download wrote a Python traceback of some sixty lines, so `serve log` showed only that; a request line was logged whole, 60,000 characters of it; the log grew without limit, and `serve log` read all of it to show twenty lines. A dropped connection is now one line, a request line is cut after 200 characters, the log keeps its last half once it passes 1 MiB, and `serve log` reads only its end.

Fixed: the line `serve files` prints for sending a file back from a Windows target, `iwr -Method PUT ...`, failed in Windows PowerShell 5.1 wherever the shell cannot ask a question, with `Windows PowerShell is in NonInteractive mode`, after the server had saved the file, so a second try saved it again as `<name>-2`. The line now has `-UseBasicParsing`. And the download line saved nothing for a file with `[` or `]` in its name, which that PowerShell reads after `-OutFile` as a pattern: such a file now gets a `(New-Object Net.WebClient).DownloadFile(...)` line. A character a Windows file name cannot hold, and each byte of a name that is not UTF-8, is `_` in the name the file is saved under. Every line was run in Windows PowerShell 5.1 against the server.

Fixed: `serve files` listed a file put straight into `/opt/pwn-broker/upload/`, in no tool's folder, and the server answered `404` for it. It is no longer listed. A file whose name holds a backslash was listed and answered `404` too, and one whose name is not UTF-8 stopped `serve files` with `unexpected error: UnicodeEncodeError`, so it printed no line for any file: both now get a line, and are served at it.

Fixed: `import` took a folder name whose archives in `wrapped/` were another box's. With my finished `2026-11-14_htb_forest` gone from `active/`, a teammate's box of the same name came in under it and nothing was asked; its `export`, which `quit` offers, then replaced my `.exported.tar.gz` without a word, and its `finish` offered to replace my `.finished.tar.gz`. An imported box now gets `-2` on the end when the archives under its name hold another box, as a new box does, with a `warn` line, and keeps its name when they are its own. And `export` and `finish` never write over an archive that holds another box, or a file they cannot read as an archive: the box's archives go under the next free name.

Fixed: an imported archive's top folder could have any name without a `/` or a leading dot, escape sequences included, and `path` printed the box's folder as it was. The top folder must now be named as a box's folder is, in lowercase letters, digits, dots, hyphens and underscores with a letter or digit first, and `path` shows a control or format character as `?`, as every other line does. An archive of a box whose folder was renamed by hand to anything else is refused: rename the folder back, or to such a name, and export again.

Fixed: a recording from an imported box could cost what it liked. One line of 96 MiB, 95 KiB in the archive, was read whole at 288 MiB of memory, and by its size the recording got 6,100 seconds to render before the `export`, `finish`, `replay` or `quit` that met it went on. A line longer than 4 MiB, which no line of a recording is, is no longer read: the recording gets a `warn` line and a text copy that says so. And no recording gets more than 600 seconds.

Fixed: a `.cast` whose file name is not UTF-8 stopped `export`, `finish` and `replay` with `'utf-8' codec can't encode character`, and no archive was made. The name is written into the text copy, which cannot hold such a byte: it is now written as `?`, and the archive holds the recording and its text copy under the names they have.

Fixed: a new box took any date, `1026-11-14` for one, but a box is read back only with a start from 1970 to 8999, so the box was made and then could never be opened again (`box.started has the wrong type`). The date question now asks again for a date outside those years, and no box is made with one.

Fixed: `target rename` moved the target's folder, then wrote its `target.toml`. When that write failed, on a full disk for instance, the target's name was no longer its folder's, and such a box cannot be read at all. The folder is now moved back.

Changed: the workflows that test and publish pwn-broker name each GitHub action by its full commit, with its version in a comment, where they named a tag. A tag can be moved to other code, and the job that publishes a release has write access.

## v0.1.14

Added: package and index schema 4 separates ordinary tool dependencies (`depends`) from Python runtimes (`requires`) and declares optional external backends. `tool install <name>` resolves ordinary dependencies first, reuses installed builds across boxes, detects missing targets and cycles, and rolls back a failed package graph. `tool install <name> --full` also selects the requested tool's package-backed and apt-backed optional backends. Missing apt providers are shown with their exact `apt-get install --no-install-recommends` command and installed only after confirmation; they remain system-owned and are never removed by rollback, `tool remove` or `finish`. No recipe-supplied installer is run.

Added: `tool doctor <name>` reports runtime and ordinary dependencies plus each declared backend's command, availability, provider and enabled feature. It only inspects state and executable paths; it installs nothing and runs no backend.

Changed: automatic dependencies are released only when orphaned, while explicitly installing one takes ownership so removing its former parent leaves it alone. Restoring a box preserves that ownership. pwn-shop's `ad-sweep` 0.1.0 build 2 brings NetExec automatically; `cred-spray` 1.0.0 build 2 stays minimal by default and declares Nmap, NetExec, FreeRDP, ipmitool and Ruby evil-winrm for `--full`.

## v0.1.13

Fixed: a relative `home` or `copy_to` in `config.toml`, or a relative `PWN_BROKER_HOME` or `PWN_BROKER_OPT`, named a different folder for the note window, `serve`, `scan`, `record` and the report, which each run from a folder of their own, so they failed or wrote elsewhere. Each must now be a whole path, such as `~/pwn-broker`, and pwn-broker says so at launch. An empty `PWN_BROKER_OPT` now means the default, as an empty `PWN_BROKER_HOME` does, not the current folder. With `copy_to` set to `wrapped/` itself, every `finish` warned that the report was there already, and `export` and `finish` copied the archive over itself; neither is copied now, as both are already there. A `.part` folder left in `copy_to` by a report copy that was cut off, by a power cut for instance, made every later copy of that report fail; it is now replaced, as the archive's `.part` file is.

Fixed: a box read from disk, an imported one included, is now refused when its id is not one plain name, or when a target's name is not the name of its folder or not one the app makes, or a target's address is not an IP address, or is an IPv6 address whose scope (after `%`) is anything but an interface name: Python's own parser takes any character there, spaces, `;` and `$(...)` included, and the same rule now applies to an address you type. An interface name may hold letters, digits and `. _ + -` (not `@`, which with a dot would carry a host name into a pasted `ssh` or URL line); a box with any other address no longer opens until the address is corrected in its `targets/<name>/target.toml`. A crafted archive could otherwise name a target `../../escaped`, so that `scan`, `rename` and other commands wrote outside the box, or give it the address `--script=<file>`, which `scan` handed to nmap as an option. `tool info` fills its examples only with a hostname, domain or address that is a plain name or address, so text from an imported box cannot reach a line you paste.

Fixed: the note's vim kept a `~/.viminfo` with its registers and command history, so a password put into a playbook's run block stayed in your home folder after `finish`. The vimrc now keeps none. A `~/.viminfo` an earlier version wrote is left as it is: delete it to drop what it holds.

Fixed: a recording's text copy could take hours to make from a crafted `.cast` of a few hundred bytes, in an imported box for instance, and `finish` waited for it. Each recording now gets 60 seconds for each megabyte of it, room for a real recording on a busy machine, and up to 10 more from one minute that all the recordings one `export`, `finish` or `replay` writes share, so crafted recordings spend that minute and never another recording's own time; `record` gives the recording it made the whole minute. In a text copy the screen alignment test (`ESC # 8`) and reverse video draw nothing, and an erase, or inserting or deleting characters, leaves no blank cells behind, so no call can touch more of the screen than was drawn on it. Every text copy is dated no earlier than its recording, whose time an archive may set in the future. One past its time gets a `warn` line and a text copy that says so, or keeps the one it has with a last line saying where it stops, so it is not tried again each time; `replay` still plays it, and deleting that text copy tries again. One that fails part of the way in, at a bad line or on output the terminal model cannot handle, gets the same, with a text copy that says why, where before it had none and was tried again each time. A folder or a link where a text copy goes gets a `warn` line, and is never rendered for, read or written through. Once the shared minute is spent, the first recording that runs out of time or fails ends the rendering, and one line says how many are left for the next `export`, `finish` or `replay`. The time is looked at between pieces of each event as well, so one long run of text, which the terminal model draws in a single call, or an escape sequence that never ends, is stopped too.

Fixed: `serve files` printed a PowerShell line with the file name bare after `-OutFile`, so a name with a space, `;` or `$` in it broke the line you paste on the target, or ran the rest of it there. Such a name is now quoted, with each of the four characters PowerShell takes as a single quote doubled, and so is a name starting with `-` or a digit, which PowerShell would read as a parameter or a number (`0x10`, `1kb`).

Fixed: `target rename` and `target remove` went ahead while a scan of the target was running or `serve` was serving its files, so `scan stop` no longer found the scan, `finish` stayed blocked by it, and `serve` answered from a folder that had moved. They now refuse until the scan ends or `serve stop`, as they do for a window still recording.

Fixed: a download of the tool index or a package over HTTPS followed a redirect to plain HTTP, where anyone on the way could rewrite the index, its hashes included, as it is not signed. Such a redirect is now refused.

Fixed: `scan` ran nmap on an IPv6 target without `-6`, which nmap refuses, and a `scan full` whose first stage found only UDP ports, with flags of your own, ran its second stage with an empty port list. IPv6 targets are scanned with `-6`, and with no TCP port the full scan stops after its first stage.

Fixed: text from a target or an archive could hold a format character, such as a right-to-left override, that reordered or hid what the terminal showed. Every line the app prints now shows format characters and line or paragraph separators as `?`, as it does control characters. `cred list` marks such a secret with `*` and points to `cred show`, as it does one with a control character.

Fixed: `serve` checked the free space for each upload on its own, so several uploads at once, each in its own thread, could together fill the disk past the 1 GiB it keeps free. Each upload now counts what the others still have to write.

Fixed: a tool package could name a command `nmap`, and `scan`, which runs the first `nmap` on the PATH, would then run the package's, as `/opt/pwn-broker/bin` comes first. `nmap` is now a reserved command name, as the other programs the app runs by name are.

Fixed: `search` numbered lines as Python splits them, so after a form feed or a line separator in pasted output its line numbers were past vim's. It now counts lines as vim does. And `serve` served a file of the target's own under a tool's name, as `upload/pspy/mine.txt` beside the `pspy` tool, which its list of files leaves out; under a tool's name it now serves only the tool's files, as the list says.

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
