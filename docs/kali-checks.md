# Checks to run by hand on Kali

Run the unit tests first: `python3 -m venv .venv && .venv/bin/pip install -e ".[dev]" && .venv/bin/python -m pytest`. The tests skipped on Windows (symlinks, named pipes, file modes, ownership, backslash file names, the installer) run there.

Then `sh install.sh --from .`, open a new terminal, and work one box end to end. Do the list once as root and once as a normal user.

- [ ] `x-terminal-emulator -e vim -u ...` opens the note window. If the option is not `-e`, add the right form to `open_note`.
- [ ] The note saves within about a second of stopping typing and on leaving the window, and reloads after `target add` writes to it, with no "file changed" prompt from vim.
- [ ] `.note-state` reads `1` while there are unsaved changes and `0` after a save, and `finish` stops while it reads `1`.
- [ ] The palette shows as the brand hex values, and `NO_COLOR=1 pwn-broker` prints no colour.
- [ ] `cred add` with `p@ss "word" with spaces\` round-trips through `cred show` and `lists/passwords.txt` unchanged.
- [ ] As a normal user: `sudo nmap -oA` into a target's `scans/`, then `finish`. The archive is written and verified, and the folder can be removed.
- [ ] `sudo /opt/pwn-broker/bin/pwn-broker` as the normal user refuses to start and names the user (the full path, because `sudo` does not search the user's PATH).
- [ ] `export`, copy the file to a second VM, `pwn-broker import <file>`: targets, note, creds and flags are all there and the prompt opens on the last target.
- [ ] A second `pwn-broker` in another terminal, while a box is open, refuses and names the open box.
- [ ] At a question, Ctrl-C cancels that command and returns to the prompt. Ctrl-D at the prompt offers the export and quits.
- [ ] With the note open in vim, change `notes.md` from another terminal (`echo x >> notes.md`). Vim shows the change within about a second, and `.note-state` in the box folder still reads `0`.
- [ ] Type in the note, then within a second run `target add` in the prompt. Vim does not show a "file changed" prompt, and nothing typed is lost.
- [ ] The note opens with every target fold closed, each showing only its `Target:` line.
- [ ] A closed fold is drawn on the raised colour (`#1A1D24`) across the whole line.
- [ ] IP addresses are Amber and `<Placeholder>` text is Ember, inside the box at the top as well as below it.
- [ ] `F8`, in normal mode and in insert mode, adds an empty fold below the line, open, with the cursor on its blank line in insert mode.
- [ ] Open a fold, put the cursor inside it, then run `target add` in the prompt. After vim reloads, that fold is still open, the others are still closed, and the cursor is on the same text.
- [ ] Select some lines in visual mode in the note, then run `target add` in the prompt. The selection stays until you leave visual mode, and the note reloads after that.
- [ ] While the note is open, no `.swp`, `~` or other backup file appears in the box folder.
- [ ] The status bar is muted text on the normal background, not reverse video, and its clock moves while the prompt is idle.
- [ ] The completion menu opens while typing a command, and Tab completes target names.
- [ ] As a normal user, `/opt/pwn-broker` belongs to that user after install, and `pwn-broker` runs without `sudo`.

## Tools

The packages are published in `pwn-shop`, which is private, so the tool commands read a folder. Get one in a clone of `pwn-shop`: `sh fetch.sh <folder>` with a signed-in `gh` downloads the published index and zips, or `python build.py build` builds them into `dist/`. Either way the folder holds `index.toml` and the zips it names. Set `tools_index = "<folder>"` in `/opt/pwn-broker/config.toml`.

- [ ] `python3 -m venv` works on a fresh Kali, and its Python is 3.12 or 3.13, the versions the bundled wheels cover. Without `python3-venv`, the launch checks print a `warn` line with `apt install python3-venv`, and the app still starts.
- [ ] With `tools_index` set to the folder, `tool list` shows the six packages (kerbrute, pspy, certipy, targetedkerberoast, ligolo-ng, peass-ng) and a `kali` column. `tool refresh` prints `ok` and a count of six tools. With `tools_index` pointing at an empty folder, every `tool` command prints one `fail` line that names the folder and `tools_index`.
- [ ] `tool install` each of the six in a box. Each prints `ok`, then how to run it. Where Kali already has a command of the same name, a `warn` line gives Kali's path and says the installed one wins. Kali is believed to package `pspy`, `certipy-ad`, `ligolo-ng` and `peass` (its names for them); confirm that, and which command names each installs, and note which installs produced a `warn` line. With Kali's `ligolo-ng` installed, installing ligolo-ng is expected to print a `warn` line that Kali has `ligolo-proxy`, and a second one that `sudo ligolo-proxy` runs Kali's copy and to use `sudo /opt/pwn-broker/bin/ligolo-proxy`.
- [ ] Run each command once from a new terminal: `kerbrute`, `certipy`, `targetedKerberoast`, `ligolo-proxy`. Each starts. The upload files are in `/opt/pwn-broker/upload/<tool>/`.
- [ ] `sudo /opt/pwn-broker/bin/ligolo-proxy`, the path `tool install` and `tool info` printed, starts the installed one. With Kali's `ligolo-ng` installed, a bare `sudo ligolo-proxy` starts Kali's copy; without it, a bare `sudo ligolo-proxy` is not found. `/etc/sudoers` is unchanged.
- [ ] For any command the check above found Kali already has, Kali's copy still runs as before when called by its full path, and `tool remove` on the installed one makes the bare name run Kali's again.
- [ ] Note what `ligolo-proxy` writes, and where, on its first run, both ways: run as you, and under `sudo`, where the home folder is root's. The package's data paths depend on it.
- [ ] Open a second box and `tool install` the same tool: the same build shares it. A different build stops and names the first box.
- [ ] While `ligolo-proxy` is running, `finish` and `tool remove ligolo-ng` both stop and name it.
- [ ] `finish` lists the box's tools and every path under the home folder it will delete. Afterwards no command, no upload folder, no `tools/` folder and no tool data from that box is left, and a path that existed before the install is still there with a `warn` line about it.
- [ ] `export` copies tool data into the box and removes nothing. `pwn-broker import <file>` on a fresh VM offers to install the tools again, and the same builds come back.
