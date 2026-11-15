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
