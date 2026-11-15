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

## Recording, /etc/hosts, the VPN and the ping

None of this has been run on Kali. Work through it in one box, once as root and once as a normal user, with a Hack The Box `.ovpn` file to hand. Before you start, copy `/etc/hosts` aside (`cp /etc/hosts /tmp/hosts.before`) to compare with afterwards.

- [ ] After `sh install.sh --from .`, the installer prints `ok    asciinema 3.2.1 in /opt/pwn-broker/app/bin/asciinema`, and `/opt/pwn-broker/app/bin/asciinema --version` prints 3.2.1. `check` in the prompt shows no `asciinema` line, because it passed. `which asciinema` does not name the app's copy.
- [ ] In a second terminal, with the box open in the prompt, `record` prints `ok    recording this window for <target> (<box>)` and the path of the `.cast`. Run `ls -l` on that `.cast` from a third terminal a few times while typing commands in the recorded one: its size grows as you work, not only at the end.
- [ ] With Kali's own zsh settings (a fresh `~/.zshrc` from Kali), the recorded window's prompt starts with `[rec <target>]`, and the rest of the prompt, the colours, the suggestions, the aliases and the history behave as they do outside `record`. Do the same with `SHELL=/bin/bash record` and Kali's own `~/.bashrc`.
- [ ] Press Ctrl-P in the recorded zsh window, Kali's toggle between its one-line and two-line prompts, then Ctrl-P again. Note whether the `[rec <target>]` prefix stays, or is gone until the next command is run.
- [ ] In the recorded window, run `nmap` against a target, type a command and edit it before Enter, run a command whose output wraps (a long hash), open `vim` and quit it, and press Ctrl-L once. `exit`, then open the `.txt`: each command reads as typed, with zsh's suggestions and highlighting gone, an edited command appears once as it was run, the wrapped line is one line, vim is one `[full-screen program until ..., see the cast]` line, and every line starts with a time.
- [ ] `replay` in the prompt lists the recording with its start time, length and size. While a second window is recording, it shows `recording now`, and `status` shows `recordings` with `(1 recording now)` and the status bar `rec 1`. `finish` refuses and names the target. `export` warns, and the export holds the recording up to that moment.
- [ ] `replay 1` plays the recording in the prompt window, with idle gaps cut to two seconds. Space pauses. Press Ctrl-C part way through: it returns to the prompt. Note whether the app prints `warn  asciinema ended with status <n>`, and with which status, and whether the terminal is left as it was, with the cursor shown, echo on, and the prompt working normally.
- [ ] `sudo record` as the normal user refuses and says to run `record` first, then `sudo` inside it.
- [ ] `target add` with an IP and a hostname asks `add <target>'s hostnames to /etc/hosts? [Y/n]`. Press Enter. As root the line is written directly; as a normal user `sudo` asks for the password once. The new line ends with `# pwn-broker <box ID>`, `getent hosts <hostname>` gives the IP, and `diff /tmp/hosts.before /etc/hosts` shows only that line. `ls -l /etc/hosts` shows the same owner and mode as before, and `ls -i` the same inode.
- [ ] `host add <name>` rewrites the line without asking, and `host` shows every hostname with `yes` under `in /etc/hosts`. `host file off` takes the line out, and the file matches `/tmp/hosts.before` again.
- [ ] As a normal user, run `sudo -k`, then `host file on` for a target with no line, and type a wrong password at each of `sudo`'s three tries. Nothing in `/etc/hosts` changes, and the app prints a `warn` line and the line to add yourself.
- [ ] `finish` removes the box's lines after the archive is written, and `cmp /tmp/hosts.before /etc/hosts` finds no difference (Kali's file ends with a line break; one that did not would gain one).
- [ ] The new target is pinged once: `ok    <ip> answered in <n> ms`, or `warn  <ip> did not answer a ping; Windows targets often do not`. Ctrl-C during the two-second wait prints `cancelled` and nothing else is skipped.
- [ ] With no VPN up, the launch checks print `warn  vpn   no VPN tunnel is up` and `start one with: vpn start`, and the app still starts. The status bar shows `no vpn`.
- [ ] `vpn start` with the Hack The Box file: the question takes the path with Tab completing it, the file is copied to `vpn/` in the box with mode 600 (`ls -l`), and the app prints `ok    vpn up, <address> on tun0`. Note the interface name if it is not `tun0`. The status bar shows `vpn <address>`.
- [ ] With a file that asks for a username and password (`auth-user-pass` with no file named), OpenVPN asks for them in the prompt window before it goes to the background, and the tunnel comes up.
- [ ] Close every terminal window except the prompt, then `quit` the prompt. From a new terminal, `ip -4 addr show tun0` still shows the address. Open the box again: `vpn status` shows `up`, the file and the box that started it, and `vpn log` shows OpenVPN's log.
- [ ] `vpn stop` prints `ok    vpn stopped`, and `ip addr show tun0` no longer finds the interface. Start one by hand with `sudo openvpn --config <file>` in another terminal: `vpn stop` refuses and says to stop it yourself, and it is still up afterwards.
- [ ] `vpn start` again, then `finish`: it asks `the VPN is still up (<address>). stop it? [y/N]`. Enter keeps it up. `tar -tzf` on the archive lists no `vpn/` entry.
