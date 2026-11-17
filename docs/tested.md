# What has been tested

Everything pwn-broker has been run on, up to 0.1.3, with the counts, versions and dates, and everything it has not. The [README](../README.md#tested-on) has the short list. The checks still to run by hand on a real Kali desktop are in [kali-checks.md](kali-checks.md).

## Unit tests

- On Windows 11 with Python 3.13 (the development machine, at commit 56a64bd): 2984 passed, 76 skipped, with warnings treated as errors. The skips are the tests that need Linux (symlinks, named pipes, file modes, ownership, inodes, `/proc`, signals, the installer's tests that need real links and file modes, virtual environments and launchers, the recorded shell's startup files) and the three tests of the real asciinema (the zsh session, the bash session and its version), which run in CI's `recording` and `kali` jobs.
- On Ubuntu 24.04 in CI with Python 3.11, 3.12, 3.13 and 3.14, and again as root on 3.13 (the `test-root` job). On Linux they include real tool installs into a virtual environment and the launchers. The `/etc/hosts` code is tested there against a file in a temporary folder, as root and as a normal user, including that the lines that are not the app's survive. On each of 3.11, 3.12, 3.13 and 3.14: 3056 passed, 8 skipped; as root on 3.13: 3055 passed, 9 skipped; with warnings treated as errors. This is GitHub Actions run 43783899615 on the `release-file` branch, commit d7c31ea, in which every job passed.
- At the `v0.1.2` commit (5751792): 3341 passed, 94 skipped on Windows 11 with Python 3.13, and 3227 passed, 4 skipped in Kali 2026.2 under WSL 2 with Python 3.14.7 as a normal user, where the tests that need links, named pipes and file names that are not UTF-8 run. The Kali run left out the installer's and the release build's tests, which need the whole checkout, and CI runs those.
- At the `v0.1.3` commit (0ba1eac): 3349 passed, 113 skipped on Windows 11 with Python 3.13. In Kali 2026.2 under WSL 2 with Python 3.14.7, as a normal user, only the tests around the two changes were run: the tool, finish and `tool` command tests (350 passed) and the installer's, with its output on a real terminal (141 passed). CI ran the rest on Linux.
- The installer's own tests (`tests/test_install_sh.py`), under `sh` and `dash`, against a stand-in release file: a full install, an upgrade that keeps `config.toml`, `tools/`, `run/` and a box folder, every refusal with the install folder unchanged, and a failed or interrupted upgrade (a failing step, TERM, HUP, a second signal) that puts the previous `python/` and `app/` back.
- The vimrc, run by Vim 9.2 in headless mode on a note the app wrote: folds, fold text, `F8`, colours, settings, and the reload after the app changes the note. Timers and focus events do not fire in that mode, so the tests run the check by hand.

## CI jobs

- **`release-file`**, on Ubuntu 24.04: the release file built twice, and the two files were byte-identical. Built by hand in Kali 2026.2 under a different Python (3.14.7) at the same commit, the file had the same SHA-256 as the one CI built. `pwn-broker-0.1.0-linux-x86_64.tar.gz` was 46,667,263 bytes (about 47 MB), `gzip -t` and `tar -xzf` accept it, and it holds 11 things, each with a licence text and a source address: Python, asciinema, pwn-broker and eight dependencies.
- **`installer`**: `sh -n`, `dash -n` and shellcheck pass on `install.sh` and `.github/scripts/kali-cycle.sh`. The release file was installed twice into a temporary install folder and home. `pwn-broker --version` printed `pwn-broker 0.1.0`; `app/bin/python` is Python 3.13.18 and resolves to `python/bin/python3.13` in the install folder; `app/bin/asciinema --version` printed `asciinema 3.2.1`; `bin/record --help` printed `usage: record [target]`; the second run printed `PATH line already in` and left one PATH line.
- **`installer`, with no Python and no network**: inside `debian:stable-slim` started with `--network none`, where the only network interface was `lo` and no `python` or `python3` was on PATH or in `/usr/bin` or `/usr/local/bin`, `sh install.sh --from <file>` ran to its last line as root, and `pwn-broker --version` and `asciinema --version` worked.
- **`recording`**, on Ubuntu 24.04: the job installs the release file, and the three real-asciinema tests pass against the installed `app/bin/asciinema`. `record` records a real bash session and a real zsh session through a pseudo-terminal, and the test checks the `[rec dc01]` prefix, the recording marker, the `.cast` header and the text copy. Both sessions are recorded, and both show that asciinema writes the recording to disk as it happens, not at the end.
- **The release workflow** (`.github/workflows/release.yml`): once by hand on `main` as a dry run that publishes nothing (run 43855237616), then for the tag `v0.1.0` (run 43863175415, commit f63e7a6). Both built the release file from the locks, installed it, and ran the unit suite against the release's own wheels on the installed Python. The tag's run then compared the release file, `install.sh` and the notes with the SHA-256 values the build recorded, and published `pwn-broker-0.1.0-linux-x86_64.tar.gz` (46,657,018 bytes), `SHA256SUMS.txt` and `install.sh`. The same again for `v0.1.1`: a dry run on `main` (run 44006917496), then the tag (run 44007195718, commit ab208b9), which published `pwn-broker-0.1.1-linux-x86_64.tar.gz` (46,667,263 bytes) with the SHA-256 the dry run had recorded for the same commit. And for `v0.1.2`: a dry run on `main` (run 44043280809), then the tag (run 44043592619, commit 5751792), which published `pwn-broker-0.1.2-linux-x86_64.tar.gz` (46,667,263 bytes), again with the SHA-256 the dry run had recorded. And for `v0.1.3`: a dry run on `main` (run 44165821976), then the tag (run 44166240355, commit 0ba1eac), which published `pwn-broker-0.1.3-linux-x86_64.tar.gz` (46,667,263 bytes), with the SHA-256 the dry run had recorded.
- **`kali`**: one whole box in the official Kali image (`kalilinux/kali-rolling`, Kali 2026.3 at the time, with Python 3.14.10, zsh 5.9.2 and OpenVPN 2.7.8), as root.
  - After the packages were installed with the network on, the container was taken off its only network (`docker inspect` showed none; inside, only `lo`, `github.com` did not resolve, a connection to 1.1.1.1:443 failed). With the network off, `sh install.sh --from` the release file printed every `ok` line: the app's Python was 3.13.18 at `/opt/pwn-broker/python/bin/python3.13` while Kali's was 3.14.10 at `/usr/bin/python3.14`, and root's `.zshrc` was Kali's own plus the one PATH line.
  - The network was connected again, then the unit suite ran on Kali's own Python with the installed asciinema (3062 passed, 2 skipped, warnings treated as errors), and the whole box cycle ran on the app's bundled Python and ended with status 0.
  - The cycle is a new box, the `/etc/hosts` line written and later removed byte for byte, a ping, the note window in vim, a credential, a hostname added later, a recording under Kali's own zsh settings with the `[rec dc01]` prefix and its text copy, `export` while recording, `replay`, `vpn start` and `vpn stop` with a real OpenVPN and `tun0`, a tool installed and removed, a Python test tool on a test runtime package around the pinned upstream CPython 3.13 build, which it downloads and checks first: the tool runs on 3.13 from the runtime, which `finish` removes and `import` puts back, `finish`, and `import`, which puts the line and the tools back. It was 19 steps on the bundled Python.
  - Most steps are checked on disk or in the system, not only in what the app prints; `replay` and `status` are checked by their output. Stand-ins: a virtual display with `xterm` for the desktop, the container's gateway as the target, an OpenVPN file with no server behind it, and two small test packages for the tools. The real upstream Python archive passed the app's unpacking rules there.

## By hand on Kali

All five in Kali 2026.2 under WSL 2 on Windows 11, on 2026-11-16, with Kali's own Python 3.14.7: the first four as root, the last as a normal user.

### Every command

Installed with the installer from before the release file (`sh install.sh --from .`), with Kali's own qterminal as `x-terminal-emulator`.

- The layout was as [design.md](design.md) section 6.14 describes: the header, the `Boxes`, `New box` and `Target <n>` headings, the indent, and one blank line around each command's output and each yes or no question.
- `note` with the note open printed `ok    the note is already open` and one vim ran; after `finish` removed the folder, neither that vim nor its terminal window was left.
- A second box named `forest` on the same day, after the first was finished and removed, got the folder `2026-11-15_htb_forest-2` and the archive `2026-11-15_htb_forest-2.finished.tar.gz`.
- The start menu's import with no file asked again, and a folder got `fail  /root is a folder, not an exported box`.
- `exit` left the prompt with the export question, and `clear` cleared the screen.
- `2` and `maybe` at a yes or no question got `fail  answer y or n` and the question again.
- `target rename a b` printed `fail  too many arguments: b` with `usage: target rename <target>` under it.
- A fresh install's first launch asked nothing about folders, because `setup` had made them.
- A long hash in `cred list` was cut and ended in `...`, and `cred show 1` printed the whole secret alone.
- `record` in a real zsh session, `replay`, `tool install kerbrute` from the published index, and `finish`, which removed the tool, worked as before.

### A release file built and installed

At commit 32ab8fe.

- `python3 -m venv .venv`, `.venv/bin/pip install -e .` and `.venv/bin/python release/build.py` built `dist/pwn-broker-0.1.0-linux-x86_64.tar.gz` (46,667,263 bytes) and `SHA256SUMS.txt`, which `sha256sum -c` accepted. Every step printed its `ok` line: the pinned Python and asciinema fetched and checked, the build tools installed from their lock, the wheel built, the locked wheels downloaded, and the release and its 11 licences checked.
- `sh install.sh --from .` was refused with the message that names a release file, and `sh install.sh --no-asciinema` printed the usage and exited 2.
- `sh install.sh --from dist/pwn-broker-0.1.0-linux-x86_64.tar.gz` printed every `ok` line and left `/opt/pwn-broker/python` and `app`, and no work folder. `pwn-broker --version` printed `pwn-broker 0.1.0`; the app's Python was 3.13.18 at `/opt/pwn-broker/python/bin/python3.13` while Kali's was 3.14.7; `asciinema --version` printed `asciinema 3.2.1`; the launcher runs `python -I -m pwn_broker`. A second run over the same install succeeded.
- The installer at that commit wrote no `.pwn-broker` marker; the one at cf585e7 writes it, refuses a `python/` without it, and runs again over an install it made (next section).
- On that install a launch showed the header and `ok    7 checks passed`, a new box was made, `tool install certipy` installed the `python-3.13` runtime and the tool from the published index, and `status` listed them.

### An upgrade from the old installer

At commit cf585e7.

- An install made by the installer from before the release file (`sh install.sh --from .` at commit b1f66bd, an environment on Kali's Python 3.14.7) was upgraded with `sh install.sh --from dist/pwn-broker-0.1.0-linux-x86_64.tar.gz`: every `ok` line printed, the app was then on Python 3.13.18 at `/opt/pwn-broker/python/bin/python3.13`, `config.toml` and a box folder under `~/pwn-broker/active` were untouched, and `python/.pwn-broker` was there.
- A second run of the installer over that install succeeded.
- With `python/.pwn-broker` removed, the installer printed `fail  /opt/pwn-broker/python exists and is not a pwn-broker Python. move it or choose another folder`, and the install still worked.
- `PWN_BROKER_OPT=relative/path` printed `fail  PWN_BROKER_OPT must be an absolute path, not relative/path`, and `PWN_BROKER_OPT=//` printed `fail  the install folder must not be empty or /`.

### The published release

`v0.1.0`, with `/opt/pwn-broker` and `~/pwn-broker` removed first.

- `curl -fsSL https://github.com/Real-Fruit-Snacks/pwn-broker/releases/latest/download/install.sh | sh` printed every `ok` line, from `checksum verified for pwn-broker-0.1.0-linux-x86_64.tar.gz` to the last, and left no work folder. `pwn-broker --version` printed `pwn-broker 0.1.0`; the app's Python was 3.13.18 at `/opt/pwn-broker/python/bin/python3.13` while Kali's was 3.14.7; `asciinema --version` printed `asciinema 3.2.1`. The same line run again succeeded, with one PATH line in `.zshrc` and one in `.bashrc`.
- On that install a new box was made and `tool install` ran for `kerbrute`, `pspy`, `certipy`, `targetedkerberoast`, `ligolo-ng` and `peass-ng`, each from the published index. `certipy` brought the `python-3.13` runtime; `status` showed 6 tools.
- `kerbrute version`, `certipy -h`, `targetedKerberoast -h` and `ligolo-proxy -h` each started and printed their own first lines, and the ten upload files were in `/opt/pwn-broker/upload`. Kali's `python3` was still `/usr/bin/python3`, 3.14.7.
- `finish` listed the six tools and the runtime as to be removed, wrote the archive and removed the folder. Afterwards `bin/` held only `pwn-broker` and `record`, `upload/` was empty, `tools.log` had an install and a finish line for each of the seven packages, and neither the note's vim nor its qterminal window was left.

`v0.1.1`, over the `v0.1.0` install of the normal user below, in Kali 2026.2 under WSL 2 with no display.

- The same `curl` line upgraded the install: `pwn-broker --version` printed `pwn-broker 0.1.1`, and nothing under `/opt/pwn-broker` belonged to anyone but that user.
- A new box, then `tool install kerbrute` and `tool install git-dumper` from the published index of fourteen tools; `git-dumper` brought the `python-3.13` runtime, and `tool list` showed all fourteen with those two installed.
- `finish` listed both tools and the runtime as to be removed, wrote the archive and removed the folder. Afterwards `bin/` held only `pwn-broker` and `record`, `tools/` only `installed.toml`, and `tools.log` had a finish line for each tool and for the runtime.
- With the installed `vimrc`, a real vim in tmux marked the note unsaved after an edit and cleared the mark when it saved by itself six seconds later, which is the fix in this release.

`v0.1.2`, over that `v0.1.1` install, the same way.

- The `curl` line upgraded the install: `pwn-broker --version` printed `pwn-broker 0.1.2`, and nothing under `/opt/pwn-broker` belonged to anyone but that user.
- A new box with `kerbrute` installed, and loot put into it from another shell: a file whose name is not UTF-8 and a file with a second name (a hard link). `status` listed the box, where 0.1.1 stopped with `unexpected error`. `export` and `finish` each printed one `warn` line for the name and wrote their archive, and `tar -tzf` showed the file under its own name and both names of the link.
- `finish` printed `ok    kerbrute 1.0.3 removed`. While it waited at `remove working folder?`, a file was written into the box from the other shell; on `y` it printed `warn  targets/dc12/scan-late.txt changed after the archive was made; the folder was kept`, and the folder was still there.
- `pwn-broker import` of that finished archive asked `a box named 2026-11-17_htb_rel012 is already here. replace it?`, replaced it on `y`, offered the tool again and opened the box. A second `finish` asked before replacing the archive and removed the folder. Afterwards `bin/` held only `pwn-broker` and `record`, and `tools/` only `installed.toml`.
- The installed `vimrc` still clears the note's unsaved mark when vim saves by itself.

`v0.1.3`, over that `v0.1.2` install, the same way, in a terminal with full colour.

- The `curl` line upgraded the install: `pwn-broker --version` printed `pwn-broker 0.1.3`, and nothing under `/opt/pwn-broker` belonged to anyone but that user. Every `ok` line, the installer's and the three the app prints in the middle, carried the same two colour codes.
- `pwn-broker import` of a finished archive whose box had `kerbrute`, with `install these tools again?` answered `n`, then `finish`: the summary had no `tools` row and no tool line followed the archive. Afterwards `bin/` held only `pwn-broker` and `record`, and `tools/` only `installed.toml`.
- Before the release, with the same code run by the 0.1.2 install's Python: two boxes with `kerbrute`. The first `finish` listed `tools    kerbrute 1.0.3   (will be kept; sharea still uses it)` and printed `ok    kerbrute 1.0.3 kept; sharea still uses it`; the second listed `(will be removed)` and removed it. That case was not run again on the published file.

### A normal user with `sudo`

`v0.1.0`, as a user named `kali` made with `useradd`: in the `sudo` group, with zsh and Kali's own `.zshrc`, and a `sudo` that asks for a password. `sudo -K` was run before each step below that needs `sudo`, so every prompt showed.

- With root's `/opt/pwn-broker` still in place, the install line printed `fail  /opt/pwn-broker belongs to root. run the installer as that user` and changed nothing. After `sudo mv /opt/pwn-broker /opt/pwn-broker.old`, the same line asked for the `sudo` password once, on the terminal though the script arrives on a pipe, printed every `ok` line, and left `/opt/pwn-broker` and everything in it owned by `kali`. Run again over itself it asked for no password.
- A new box with a target: `add web01's hostnames to /etc/hosts? [Y/n]` asked for the password and wrote the line, and `host add` rewrote it. `/etc/hosts` stayed root's, mode 644. The note opened in one vim, in a terminal window of its own.
- `vpn start` copied the file, asked for the password and printed `ok    vpn up, 10.10.14.7 on tun0`. OpenVPN ran as root; its settings copy, log, process ID file and marker in `/opt/pwn-broker/run/vpn` belonged to `kali`. `vpn status`, `vpn log` and `status` showed the tunnel.
- `tool install` ran for `kerbrute`, `ligolo-ng` and `certipy` from the published index, and `certipy` brought the runtime. `kerbrute version`, `certipy -h` and `ligolo-proxy -h` each started, and `sudo /opt/pwn-broker/bin/ligolo-proxy -h` ran the installed one.
- `sudo /opt/pwn-broker/bin/pwn-broker` printed `fail  pwn-broker was installed by kali; run it as kali`, and `sudo /opt/pwn-broker/bin/record` printed `fail  record must run as kali, the user who installed pwn-broker. run record first, then sudo inside it`. Each exited with status 1.
- `record` in a second window recorded as `kali`, and `sudo id` inside it worked. Two wrong passwords and the right one were typed at `sudo`'s prompt; none of the three is in the `.cast` or the `.txt`.
- `finish` asked for the password to take the line out of `/etc/hosts` and again to stop the VPN, printed `warn  root's home could not be checked for ligolo-ng's data`, and removed the three tools and the runtime. Afterwards `/etc/hosts` was byte for byte what it was before the box, nothing under `/opt/pwn-broker` or the home folder belonged to root, and no OpenVPN, `tun0`, note vim or terminal window was left.
- In another box, Ctrl-C at `sudo`'s prompt for `/etc/hosts` printed `warn  /etc/hosts was not changed: sudo was cancelled` and the line to add by hand. Three wrong passwords at `host file on` printed `warn  /etc/hosts was not changed: cp exited 1` and the same line. Ctrl-C at `sudo`'s prompt in `vpn start` printed `cancelled`, and `vpn status` then said `not up`.
- In another, `sudo` made two files and a folder with a file in it under a target's `scans/`, all root's, and one more file only root could read. `finish` asked for the password once, wrote and verified the archive with all four files in it, and removed the working folder.
- With `tools_index` set to a folder filled by `pwn-shop`'s `fetch.sh`, and the shell in a network namespace whose only interface was `lo`, down: the launch ran its checks, a box was made, `tool install` ran for `certipy` with the runtime, `ligolo-ng` and `pspy`, and `finish` removed them.
- Then with a `sudo` that needs no password: `kali-grant-root` 2024.4.0 installed and the user added to `kali-trusted`, so `sudo -n` worked. With `/opt/pwn-broker` moved aside, the install line printed every `ok` line and asked for nothing. In one box the `/etc/hosts` line was written, `vpn start` brought `tun0` up, `ligolo-ng` was installed and `sudo /opt/pwn-broker/bin/ligolo-proxy -h` ran, a window was recorded with `sudo id` in it, and `sudo` made three files under a target's `scans/`, one of them readable by root alone. `finish` archived all three, took the line out of `/etc/hosts`, stopped the VPN and removed the folder, with no prompt at any step. `/etc/hosts` was byte for byte what it was before, and nothing under `/opt/pwn-broker` or the home folder belonged to root.

## pwn-shop's packages

- The seven packages in `pwn-shop`, in its CI on `main` (run 43772170454): the six tools and the `python-3.13` runtime. Its `packages` job, on Ubuntu 24.04, built the runtime and build 3 of `certipy` and `targetedkerberoast`, downloaded the four packages already published and rebuilt each to the same bytes, and installed all seven through this app's own code under Python 3.12, 3.13 and 3.14, then started each tool's commands. Its `kali` job, in the official Kali image (Kali 2026.3, Python 3.14.8) with the container's network confirmed off, installed the runtime and all six tools through this app's own code and started each tool. The run then published the runtime and build 3 of `certipy` and `targetedkerberoast`. Builds 1 and 2 of those two were withdrawn afterwards, so every package has exactly one published build.
- The published index, on Windows 11 on 2026-11-15, the day both repositories became public: with no `tools_index` setting, the app's own code loaded the index from `pwn-shop`'s release and downloaded `certipy` 5.1.0 build 3 and the `python-3.13` runtime, and each matched the size and SHA-256 the index gives. Nothing was installed there.
- `tool install` from the published index has run on Kali by hand for all six tools, with the runtime that two of them require ([above](#the-published-release)). CI installs every package from a folder, with the network off.

## Not tested

- A full Kali desktop session. CI's Kali run used a virtual display and `xterm`, and the run by hand used Kali's own qterminal under WSL, so Xfce, its window manager and focus have not been tried. Nor has your own VM.
- A normal user anywhere but that one run by hand under WSL, with a `sudo` that asks for a password and then with one that does not. CI's Kali run is root.
- A real Hack The Box connection. The OpenVPN file in the Kali run has no server behind it.
- A real tool package against a real target. `pwn-shop`'s CI installed and started each one on Kali, in a container, and all six were installed from the published index, started once and removed by `finish` in the run by hand under WSL. Three were installed and started by a normal user there. None has been run on a full Kali desktop or against a real target.
- On a terminal that hosts all its windows in one server process, such as gnome-terminal, `finish` closes the note's vim but cannot close its window. Whether that terminal then closes the window by itself has not been tried.

## Known limits

The full list. The README carries the ones you are most likely to meet.

- A release is x86_64 Linux with glibc only. The app's own Python and OpenSSL are fixed when a release is made, not when Kali updates, and the app takes about 100 MB more on disk.
- Close pwn-broker before you run the installer. An upgrade replaces `app/` and `python/` under a running prompt, and the installer does not check whether one is open.
- After a killed or interrupted install, `/opt/pwn-broker/.install.<random>` can be left behind, and it may hold the previous install.
- `SHA256SUMS.txt` comes from the same release as the file it checks, and the tool index is not signed: the checks catch corruption and a swapped zip, not who published either.
- A window still recording has no text copy until it closes or the box is exported.
- A full-screen program (vim, less, a menu) appears only in the `.cast`. The text copy has one line saying when it ran.
- A password typed on a command line in a recorded window is recorded, and goes into the archive. One typed at a hidden prompt is not.
- The `[rec]` prefix is for zsh and bash only. Any other shell records without it.
- `finish` refuses while a window is recording for the box. Exit those windows first.
- Checking an archive reads its whole manifest into memory. The largest one accepted is 64 MiB, which is what a box of about 250,000 files makes: that took 8 seconds and 370 MiB to read on the test machine. One of the same size written to be slow took 23 seconds and 1.5 GiB. Import an archive from someone else with that in mind.
- `finish` looks at every file's size and time once more before it removes the folder. A file written in the moment between that look and the removal is still lost; stop what writes into the box first.
- Only `tun` interfaces count as a VPN, and there is no setting for it.
- Only OpenVPN files can be started, and the app keeps track of one VPN at a time: `vpn stop` before starting another file.
- An archive holds no copy of the VPN file, only its name and SHA-256. Keep the `.ovpn` file yourself.
- A tunnel the app did not start is never stopped by it, at `vpn stop` or at `finish`.
- Ctrl-C while `vpn start` waits for OpenVPN to write its process ID can leave an OpenVPN running that the app does not track. `vpn stop` calls it a tunnel not started by pwn-broker; stop it by hand.
- Starting a second tunnel while one the app did not start is up is reported as not up after 15 seconds, because the app reads only the lowest-numbered tunnel.
- `quit` leaves the box's `/etc/hosts` lines in place. Only `finish` removes them; until then the hostnames go on resolving to the box's targets.
- Lines in `/etc/hosts` that are not the app's are never changed. One that names the same host with another address has to be removed by hand; the `warn` line gives its number and the command to run after.
- Builds 1 and 2 of the two Python tool packages, `certipy` and `targetedkerberoast`, were withdrawn on 2026-11-15, before any box had used them. Build 3 of each, which requires the `python-3.13` runtime, is the only one published. The other four tools need no Python. A tool that still runs on Kali's own Python says so if Kali's Python cannot make its environment; none is published.
- A runtime carries its own OpenSSL and other libraries. They are fixed when a new build of the runtime is published, not when Kali updates. The first tool that requires one costs a download the app shows as 34 MB, about 100 MB unpacked, and the zip kept in the download cache.
- After Ctrl-C at a yes or no question, the next line follows directly under the question, with no blank line between.
- `--help` and `--version` are printed without colour.
- Stop a tool before you type `finish`. `finish` refuses while one of the box's tools is running, but a tool started after that check can write into its home folder while the box is being archived, and those files are deleted without being copied.
- Tool data that could not be copied into the box in full is left in the home folder with a `warn` line. A later install of the same tool treats it as having been there before, so it is never copied or deleted again. Move it yourself.
- Within one install of a tool, a second `export` or `finish` replaces the box's copy of that tool's data with the current one. Files the tool deleted in between are only in the earlier archive.
- If `tools/installed.toml` is damaged, `finish` stops and names it. Moving it aside makes the next launch offer to remove every tool's files as leftovers; say yes and install the tools again.
- Run as a normal user, the app cannot read root's home folder. Data a tool wrote there under `sudo` is not copied or deleted; `finish` prints a `warn` line saying so.
- `cred list` marks a secret it cannot show exactly (a tab, another control character, or a space at either end) with `*` after the number. `cred show` prints it unchanged.
- Links and special files (named pipes, sockets, devices) in a box are not archived. `export` and `finish` list them, and `finish` says how many will go when the folder is removed.
