# Changelog

## Unreleased

What a tool package is checked for, made stricter. No published package is affected.

- A package's commands may not take the name of a program the app runs itself: `chown` and `x-terminal-emulator` were missing, so with `/opt/pwn-broker/bin` first on PATH the app would have run a package's copy, as root when the app is. More names that ask for a password, manage the system, fetch something to run, or that other programs start to show or edit something (`less`, `pager`, `editor`) are reserved too, and so are Python and pip under a versioned name such as `python3.13` or `python3.13t`.
- A zip whose list of entries is larger than 4 MiB is refused before the list is read. A zip of nothing but two million entries cost 800 MiB of memory before the limit of 10,000 entries was applied.
- A tool's files and folders get their modes set at unpack (755, and 644 for what is not run), as a runtime's do. They used to follow the umask, so under a loose one a file a launcher runs was writable by anyone on the machine. A folder is made closed and then opened, so it is at no moment looser than it ends up, and a link that turns up where a folder goes is not followed.
- A package or index version has to start with a letter or digit and hold only letters, digits and `. _ + ~ -`, 100 characters at most. It used to be refused only for a slash, a backslash or a space.
- A zip entry's name may not hold a colon or a control character, or be longer than a path may be, as a runtime archive's may not. No name or link target in a package may have more than 64 parts: 20 files under a name 1,900 parts deep took six seconds to unpack, and a tree that deep could not always be removed again. A stored zip entry whose two sizes differ is refused.
- A runtime archive's extended header records are dropped as each entry passes its checks. Kept, a 15 KiB record on each of 20,000 entries held 300 MiB.
- A manifest may not claim more of the home folder: places that hold keys or sign-ins (`.aws`, `.kube`, `.docker`, `.netrc`, `.git-credentials` and others), places that run something at login or in every shell (`.bash_aliases`, `.xprofile`, `.config/fish` and others), the folders a desktop makes (`Pictures`, `Music` and the rest), and anything under `.local/bin`.
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
