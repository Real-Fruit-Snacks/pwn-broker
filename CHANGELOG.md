# Changelog

## v0.1.0 (unreleased)

- Installer: `install.sh` builds a virtual environment under `/opt/pwn-broker`, installs the package and adds the PATH line. It takes `--from`, `--config` and `--no-path`.
- Launch checks, a menu to start, import or resume a box, and a lock so only one box is open at a time.
- New box questions, targets with their own folders, and a note window in vim that saves as you type.
- A prompt with target, credential, flag, file and status commands.
- Credentials kept as typed, with the `lists/` folder rebuilt from them for other tools.
- File records with SHA-256, kept in `files.toml`.
- `finish` to archive and close a box, `export` for a snapshot, and `import` to unpack one.
- Tool installs: `tool list`, `search`, `info`, `install`, `remove`, `refresh` and `cache clear`. A package is a zip checked against the size and SHA-256 in the index; a Python tool is installed into its own virtual environment from bundled wheels with no network and hash checking on, after its `wheels.lock` is checked line by line. Nothing from a package runs during install, and Kali's own copies of a tool are never changed.
- Tools are removed at `finish` unless another unfinished box still uses them. Tool data in the home folder is copied into the box first and deleted only if it did not exist before the install; a path that could not be copied in full is kept, with a warning. `tool remove` by the last box that uses a tool does the same. `finish` refuses while one of the box's tools is running. `export` copies tool data and removes nothing, and `import` and reopening a box offer to install its tools again.
- Recording: `record [target]` records a terminal window into the target's `recordings/` folder under the pinned asciinema, with a `[rec <target>]` prefix on the zsh or bash prompt. An address that is not a target can be added from `record`; the prompt and `record` share a lock, and the prompt reloads the box when it changed on disk.
- A text copy beside each recording, with the time on every line, made by replaying the `.cast` through `pyte`. Full-screen programs are one line; the `.cast` holds them.
- `replay` lists a target's recordings and plays one, with idle gaps cut to two seconds. `finish` refuses while a window is recording; `export` warns and packs a recording up to its last whole line. `status` gains a `recordings` line and the status bar `rec <n>`.
- `/etc/hosts`: a line per target, marked with the box ID, offered by `target add` and `target edit` (default yes), kept in step with the target, removed at `finish` and put back when the box opens. `host`, `host add`, `host remove`, `host file on` and `host file off`. Only the app's marked lines are changed; as a normal user the file is copied into place with `sudo`.
- VPN: a `vpn` launch check, the tunnel's address in the status bar and `status`, and `vpn start`, `stop`, `status` and `log`. `vpn start` copies the `.ovpn` file into the box's `vpn/` folder, which is never archived, and starts OpenVPN in the background. `vpn stop` stops only the process the app started. `finish` asks whether to stop it, default no.
- Each new target with an IP is pinged once.
- Installer: downloads asciinema 3.2.1 from its upstream release and checks it against a pinned SHA-256; `--no-asciinema` skips it. The launch check `asciinema` offers to download it again, and the `record` launcher is put back if it is missing. `pyte` 0.8.2 is a new dependency.
- `record`, `asciinema`, `openvpn`, `ping` and `ip` join the command names a tool package may not use.
- Settings in `config.toml`: `home`, `copy_to`, `default_platform`, `terminal`, `check_updates`, `tools_index`.
- The published tool index is private for now, so `tools_index` must point at a folder. Recording, `/etc/hosts`, the VPN commands and the ping have not been run on Kali yet.
