# Changelog

## v0.1.0 (unreleased)

- Installer: `install.sh` builds a virtual environment under `/opt/pwn-broker`, installs the package and adds the PATH line. It takes `--from`, `--config` and `--no-path`.
- Launch checks, a menu to start, import or resume a box, and a lock so only one box is open at a time.
- New box questions, targets with their own folders, and a note window in vim that saves as you type.
- A prompt with target, credential, flag, file and status commands.
- Credentials kept as typed, with the `lists/` folder rebuilt from them for other tools.
- File records with SHA-256, kept in `files.toml`.
- `finish` to archive and close a box, `export` for a snapshot, and `import` to unpack one.
- Settings in `config.toml`: `home`, `copy_to`, `default_platform`, `terminal`, `check_updates`.
- Not in this version: recording, `/etc/hosts` management and tool install.
