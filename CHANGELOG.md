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
- Settings in `config.toml`: `home`, `copy_to`, `default_platform`, `terminal`, `check_updates`, `tools_index`.
- Not in this version: recording and `/etc/hosts` management. The published tool index is private for now, so `tools_index` must point at a folder.
