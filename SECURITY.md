# Security

## Supported versions

The latest release only. Fixes ship as a new SemVer tag; there are no backports.

## Reporting

Use GitHub's private vulnerability reporting on this repository (Security → Report a vulnerability). Don't open a public issue for anything that could write outside a box folder or expose a credential.

Include `pwn-broker --version`, your Kali and Python versions, whether you ran it as root or a normal user, and the commands that show the problem. Use placeholder credentials and flags.

This is a one-person project. I read reports within a week. If it's real, the fix and the changelog entry name the problem plainly.

## What counts

- An imported archive that writes, links or overwrites anything outside the box folder it is unpacked into.
- Anything that alters, leaks or mis-stores a credential: a value changed on the way in or out or a secret written somewhere it shouldn't be.
- The installer or its checksum step: `install.sh` installing a wheel whose SHA-256 does not match `SHA256SUMS.txt`, or deleting or replacing something that isn't its own.
- A tool package or index that gets past the checks: a download or cached zip used although its size or SHA-256 differs from the index, a package that runs something other than `pip` installing bundled wheels during install, a Python tool installed from anything but its bundled, hash-checked wheels, or an entry that unpacks outside the tool's folder.
- A tool removal that deletes anything outside `/opt/pwn-broker`, or tool data deleted from the home folder that existed before the install.
- The `sudo` handling: a way to run something as root that the user didn't ask for, or ownership left wrong after a root-run tool.

## What this tool handles

- Network: none while you work, except the `tool` commands that need the index or a package, which download from `tools_index` when it is a URL. It uploads nothing. The installer downloads the wheel and `SHA256SUMS.txt` from the latest GitHub release over HTTPS and checks the wheel's SHA-256 before installing anything.
- Credentials: kept exactly as typed in a box's own files on your disk, and copied into the `lists/` folder for other tools. They are not encrypted; treat a box folder, its archives and its exports like the credentials they hold.
- Privileges: it runs as the user who installed it and refuses to start as anyone else. It uses `sudo` only for the few privileged steps it needs, such as creating its install folder and correcting file ownership.
- Archives: unpacking refuses any entry that would land outside the box folder.
- Tool packages: a download is checked against the size and SHA-256 in the index, and so is a cached zip each time it is used. A package holds no install script, and nothing from it runs during install; a Python tool's dependencies are installed from wheels in the package with `pip --no-index --only-binary :all: --require-hashes`. Unpacking refuses any entry outside the tool's folder, and any link. Deletes are guarded: the app refuses to remove anything outside `/opt/pwn-broker`, whatever a manifest or index says, and never deletes home-folder data that existed before the install. An index or package whose `schema` is not 1 is refused. The index and the zips come from `tools_index`, over HTTPS or from a folder; the hash check catches corruption and a swapped zip, but the index itself is not signed, so it does not prove who published it. `/opt/pwn-broker/bin` is writable by your user and first on your PATH, so anything running as you could place a command there. On a single-user lab VM that is acceptable; it would not be on a shared machine.

## Out of scope

The tools you run alongside it, and Hack The Box itself: report to the tool's maintainers and to [Hack The Box](https://help.hackthebox.com/).
