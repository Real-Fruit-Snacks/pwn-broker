import base64
import gzip
import hashlib
import io
import sys
import tarfile
import zipfile
from pathlib import Path

import tomli_w

from pwn_broker.filescan import sha256_file


# every zip made here carries this date, so the same content always gives the same bytes and
# checksum whenever it is built
_ZIP_DATE = (1980, 1, 1, 0, 0, 0)


def _put(zf: zipfile.ZipFile, name: str, data: bytes | str) -> None:
    info = zipfile.ZipInfo(name, date_time=_ZIP_DATE)
    info.compress_type = zf.compression
    info.external_attr = 0o600 << 16  # what writestr gives a member named by a string
    zf.writestr(info, data)


def _record_line(name: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{name},sha256={digest},{len(data)}"


def make_wheel(
    folder: Path, dist: str, version: str, *, module: str, entry: str | None = None
) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    stem = dist.replace("-", "_")
    info = f"{stem}-{version}.dist-info"
    files = {
        f"{module}.py": (
            f"def main():\n    print({dist + ' ' + version!r})\n\n\n"
            'if __name__ == "__main__":\n    main()\n'
        ).encode(),
        f"{info}/METADATA": f"Metadata-Version: 2.1\nName: {dist}\nVersion: {version}\n".encode(),
        f"{info}/WHEEL": (
            "Wheel-Version: 1.0\nGenerator: toolkit\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ).encode(),
    }
    if entry is not None:
        files[f"{info}/entry_points.txt"] = (
            f"[console_scripts]\n{entry} = {module}:main\n"
        ).encode()
    lines = [_record_line(name, data) for name, data in files.items()]
    lines.append(f"{info}/RECORD,,")
    files[f"{info}/RECORD"] = ("\n".join(lines) + "\n").encode()
    path = folder / f"{stem}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            _put(zf, name, data)
    return path


RUNTIME_ARCHIVE = b"runtime archive stand-in\n"


def _runtime_defaults() -> dict:
    return {
        "schema": 2,
        "name": "python-3.13",
        "version": "3.13.18",
        "build": 1,
        "kind": "runtime",
        "description": "CPython 3.13, for the tools that require it",
        "upstream": "https://github.com/astral-sh/python-build-standalone",
        "licence": "PSF-2.0",
        "arch": "x86_64",
        "runtime": {
            "archive": "files/python.tar.gz",
            "python": "python/bin/python3.13",
            "series": "3.13",
        },
    }


def _notes_defaults() -> dict:
    return {
        "schema": 3,
        "name": "playbooks",
        "version": "2026.11.19",
        "build": 1,
        "kind": "notes",
        "description": "Playbooks to read into the note and fill in",
        "tags": ["notes", "playbooks"],
        "upstream": "https://github.com/Real-Fruit-Snacks/pwn-playbooks",
        "licence": "CC-BY-4.0",
        "arch": "any",
        "needs_root": False,
        "notes": {"root": "files/playbooks"},
    }


def built_playbook(name: str, title: str, rel: str, placeholders: list[str], body: str,
                   version: str = "2026.11.19") -> str:
    """A playbook as pwn-playbooks builds it: one fold, its run block, Fill in, body, end line."""
    lines = [
        "##########@@@@@@@@@@",
        f"Playbook: {title}   {rel}   {version}",
        "my",
        f"/^END OF {name} PLAYBOOK$",
        "mz",
        *[f":'y,'zs/{p}/<Replace>/ge" for p in placeholders],
        "'y",
        "",
        "Fill in:  " + "  ".join(placeholders),
        "",
        body.rstrip("\n"),
        "",
        f"END OF {name} PLAYBOOK",
        "@@@@@@@@@@##########",
    ]
    return "\n".join(lines) + "\n"


SMB_BODY = "## Null session\nnxc smb <TargetIP> -u '' -p ''\nnxc smb <TargetIP> -u <Username> -p ''\n"
SERVICES_BODY = "## Weak service permissions\nsc.exe qc <Service>\n"


def notes_files() -> dict[str, bytes]:
    return {
        "files/playbooks/02-enum/smb.md": built_playbook(
            "smb", "SMB enumeration", "02-enum/smb", ["<TargetIP>", "<Username>"], SMB_BODY
        ).encode(),
        "files/playbooks/06-privesc/windows/services.md": built_playbook(
            "services", "Windows privesc: services", "06-privesc/windows/services",
            ["<Service>"], SERVICES_BODY,
        ).encode(),
    }


def make_notes_entry(folder: Path, files: dict | None = None, **overrides):
    """A notes package, the playbooks by default, with its index entry."""
    from pwn_broker.toolindex import BuildEntry

    manifest = sample_manifest(kind="notes", **overrides)
    zip_path, size, sha = make_package(folder, manifest, notes_files() if files is None else files)
    entry = BuildEntry(
        name=manifest["name"],
        version=manifest["version"],
        build=manifest["build"],
        kind="notes",
        needs_root=False,
        commands=[],
        file=zip_path.name,
        url="",
        size=size,
        sha256=sha,
    )
    return zip_path, entry


def sample_manifest(**overrides) -> dict:
    # kind="runtime" gives a runtime package; kind="notes" a schema 3 notes package;
    # requires=[...] gives a schema 2 Python tool
    if overrides.get("kind") == "runtime":
        data = _runtime_defaults()
    elif overrides.get("kind") == "notes":
        data = _notes_defaults()
    elif "requires" in overrides:
        data = _tool_defaults()
        data.update(
            schema=2,
            command=[{"name": "kerbrute", "type": "python-entry", "entry": "kerbrute"}],
            python={"lock": "wheels.lock", "wheels": "wheels"},
        )
    else:
        data = _tool_defaults()
    data.update(overrides)
    return data


def _tool_defaults() -> dict:
    return {
        "schema": 1,
        "name": "kerbrute",
        "version": "1.0.3",
        "build": 1,
        "kind": "kali",
        "description": "Kerberos user enumeration",
        "tags": ["kerberos"],
        "upstream": "https://github.com/ropnop/kerbrute",
        "licence": "Apache-2.0",
        "arch": "x86_64",
        "needs_root": False,
        "examples": ["kerbrute userenum -d {domain} users.txt"],
        "command": [{"name": "kerbrute", "type": "binary", "path": "files/kerbrute"}],
    }


def make_package(
    folder: Path,
    manifest: dict,
    files: dict[str, bytes],
    *,
    wheels: list[Path] = (),
    lock: bytes | None = None,
) -> tuple[Path, int, str]:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{manifest['name']}-{manifest['version']}-{manifest['build']}.zip"
    entries = {"manifest.toml": tomli_w.dumps(manifest).encode(), "LICENSE": b"licence text\n"}
    entries.update(files)
    runtime = manifest.get("runtime")
    if isinstance(runtime, dict) and isinstance(runtime.get("archive"), str):
        # the package checks only ask that the archive is there, so any bytes stand in for it
        entries.setdefault(runtime["archive"], RUNTIME_ARCHIVE)
    pins = []
    for wheel in wheels:
        dist, version = wheel.name.split("-")[:2]
        entries[f"wheels/{wheel.name}"] = wheel.read_bytes()
        pins.append(f"{dist.replace('_', '-')}=={version} --hash=sha256:{sha256_file(wheel)}")
    if wheels:
        entries["wheels.lock"] = ("\n".join(pins) + "\n").encode()
    if lock is not None:
        entries["wheels.lock"] = lock
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
        for name, data in entries.items():
            _put(zf, name, data)
    return path, path.stat().st_size, sha256_file(path)


def make_entry(folder: Path, manifest_overrides: dict | None = None, files: dict | None = None):
    # a binary package built for this machine, with its index entry
    from pwn_broker.toolindex import BuildEntry
    from pwn_broker.toolpkg import machine_arch

    manifest = sample_manifest(arch=machine_arch(), **(manifest_overrides or {}))
    if files is None:
        files = {} if manifest["kind"] == "runtime" else {"files/kerbrute": b"#!/bin/sh\necho hi\n"}
    zip_path, size, sha = make_package(folder, manifest, files)
    entry = BuildEntry(
        name=manifest["name"],
        version=manifest["version"],
        build=manifest["build"],
        kind=manifest["kind"],
        needs_root=manifest.get("needs_root", False),
        commands=[c["name"] for c in manifest.get("command", [])],
        file=zip_path.name,
        url="",
        size=size,
        sha256=sha,
        requires=list(manifest.get("requires", [])),
    )
    return zip_path, entry


def stand_in_python() -> bytes:
    # a POSIX shell script that runs this machine's own Python, so an environment can be made
    quoted = "'" + sys.executable.replace("'", "'\\''") + "'"
    return f'#!/bin/sh\nexec {quoted} "$@"\n'.encode()


def runtime_archive(members: dict[str, bytes]) -> bytes:
    # a gzip tar of executable files and the folders they sit in
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        folders = {n.rsplit("/", 1)[0] for n in members if "/" in n}
        for top in list(folders):
            while "/" in top:
                top = top.rsplit("/", 1)[0]
                folders.add(top)
        for name in sorted(folders):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            tar.addfile(info)
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), mtime=0)


def make_runtime(
    folder: Path,
    name: str = "python-3.13",
    version: str = "3.13.18",
    series: str = "3.13",
    *,
    build: int = 1,
    archive: bytes | None = None,
):
    """A runtime package and its index entry; its archive holds python/bin/python<series>."""
    from pwn_broker.toolindex import BuildEntry
    from pwn_broker.toolpkg import machine_arch

    interpreter = f"python/bin/python{series}"
    manifest = sample_manifest(kind="runtime", name=name, version=version, build=build)
    manifest["arch"] = machine_arch()
    manifest["runtime"] = {
        "archive": "files/python.tar.gz",
        "python": interpreter,
        "series": series,
    }
    if archive is None:
        archive = runtime_archive({interpreter: stand_in_python()})
    zip_path, size, sha = make_package(folder, manifest, {"files/python.tar.gz": archive})
    entry = BuildEntry(
        name=name,
        version=version,
        build=build,
        kind="runtime",
        needs_root=False,
        commands=[],
        file=zip_path.name,
        url="",
        size=size,
        sha256=sha,
    )
    return zip_path, entry


def write_index(folder: Path, entries: list) -> Path:
    # a folder index (tools_index pointing at a directory): index.toml next to the zips
    tools: dict[str, list] = {}
    for e in entries:
        tools.setdefault(e.name, []).append(e)
    rows = []
    for name, builds in tools.items():
        rows.append(
            {
                "name": name,
                "description": f"{name} stand-in",
                "tags": [],
                "licence": "MIT",
                "upstream": "https://example.invalid/" + name,
                "latest": f"{builds[-1].version}-{builds[-1].build}",
                "build": [_build_row(b) for b in builds],
            }
        )
    # schema 2 only when an entry needs it, so an index of schema 1 packages stays schema 1;
    # schema 3 when it holds a notes package
    if any(e.kind == "notes" for e in entries):
        schema = 3
    elif any(e.kind == "runtime" or e.requires for e in entries):
        schema = 2
    else:
        schema = 1
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "index.toml"
    path.write_text(tomli_w.dumps({"schema": schema, "tool": rows}), encoding="utf-8")
    return path


def _build_row(b) -> dict:
    row = {
        "version": b.version,
        "build": b.build,
        "kind": b.kind,
        "needs_root": b.needs_root,
        "commands": b.commands,
        "file": b.file,
        "size": b.size,
        "sha256": b.sha256,
    }
    if b.requires:
        row["requires"] = list(b.requires)
    return row


def make_python_tool(
    folder: Path, name: str = "certipy", version: str = "5.1.0", *, build: int = 3, **overrides
):
    """A schema 2 Python tool that requires python-3.13, and its index entry."""
    from pwn_broker.toolindex import BuildEntry
    from pwn_broker.toolpkg import machine_arch

    wheel = make_wheel(folder / "wheel-source", f"{name}-py", "1.0", module="tool", entry=name)
    manifest = sample_manifest(
        name=name, version=version, build=build, arch=machine_arch(), requires=["python-3.13"],
        command=[{"name": name, "type": "python-entry", "entry": name}], **overrides,
    )  # fmt: skip
    zip_path, size, sha = make_package(folder, manifest, {}, wheels=[wheel])
    entry = BuildEntry(
        name=name,
        version=version,
        build=build,
        kind=manifest["kind"],
        needs_root=False,
        commands=[name],
        file=zip_path.name,
        url="",
        size=size,
        sha256=sha,
        requires=list(manifest["requires"]),
    )
    return zip_path, entry


def no_real_venv(monkeypatch, *, fail: str | None = None):
    """Stands in for the programs an install runs, so nothing runs.

    Kali's Python reports 3.13; `fail` names a step ("venv" or "pip") that exits 1.
    """
    from types import SimpleNamespace

    from pwn_broker import toolinstall

    calls: list[list[str]] = []

    def run(argv, **kwargs):
        calls.append(list(argv))
        if argv[1:3] == ["-I", "-c"]:
            return SimpleNamespace(returncode=0, stdout="3.13\n", stderr="")
        if fail is not None and fail in argv:
            return SimpleNamespace(returncode=1, stdout="", stderr=f"{fail} refused\n")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    defaults = {**toolinstall.install.__kwdefaults__, "run": run}
    monkeypatch.setattr(toolinstall.install, "__kwdefaults__", defaults)
    return calls
