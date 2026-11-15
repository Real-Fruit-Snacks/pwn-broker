import base64
import hashlib
import zipfile
from pathlib import Path

import tomli_w

from pwn_broker.filescan import sha256_file


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
            zf.writestr(name, data)
    return path


def sample_manifest(**overrides) -> dict:
    data = {
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
    data.update(overrides)
    return data


def make_package(
    folder: Path, manifest: dict, files: dict[str, bytes], *, wheels: list[Path] = ()
) -> tuple[Path, int, str]:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{manifest['name']}-{manifest['version']}-{manifest['build']}.zip"
    entries = {"manifest.toml": tomli_w.dumps(manifest).encode(), "LICENSE": b"licence text\n"}
    entries.update(files)
    lock = []
    for wheel in wheels:
        dist, version = wheel.name.split("-")[:2]
        entries[f"wheels/{wheel.name}"] = wheel.read_bytes()
        lock.append(f"{dist.replace('_', '-')}=={version} --hash=sha256:{sha256_file(wheel)}")
    if wheels:
        entries["wheels.lock"] = ("\n".join(lock) + "\n").encode()
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path, path.stat().st_size, sha256_file(path)
