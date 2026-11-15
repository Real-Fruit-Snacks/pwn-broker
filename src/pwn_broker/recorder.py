import hashlib
import os
from collections.abc import Callable
from pathlib import Path

from pwn_broker import toolindex
from pwn_broker.paths import AppPaths
from pwn_broker.toolindex import ToolError

VERSION = "3.2.1"
URL = f"https://github.com/asciinema/asciinema/releases/download/v{VERSION}/asciinema-x86_64-unknown-linux-musl"
SIZE = 8130064
SHA256 = "bec9781bc8f297a9d3d74ff60205599507f2abba1183578b8b2f22be4c999214"

_CHUNK = 1 << 16


class RecorderError(Exception):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def present(paths: AppPaths, *, sha256: str = SHA256) -> bool:
    """True when the app's asciinema is a regular file with the pinned checksum."""
    try:
        return paths.asciinema.is_file() and _sha256(paths.asciinema) == sha256
    except OSError:
        return False


def fetch(
    paths: AppPaths,
    *,
    download: Callable[[str, Path, int, float], None] = toolindex.download,
    timeout: float = 120.0,
    size: int = SIZE,
    sha256: str = SHA256,
) -> None:
    """Download the pinned asciinema into place, or raise RecorderError and change nothing."""
    target = paths.asciinema
    temp = target.with_name(f".{target.name}.{os.getpid()}.part")
    try:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            download(URL, temp, size, timeout)
            try:
                got = temp.stat().st_size
            except FileNotFoundError:
                raise RecorderError("the download has the wrong size: nothing was written") from None
            if got != size:
                raise RecorderError(f"the download has the wrong size: {got} bytes, expected {size}")
            if _sha256(temp) != sha256:
                raise RecorderError("the download does not match its checksum")
            os.chmod(temp, 0o755)
            os.replace(temp, target)
        except (ToolError, OSError) as exc:
            raise RecorderError(str(exc)) from exc
    finally:
        try:
            temp.unlink()
        except OSError:
            pass
