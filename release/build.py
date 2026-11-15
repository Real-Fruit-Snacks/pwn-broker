"""Builds a release of pwn-broker as one file from pinned inputs.

    python release/build.py [--out dist] [--cache .cache/release]

The file holds the pinned upstream Python build byte for byte, the app's wheel and every locked
dependency's wheel, wheels.lock pinning each of them, the pinned asciinema and licences/. The
same checkout gives the same file, byte for byte, on any x86_64 Linux machine: every input is
pinned by its SHA-256, every archive member carries fixed times, owners and modes, and the
gzip wrapping is written here, so no compression library decides the bytes.

It runs on x86_64 Linux only, since it runs the Python it packs, from a checkout with the app
installed (it imports pwn_broker).
"""

import argparse
import binascii
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pwn_broker import recorder, runtimearchive, toolpkg
from pwn_broker.filescan import sha256_file

REPO = Path(__file__).resolve().parent.parent
APP = "pwn-broker"
# 1980-01-01 00:00:00 UTC, the time every member of the release carries
EPOCH = 315532800
SUMS = "SHA256SUMS.txt"
COMMAND_TIMEOUT = 1800
FETCH_TIMEOUT = 60
FETCH_DEADLINE = 900.0
_CHUNK = 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.!+_-]*")
_WHEEL = re.compile(
    r"(?P<name>[^-]+)-(?P<version>[^-]+)(?:-[0-9][^-]*)?-[^-]+-[^-]+-[^-]+\.whl"
)
# gzip: deflate, no flags, no time, no extra flags, unknown system
_GZIP_HEADER = bytes.fromhex("1f8b08000000000000ff")
_STORED_MAX = 65535


class BuildError(Exception):
    pass


@dataclass(frozen=True)
class Pin:
    version: str
    url: str
    size: int
    sha256: str


Fetch = Callable[[str, Path, int, str], None]
Run = Callable[..., subprocess.CompletedProcess]


def _ok(what: str) -> None:
    print(f"ok    {what}", flush=True)


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _unlink(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


# ---- pins and locks


def _read_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_bytes().decode("utf-8"))
    except OSError as exc:
        raise BuildError(f"cannot read {path}: {exc}") from exc
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise BuildError(f"{path} cannot be read ({exc})") from exc


def load_pins(path: Path) -> Pin:
    """The Python build's pin from release/pins.toml."""
    table = _read_toml(path).get("python")
    if not isinstance(table, dict):
        raise BuildError(f"{path.name} has no [python] table")
    version, url, size, sha256 = (table.get(k) for k in ("version", "url", "size", "sha256"))
    if not isinstance(version, str) or not version:
        raise BuildError(f"{path.name}: python.version must be a non-empty string")
    if not isinstance(url, str) or not url.startswith("https://"):
        raise BuildError(f"{path.name}: python.url must be an https address")
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        raise BuildError(f"{path.name}: python.size must be a whole number of 1 or more")
    if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
        raise BuildError(f"{path.name}: python.sha256 must be 64 lower-case hexadecimal characters")
    return Pin(version, url, size, sha256)


def _asciinema_pin() -> Pin:
    return Pin(recorder.VERSION, recorder.URL, recorder.SIZE, recorder.SHA256)


def project_version(pyproject: Path) -> str:
    version = _read_toml(pyproject).get("project", {}).get("version")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise BuildError(f"{pyproject.name}: project.version {version!r} is not a plain version")
    return version


def _parse_lock(raw: bytes, label: str) -> list[tuple[str, str, str]]:
    try:
        toolpkg.check_lock(raw, label)
    except toolpkg.ToolError as exc:
        raise BuildError(str(exc)) from exc
    pins = []
    seen: dict[str, int] = {}
    for number, line in enumerate(raw.decode("utf-8").split("\n")[:-1], start=1):
        pin, *hashes = line.split(" ")
        name, version = pin.split("==")
        if len(hashes) != 1:
            raise BuildError(
                f"{label} line {number}: {name} has {len(hashes)} hashes; a line holds exactly one"
            )
        key = _norm(name)
        if key in seen:
            raise BuildError(f"{label} line {number}: {name} is already pinned on line {seen[key]}")
        seen[key] = number
        pins.append((name, version, hashes[0].removeprefix("--hash=sha256:")))
    return pins


def read_lock(path: Path) -> list[tuple[str, str, str]]:
    """(name, version, sha256) for each line of a strict lock with one hash per line."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise BuildError(f"cannot read {path}: {exc}") from exc
    return _parse_lock(raw, path.name)


# ---- downloading


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise BuildError(f"redirect to {newurl!r} refused: only https addresses are accepted")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download(url: str, path: Path, limit: int) -> None:
    if not url.lower().startswith("https://"):
        raise BuildError(f"{url!r}: only https addresses are accepted")
    opener = urllib.request.build_opener(_HttpsOnly)
    request = urllib.request.Request(url, headers={"User-Agent": "pwn-broker-release-build"})
    deadline = time.monotonic() + FETCH_DEADLINE
    total = 0
    try:
        with opener.open(request, timeout=FETCH_TIMEOUT) as response, open(path, "wb") as out:
            while chunk := response.read(_CHUNK):
                total += len(chunk)
                if total > limit:
                    raise BuildError(f"{url}: the download is larger than the {limit} bytes pinned")
                if time.monotonic() > deadline:
                    raise BuildError(f"{url}: the download took too long")
                out.write(chunk)
    except BuildError:
        raise
    except Exception as exc:
        raise BuildError(f"cannot download {url}: {str(exc) or type(exc).__name__}") from exc


def _matches(path: Path, size: int, sha256: str) -> bool:
    try:
        return path.is_file() and path.stat().st_size == size and sha256_file(path) == sha256
    except OSError:
        return False


def fetch(
    url: str,
    dest: Path,
    size: int,
    sha256: str,
    *,
    download: Callable[[str, Path, int], None] = _download,
) -> None:
    """Leaves at dest the file of that size and SHA-256, or raises BuildError and leaves nothing.

    A cached file is reused only if it matches; otherwise it is removed and the file is
    downloaded to a temporary name beside dest, checked, and moved into place.
    """
    if _matches(dest, size, sha256):
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    _unlink(dest)
    part = dest.with_name(f".{dest.name}.{os.getpid()}.part")
    try:
        download(url, part, size)
        if not part.is_file():
            raise BuildError(f"{dest.name}: the download of {url} wrote nothing")
        found = part.stat().st_size
        found_sha = sha256_file(part)
        if found != size or found_sha != sha256:
            raise BuildError(
                f"{dest.name}: expected {size} bytes with SHA-256 {sha256}, "
                f"found {found} bytes with SHA-256 {found_sha}"
            )
        os.replace(part, dest)
    finally:
        _unlink(part)


def _cache_name(url: str) -> str:
    name = url.rstrip("/").rpartition("/")[2]
    if not name or name in (".", ".."):
        raise BuildError(f"{url}: the address does not end with a file name")
    return name


# ---- the archive


def _mode(path: Path) -> int:
    return 0o755 if path.stat().st_mode & stat.S_IXUSR else 0o644


def _tar_entries(tree: Path, top: str) -> list[tuple[str, Path]]:
    entries = [(top, tree)]
    for path in tree.rglob("*"):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise BuildError(f"{path} is not a regular file or folder")
        entries.append((f"{top}/{path.relative_to(tree).as_posix()}", path))
    return sorted(entries)


def _write_tar(tree: Path, top: str, fileobj) -> None:
    ustar = tarfile.USTAR_FORMAT
    with tarfile.open(fileobj=fileobj, mode="w", format=ustar, encoding="utf-8") as tar:
        for name, path in _tar_entries(tree, top):
            info = tarfile.TarInfo(name)
            info.mtime = EPOCH
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if path.is_dir():
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
            else:
                info.type = tarfile.REGTYPE
                info.mode = _mode(path)
                info.size = path.stat().st_size
            try:
                # the header is made before any data is read, so a name that does not fit
                # stops here
                info.tobuf(ustar, "utf-8", "strict")
            except ValueError as exc:
                raise BuildError(f"{name} does not fit a USTAR header ({exc})") from exc
            if path.is_dir():
                tar.addfile(info)
            else:
                with open(path, "rb") as fh:
                    tar.addfile(info, fh)


def _write_stored_gzip(src, dst) -> None:
    """Wraps src's bytes as gzip in deflate stored blocks: no compression, no library."""
    dst.write(_GZIP_HEADER)
    crc = 0
    length = 0
    block = src.read(_STORED_MAX)
    while True:
        following = src.read(_STORED_MAX) if block else b""
        final = not following
        dst.write(bytes([1 if final else 0]))
        dst.write(struct.pack("<HH", len(block), len(block) ^ 0xFFFF))
        dst.write(block)
        crc = binascii.crc32(block, crc)
        length += len(block)
        if final:
            break
        block = following
    dst.write(struct.pack("<II", crc & 0xFFFFFFFF, length & 0xFFFFFFFF))


def write_archive(tree: Path, out: Path, top: str) -> None:
    """Writes tree, under the one top folder top, as a gzip tar at out, or leaves nothing."""
    try:
        with tempfile.TemporaryFile(dir=out.parent) as tar:
            _write_tar(tree, top, tar)
            tar.seek(0)
            with open(out, "wb") as dst:
                _write_stored_gzip(tar, dst)
    except BaseException:
        _unlink(out)
        raise


# ---- the release tree


def _wheel_name(file_name: str) -> tuple[str, str] | None:
    found = _WHEEL.fullmatch(file_name)
    return (_norm(found["name"]), found["version"]) if found else None


def check_tree(root: Path, version: str) -> None:
    """Every wheel in wheels/ is named by exactly one line of wheels.lock with its SHA-256,
    every line has its wheel, and one of them is the app's at this version."""
    try:
        raw = (root / "wheels.lock").read_bytes()
    except OSError as exc:
        raise BuildError(f"cannot read wheels.lock: {exc}") from exc
    lines = {
        _norm(name): (number, name, v, sha)
        for number, (name, v, sha) in enumerate(_parse_lock(raw, "wheels.lock"), start=1)
    }
    folder = root / "wheels"
    if not folder.is_dir():
        raise BuildError("the release has no wheels/ folder")
    named: dict[str, str] = {}
    for path in sorted(folder.iterdir()):
        wheel = _wheel_name(path.name) if path.is_file() and not path.is_symlink() else None
        if wheel is None:
            raise BuildError(f"wheels/{path.name} is not a wheel")
        line = lines.get(wheel[0])
        if line is None or line[2] != wheel[1]:
            raise BuildError(f"wheels/{path.name} is not named by any line of wheels.lock")
        number, _name, _v, sha = line
        if wheel[0] in named:
            raise BuildError(
                f"wheels.lock line {number} names more than one wheel: "
                f"{named[wheel[0]]} and {path.name}"
            )
        found = sha256_file(path)
        if found != sha:
            raise BuildError(
                f"wheels/{path.name} has SHA-256 {found}, but wheels.lock line {number} gives {sha}"
            )
        named[wheel[0]] = path.name
    for key, (number, name, v, _sha) in lines.items():
        if key not in named:
            raise BuildError(
                f"wheels.lock line {number} ({name}=={v}) names a wheel that is not in wheels/"
            )
    app = lines.get(APP)
    if app is None or app[2] != version:
        raise BuildError(f"wheels.lock has no line for {APP} {version}")


def _app_wheel(folder: Path, version: str) -> Path:
    files = sorted(folder.iterdir())
    if not files:
        raise BuildError("hatchling made no wheel")
    if len(files) > 1:
        raise BuildError(
            f"hatchling made {len(files)} files ({', '.join(p.name for p in files)}), not one wheel"
        )
    (wheel,) = files
    if not wheel.is_file() or _wheel_name(wheel.name) != (APP, version):
        raise BuildError(f"hatchling made {wheel.name}, which is not a wheel of {APP} {version}")
    return wheel


def _wheels_lock(locked: list[tuple[str, str, str]], version: str, app_sha256: str) -> bytes:
    pins = [*locked, (APP, version, app_sha256)]
    pins.sort(key=lambda pin: _norm(pin[0]))
    return "".join(f"{n}=={v} --hash=sha256:{h}\n" for n, v, h in pins).encode("utf-8")


# ---- commands


def _tool_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    # nothing from the caller's Python or pip settings may change what the build installs,
    # fetches or builds
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("PYTHON", "PIP_"))}
    env["PIP_CONFIG_FILE"] = os.devnull
    env.update(extra or {})
    return env


def _tail(text: str | None) -> str:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return " / ".join(lines[-2:]) or "no output"


def _run(run: Run, cmd: list, what: str, *, cwd: Path | None = None, extra=None) -> None:
    cmd = [str(c) for c in cmd]
    try:
        done = run(
            cmd, cwd=cwd, env=_tool_env(extra), capture_output=True, text=True,
            timeout=COMMAND_TIMEOUT,
        )  # fmt: skip
    except subprocess.TimeoutExpired as exc:
        raise BuildError(f"cannot {what}: it took longer than {COMMAND_TIMEOUT} seconds") from exc
    except OSError as exc:
        raise BuildError(f"cannot {what}: {exc}") from exc
    if done.returncode != 0:
        raise BuildError(f"cannot {what}: {_tail(done.stderr or done.stdout)}")


def _pip(python: Path, sub: str, *args) -> list:
    return [python, "-I", "-m", "pip", "--isolated", sub, "--disable-pip-version-check",
            "--no-input", *args]  # fmt: skip


# ---- the build


def _on_x86_64_linux() -> bool:
    return sys.platform == "linux" and platform.machine() == "x86_64"


def build_release(
    repo: Path,
    out: Path,
    cache: Path,
    *,
    fetch: Fetch = fetch,
    run: Run = subprocess.run,
    platform_ok: Callable[[], bool] = _on_x86_64_linux,
) -> Path:
    """Builds the release file into out from the checkout at repo and returns its path.

    Nothing is written to out unless the release passes its checks.
    """
    if not platform_ok():
        raise BuildError("a release is built on x86_64 Linux: the build runs the Python it packs")
    release = repo / "release"
    python_pin = load_pins(release / "pins.toml")
    asciinema_pin = _asciinema_pin()
    version = project_version(repo / "pyproject.toml")
    requirements = release / "requirements.lock"
    build_requirements = release / "build-requirements.lock"
    locked = read_lock(requirements)
    read_lock(build_requirements)
    top = f"{APP}-{version}"
    name = f"{top}-linux-x86_64.tar.gz"

    python_archive = cache / _cache_name(python_pin.url)
    fetch(python_pin.url, python_archive, python_pin.size, python_pin.sha256)
    _ok(f"Python {python_pin.version}: {python_pin.size} bytes, SHA-256 as pinned")
    asciinema = cache / _cache_name(asciinema_pin.url)
    fetch(asciinema_pin.url, asciinema, asciinema_pin.size, asciinema_pin.sha256)
    _ok(f"asciinema {asciinema_pin.version}: {asciinema_pin.size} bytes, SHA-256 as pinned")

    with tempfile.TemporaryDirectory(prefix="pwn-broker-release-") as tmp:
        work = Path(tmp)
        try:
            runtimearchive.unpack(python_archive, work / "python")
        except toolpkg.ToolError as exc:
            raise BuildError(str(exc)) from exc
        python = work / "python" / "python" / "bin" / "python3"
        if not python.is_file():
            raise BuildError("the Python build has no python/bin/python3")
        env = work / "env"
        env_python = env / "bin" / "python"
        _run(run, [python, "-I", "-m", "venv", env], "make the build environment")
        _run(
            run,
            _pip(env_python, "install", "--no-cache-dir", "--only-binary", ":all:",
                 "--require-hashes", "-r", build_requirements),
            "install the build tools",
        )  # fmt: skip
        _ok(f"installed the build tools from {build_requirements.name}")
        built = work / "built"
        built.mkdir()
        _run(
            run,
            [env_python, "-I", "-m", "hatchling", "build", "-t", "wheel", "-d", built],
            "build the app's wheel",
            cwd=repo,
            extra={"SOURCE_DATE_EPOCH": str(EPOCH)},
        )
        app_wheel = _app_wheel(built, version)
        _ok(f"built {app_wheel.name}")
        downloaded = work / "downloaded"
        downloaded.mkdir()
        _run(
            run,
            _pip(env_python, "download", "--no-deps", "--only-binary", ":all:", "--require-hashes",
                 "--no-cache-dir", "-r", requirements, "-d", downloaded),
            "download the locked wheels",
        )  # fmt: skip
        _ok(f"downloaded the wheels {requirements.name} pins")

        root = work / "tree" / top
        wheels = root / "wheels"
        wheels.mkdir(parents=True)
        shutil.copyfile(python_archive, root / "python.tar.gz")
        shutil.copyfile(asciinema, root / "asciinema")
        os.chmod(root / "asciinema", 0o755)
        licences = root / "licences"
        licences.mkdir()
        shutil.copyfile(repo / "LICENSE", licences / f"{APP}.txt")
        for path in [app_wheel, *sorted(downloaded.iterdir())]:
            if not path.is_file() or path.is_symlink():
                raise BuildError(f"wheels/{path.name} is not a wheel")
            shutil.copyfile(path, wheels / path.name)
        (root / "wheels.lock").write_bytes(_wheels_lock(locked, version, sha256_file(app_wheel)))
        check_tree(root, version)
        _ok("checked the release: every wheel is named by wheels.lock with its SHA-256")

        out.mkdir(parents=True, exist_ok=True)
        final = out / name
        part = out / f".{name}.part"
        sums_part = out / f".{SUMS}.part"
        try:
            write_archive(root, part, top)
            sums_part.write_bytes(f"{sha256_file(part)}  {name}\n".encode("utf-8"))
            os.replace(part, final)
            try:
                os.replace(sums_part, out / SUMS)
            except BaseException:
                _unlink(final)
                raise
        finally:
            _unlink(part)
            _unlink(sums_part)
    return final


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="build.py", description="Builds the release file from the pinned inputs."
    )
    parser.add_argument("--out", type=Path, default=REPO / "dist")
    parser.add_argument("--cache", type=Path, default=REPO / ".cache" / "release")
    args = parser.parse_args(argv)
    try:
        path = build_release(REPO, args.out, args.cache)
        size = path.stat().st_size
        digest = sha256_file(path)
    except (BuildError, OSError) as exc:
        print(f"fail  {exc}", file=sys.stderr)
        return 1
    print(f"ok    wrote {path} ({size} bytes, SHA-256 {digest})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
