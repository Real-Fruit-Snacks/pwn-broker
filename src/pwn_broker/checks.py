import json
import os
import shutil
import subprocess
import threading
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from pwn_broker import __version__, setup, vpn
from pwn_broker.config import Settings
from pwn_broker.console import Cancelled, Console
from pwn_broker.notewindow import has_display
from pwn_broker.paths import AppPaths

RELEASES_URL = "https://api.github.com/repos/Real-Fruit-Snacks/pwn-broker/releases/latest"


@dataclass
class CheckResult:
    name: str
    status: str
    message: str
    hint: str = ""
    repair: Callable[[], None] | None = None


def _tool(name: str, binary: str, which: Callable[[str], str | None], hint: str) -> CheckResult:
    found = which(binary)
    if found:
        return CheckResult(name, "ok", found)
    return CheckResult(name, "fail", f"{binary} not found", hint)


def _venv(run: Callable) -> CheckResult:
    # venv --help answers even without python3-venv; ensurepip is what that package adds.
    # Only Python tools need it, so a missing one is a warning, not a reason to stop
    try:
        done = run(["python3", "-c", "import ensurepip"], capture_output=True, timeout=20)
        working = done.returncode == 0
    except (OSError, subprocess.SubprocessError):
        working = False
    if working:
        return CheckResult("venv", "ok", "python3 can make virtual environments")
    return CheckResult(
        "venv", "warn", "python3 cannot make virtual environments", "apt install python3-venv"
    )


def run_checks(
    paths: AppPaths,
    settings: Settings,
    env: Mapping[str, str],
    which: Callable[[str], str | None] = shutil.which,
    repair_path: Callable[[], None] | None = None,
    run: Callable = subprocess.run,
    *,
    tunnel: Callable[[], vpn.Tunnel | None],
) -> list[CheckResult]:
    results = [
        _tool("vim", "vim", which, "apt install vim"),
        _tool(
            "terminal",
            settings.terminal,
            which,
            f"install {settings.terminal} or set terminal in {paths.config_file}",
        ),
        _tool("tar", "tar", which, "apt install tar"),
        _venv(run),
    ]

    if has_display(env):
        results.append(CheckResult("display", "ok", "desktop session found"))
    else:
        results.append(
            CheckResult(
                "display",
                "warn",
                "no desktop session",
                f"run vim by hand: vim -u {paths.vim_dir / 'vimrc'} notes.md",
            )
        )

    if str(paths.bin) in env.get("PATH", "").split(os.pathsep):
        results.append(CheckResult("path", "ok", f"{paths.bin} is on PATH"))
    else:
        results.append(
            CheckResult(
                "path",
                "warn",
                f"{paths.bin} is not on PATH",
                "open a new terminal, or add it to PATH",
                repair_path,
            )
        )

    def make_folders() -> None:
        paths.active.mkdir(parents=True, exist_ok=True)
        paths.wrapped.mkdir(parents=True, exist_ok=True)

    if paths.active.exists() and paths.wrapped.exists():
        results.append(CheckResult("folders", "ok", "box folders exist"))
    else:
        results.append(
            CheckResult("folders", "warn", "box folders are missing", repair=make_folders)
        )

    found = tunnel()
    if found is not None:
        results.append(CheckResult("vpn", "ok", f"{found.address} on {found.name}"))
    else:
        results.append(
            CheckResult("vpn", "warn", "no VPN tunnel is up", "start one with: vpn start")
        )
    return results


def report(console: Console, results: list[CheckResult]) -> None:
    passed = sum(1 for r in results if r.status == "ok")
    if passed:
        console.ok("1 check passed" if passed == 1 else f"{passed} checks passed")
    for result in results:
        if result.status == "ok":
            continue
        line = f"{result.name}   {result.message}"
        if result.status == "fail":
            console.fail(line)
        else:
            console.warn(line)
        if result.hint:
            console.info(result.hint)
        if result.repair is not None:
            _offer_repair(console, result.name, result.repair)


def _offer_repair(console: Console, name: str, repair: Callable[[], None]) -> None:
    try:
        agreed = console.confirm("fix it now?", default=True)
    except Cancelled:
        return
    if not agreed:
        return
    try:
        repair()
    except (OSError, ValueError) as exc:
        console.fail(str(exc))
    else:
        console.ok(f"{name} fixed")


def _parts(version: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(piece) for piece in version.split("."))
    except ValueError:
        return None


def newer(current: str, latest: str) -> bool:
    a, b = _parts(current), _parts(latest)
    if a is None or b is None:
        return False
    # "0.2" and "0.2.0" are the same release.
    width = max(len(a), len(b))
    return b + (0,) * (width - len(b)) > a + (0,) * (width - len(a))


def _fetch(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "pwn-broker"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def latest_version(
    fetch: Callable[[str, float], bytes] = _fetch, timeout: float = 2.0
) -> str | None:
    try:
        data = json.loads(fetch(RELEASES_URL, timeout))
        tag = data["tag_name"]
    except Exception:
        return None
    if not isinstance(tag, str):
        return None
    return tag.removeprefix("v")


def version_check(
    settings: Settings,
    current: str = __version__,
    fetch: Callable[[str, float], bytes] = _fetch,
) -> CheckResult | None:
    if not settings.check_updates:
        return None
    latest = latest_version(fetch)
    if latest is None or not newer(current, latest):
        return None
    return CheckResult("version", "warn", f"{latest} is available, this is {current}")


def newer_release_within(settings: Settings, timeout: float = 2.0) -> CheckResult | None:
    # a slow or hanging network must never hold up the prompt
    found: list[CheckResult | None] = []

    def look() -> None:
        try:
            found.append(version_check(settings))
        except Exception:
            pass

    thread = threading.Thread(target=look, daemon=True)
    thread.start()
    thread.join(timeout)
    return found[0] if found else None


def launch_checks(
    paths: AppPaths,
    settings: Settings,
    env: Mapping[str, str],
    home: Path,
    include_version: bool = True,
    *,
    tunnel: Callable[[], vpn.Tunnel | None],
) -> list[CheckResult]:
    def add_path_lines() -> None:
        # the same rc files the installer writes to
        setup.ensure_path_line(home / ".zshrc", paths.bin)
        if (home / ".bashrc").exists():
            setup.ensure_path_line(home / ".bashrc", paths.bin)

    results = run_checks(paths, settings, env, repair_path=add_path_lines, tunnel=tunnel)
    if include_version:
        version = version_check(settings)
        if version is not None:
            results.append(version)
    return results
