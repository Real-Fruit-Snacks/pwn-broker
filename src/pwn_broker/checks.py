import json
import os
import shutil
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from pwn_broker import __version__, setup
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


def run_checks(
    paths: AppPaths,
    settings: Settings,
    env: Mapping[str, str],
    which: Callable[[str], str | None] = shutil.which,
    repair_path: Callable[[], None] | None = None,
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
    return results


def report(console: Console, results: list[CheckResult]) -> None:
    passed = sum(1 for r in results if r.status == "ok")
    if passed:
        console.ok(f"{passed} checks passed")
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
    except OSError as exc:
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


def launch_checks(
    paths: AppPaths, settings: Settings, env: Mapping[str, str], home: Path
) -> list[CheckResult]:
    results = run_checks(
        paths,
        settings,
        env,
        repair_path=lambda: setup.ensure_path_line(home / ".zshrc", paths.bin),
    )
    version = version_check(settings)
    if version is not None:
        results.append(version)
    return results
