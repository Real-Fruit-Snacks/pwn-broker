import re
import shutil
import subprocess
from dataclasses import dataclass

TIME = re.compile(r"time=([0-9]+(?:\.[0-9]+)?) ms")


@dataclass
class Result:
    answered: bool
    ms: float | None
    # false when there is no ping on the machine, so nothing was sent
    checked: bool


def once(ip: str, *, run=subprocess.run, which=shutil.which) -> Result:
    if which("ping") is None:
        return Result(False, None, False)
    try:
        done = run(
            ["ping", "-c", "1", "-W", "2", ip],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=5,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return Result(False, None, True)
    if done.returncode != 0:
        return Result(False, None, True)
    found = TIME.search(done.stdout or "")
    return Result(True, float(found[1]) if found else None, True)
