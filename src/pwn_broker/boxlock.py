import errno
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import IO

from pwn_broker.paths import AppPaths

try:
    import fcntl
except ImportError:  # Windows, where the test suite runs
    fcntl = None
    import msvcrt

RETRY = 0.1
# what msvcrt.locking raises when another handle holds the byte
WINDOWS_CONTENDED = (errno.EACCES, errno.EDEADLK)


class Busy(Exception):
    """The box lock is held by another program."""


def _try_lock(handle: IO[bytes]) -> bool:
    handle.seek(0)
    if fcntl is not None:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True
    try:
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError as exc:
        # only contention means busy; anything else is a real fault and must not be waited out
        if isinstance(exc, PermissionError) or exc.errno in WINDOWS_CONTENDED:
            return False
        raise
    return True


def _unlock(handle: IO[bytes]) -> None:
    handle.seek(0)
    if fcntl is not None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    else:
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


@contextmanager
def held(
    paths: AppPaths,
    *,
    wait: float,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Iterator[None]:
    """Hold the exclusive lock on the box, retrying for up to `wait` seconds, else raise Busy.

    Not re-entrant: each holder opens the file for itself, so a second holder in the same
    process waits like one in another process.
    """
    paths.box_lock.parent.mkdir(parents=True, exist_ok=True)
    with open(paths.box_lock, "ab") as handle:
        deadline = clock() + wait
        while not _try_lock(handle):
            if clock() >= deadline:
                raise Busy
            sleep(RETRY)
        try:
            yield
        finally:
            _unlock(handle)
