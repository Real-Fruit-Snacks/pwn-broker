import pytest

from pwn_broker import boxlock
from pwn_broker.boxlock import Busy, held


class FakeTime:
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def test_second_holder_gets_busy_after_waiting(paths):
    fake = FakeTime()
    with held(paths, wait=0):
        with pytest.raises(Busy):
            with held(paths, wait=0.5, sleep=fake.sleep, clock=fake.clock):
                pass
    assert fake.slept
    assert set(fake.slept) == {0.1}
    assert 0.5 <= fake.now <= 0.7


def test_lock_is_created_when_missing(paths):
    assert not paths.box_lock.exists()
    with held(paths, wait=0):
        assert paths.box_lock.exists()


def test_free_again_after_exit(paths):
    with held(paths, wait=0):
        pass
    with held(paths, wait=0):
        pass


def test_free_again_after_an_exception(paths):
    with pytest.raises(RuntimeError):
        with held(paths, wait=0):
            raise RuntimeError("boom")
    with held(paths, wait=0):
        pass


def test_waiter_gets_the_lock_once_it_is_released(paths, monkeypatch):
    tries = iter([False, False, True])
    monkeypatch.setattr(boxlock, "_try_lock", lambda handle: next(tries))
    monkeypatch.setattr(boxlock, "_unlock", lambda handle: None)
    fake = FakeTime()
    with held(paths, wait=5, sleep=fake.sleep, clock=fake.clock):
        pass
    assert fake.slept == [0.1, 0.1]


def test_zero_wait_tries_once_and_does_not_sleep(paths, monkeypatch):
    calls = []
    monkeypatch.setattr(boxlock, "_try_lock", lambda handle: calls.append(1) or False)
    fake = FakeTime()
    with pytest.raises(Busy):
        with held(paths, wait=0, sleep=fake.sleep, clock=fake.clock):
            pass
    assert calls == [1]
    assert fake.slept == []


def test_handle_is_closed_when_busy(paths, monkeypatch):
    monkeypatch.setattr(boxlock, "_try_lock", lambda handle: False)
    with pytest.raises(Busy):
        with held(paths, wait=0):
            pass
    paths.box_lock.unlink()


# the two platform branches, through stub modules (the one for the other platform cannot run here)

class _Handle:
    def seek(self, pos):
        pass

    def fileno(self):
        return 7


def _fcntl_stub(error=None):
    from types import SimpleNamespace

    calls = []

    def flock(fd, how):
        calls.append((fd, how))
        if error is not None and how & 4:
            raise error

    return SimpleNamespace(LOCK_EX=2, LOCK_NB=4, LOCK_UN=8, flock=flock), calls


def test_fcntl_branch_asks_for_an_exclusive_nonblocking_lock_and_releases_it(monkeypatch):
    stub, calls = _fcntl_stub()
    monkeypatch.setattr(boxlock, "fcntl", stub)
    assert boxlock._try_lock(_Handle()) is True
    boxlock._unlock(_Handle())
    assert calls == [(7, 2 | 4), (7, 8)]


def test_fcntl_branch_maps_contention_to_not_taken(monkeypatch):
    stub, _ = _fcntl_stub(BlockingIOError())
    monkeypatch.setattr(boxlock, "fcntl", stub)
    assert boxlock._try_lock(_Handle()) is False


@pytest.mark.parametrize("error", [OSError(37, "no locks"), OSError(9, "bad fd"), InterruptedError()])
def test_fcntl_branch_lets_other_errors_through(monkeypatch, error):
    stub, _ = _fcntl_stub(error)
    monkeypatch.setattr(boxlock, "fcntl", stub)
    with pytest.raises(OSError):
        boxlock._try_lock(_Handle())


def _msvcrt_stub(error):
    from types import SimpleNamespace

    def locking(fd, mode, size):
        raise error

    return SimpleNamespace(LK_NBLCK=2, LK_UNLCK=0, locking=locking)


@pytest.mark.parametrize(
    "error", [PermissionError(13, "denied"), OSError(13, "denied"), OSError(36, "deadlock")]
)
def test_msvcrt_branch_maps_contention_to_not_taken(monkeypatch, error):
    monkeypatch.setattr(boxlock, "fcntl", None)
    monkeypatch.setattr(boxlock, "msvcrt", _msvcrt_stub(error), raising=False)
    assert boxlock._try_lock(_Handle()) is False


def test_msvcrt_branch_lets_other_errors_through(monkeypatch):
    monkeypatch.setattr(boxlock, "fcntl", None)
    monkeypatch.setattr(boxlock, "msvcrt", _msvcrt_stub(OSError(9, "bad fd")), raising=False)
    with pytest.raises(OSError):
        boxlock._try_lock(_Handle())


def test_a_lock_error_that_is_not_contention_is_not_waited_out(paths, monkeypatch):
    def broken(handle):
        raise OSError(37, "no locks available")

    monkeypatch.setattr(boxlock, "_try_lock", broken)
    fake = FakeTime()
    with pytest.raises(OSError):
        with held(paths, wait=30, sleep=fake.sleep, clock=fake.clock):
            pass
    assert fake.slept == []
