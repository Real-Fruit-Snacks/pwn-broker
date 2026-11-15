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
