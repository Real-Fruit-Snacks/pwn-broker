import subprocess

from pwn_broker.ping import Result, once

REPLY = (
    "PING 10.10.10.161 (10.10.10.161) 56(84) bytes of data.\n"
    "64 bytes from 10.10.10.161: icmp_seq=1 ttl=127 time=43.2 ms\n"
)


def _found(name):
    return f"/usr/bin/{name}"


def _runner(calls, status=0, stdout="", error=None):
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if error is not None:
            raise error
        return subprocess.CompletedProcess(argv, status, stdout=stdout, stderr="")

    return run


def test_an_answer_with_a_time():
    calls = []
    result = once("10.10.10.161", run=_runner(calls, stdout=REPLY), which=_found)
    assert result == Result(answered=True, ms=43.2, checked=True)
    [(argv, kwargs)] = calls
    assert argv == ["ping", "-c", "1", "-W", "2", "10.10.10.161"]
    assert kwargs["capture_output"] is True and kwargs["timeout"] == 5


def test_an_answer_without_a_time():
    result = once("10.10.10.161", run=_runner([], stdout="1 received\n"), which=_found)
    assert result == Result(True, None, True)


def test_no_answer():
    result = once("10.10.10.161", run=_runner([], status=1, stdout="0 received\n"), which=_found)
    assert result == Result(False, None, True)


def test_a_timeout_is_no_answer():
    error = subprocess.TimeoutExpired(["ping"], 5)
    assert once("10.10.10.161", run=_runner([], error=error), which=_found) == Result(False, None, True)


def test_an_os_error_is_no_answer():
    error = OSError("exec format error")
    assert once("10.10.10.161", run=_runner([], error=error), which=_found) == Result(False, None, True)


def test_no_ping_on_the_machine_runs_nothing():
    calls = []
    result = once("10.10.10.161", run=_runner(calls), which=lambda name: None)
    assert result == Result(False, None, False)
    assert calls == []
