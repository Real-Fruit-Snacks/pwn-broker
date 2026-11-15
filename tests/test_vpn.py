import json
import subprocess
from types import SimpleNamespace

import pytest

from pwn_broker.session import current_tunnel
from pwn_broker.vpn import Tunnel, tunnel


def _iface(name, address=None, family="inet"):
    info = [] if address is None else [{"family": family, "local": address, "prefixlen": 23}]
    return {"ifindex": 3, "ifname": name, "addr_info": info}


def _ip(*interfaces, code=0):
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=code, stdout=json.dumps(list(interfaces)))

    run.calls = calls
    return run


def test_reads_the_only_tunnel():
    run = _ip(_iface("lo", "127.0.0.1"), _iface("eth0", "192.168.1.5"), _iface("tun0", "10.10.14.7"))
    assert tunnel(run) == Tunnel("tun0", "10.10.14.7")


def test_asks_ip_for_json_with_output_captured_and_a_one_second_limit():
    run = _ip(_iface("tun0", "10.10.14.7"))
    tunnel(run)
    [(argv, kwargs)] = run.calls
    assert argv == ["ip", "-j", "-4", "addr", "show"]
    assert kwargs["capture_output"] is True and kwargs["timeout"] == 1


def test_the_lowest_numbered_tunnel_wins():
    run = _ip(_iface("tun10", "10.10.9.1"), _iface("tun2", "10.10.14.9"))
    assert tunnel(run) == Tunnel("tun2", "10.10.14.9")


def test_a_tunnel_without_an_address_is_skipped():
    run = _ip(_iface("tun0"), _iface("tun1", "10.10.14.9"))
    assert tunnel(run) == Tunnel("tun1", "10.10.14.9")


def test_a_tunnel_with_only_an_address_of_another_family_is_skipped():
    assert tunnel(_ip(_iface("tun0", "fe80::1", family="inet6"))) is None


def test_no_tun_interface():
    assert tunnel(_ip(_iface("lo", "127.0.0.1"), _iface("eth0", "192.168.1.5"))) is None


def test_names_that_only_contain_tun_are_ignored():
    run = _ip(_iface("tunnel0", "10.0.0.1"), _iface("mytun0", "10.0.0.2"), _iface("tun", "10.0.0.3"))
    assert tunnel(run) is None


def test_an_address_that_does_not_parse_counts_as_none():
    assert tunnel(_ip(_iface("tun0", "not-an-address"))) is None


def test_a_timeout_is_no_tunnel():
    def run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 1)

    assert tunnel(run) is None


def test_no_ip_on_the_machine_is_no_tunnel():
    def run(argv, **kwargs):
        raise FileNotFoundError("ip")

    assert tunnel(run) is None


def test_invalid_json_is_no_tunnel():
    assert tunnel(lambda argv, **kw: SimpleNamespace(returncode=0, stdout="{nope")) is None


@pytest.mark.parametrize("text", ['{"ifname": "tun0"}', '[1, 2]', '[{"ifname": 3}]', '[{"addr_info": []}]', "null"])
def test_the_wrong_shape_is_no_tunnel(text):
    assert tunnel(lambda argv, **kw: SimpleNamespace(returncode=0, stdout=text)) is None


def test_a_failing_ip_is_no_tunnel():
    assert tunnel(_ip(_iface("tun0", "10.10.14.7"), code=1)) is None


# the cache

def _counting(session, answers):
    reads = []

    def read():
        reads.append(1)
        return answers[len(reads) - 1]

    session.tunnel = read
    return reads


def test_two_reads_inside_ten_seconds_run_ip_once(session):
    found = Tunnel("tun0", "10.10.14.7")
    reads = _counting(session, [found, None])
    assert current_tunnel(session) == found
    assert current_tunnel(session) == found
    assert len(reads) == 1


def test_a_fresh_read_asks_again(session):
    found = Tunnel("tun0", "10.10.14.7")
    reads = _counting(session, [found, None])
    current_tunnel(session)
    assert current_tunnel(session, fresh=True) is None
    assert len(reads) == 2


def test_a_no_answer_is_cached_too(session):
    reads = _counting(session, [None, Tunnel("tun0", "10.10.14.7")])
    assert current_tunnel(session) is None
    assert current_tunnel(session) is None
    assert len(reads) == 1


def test_an_old_answer_is_read_again(session):
    from datetime import timedelta

    now = [session.clock()]
    session.clock = lambda: now[0]
    reads = _counting(session, [None, Tunnel("tun0", "10.10.14.7")])
    current_tunnel(session)
    now[0] += timedelta(seconds=9)
    assert current_tunnel(session) is None
    now[0] += timedelta(seconds=1)
    assert current_tunnel(session) == Tunnel("tun0", "10.10.14.7")
    assert len(reads) == 2


def test_a_clock_that_goes_backwards_counts_as_stale(session):
    from datetime import timedelta

    now = [session.clock()]
    session.clock = lambda: now[0]
    reads = _counting(session, [None, None])
    current_tunnel(session)
    now[0] -= timedelta(seconds=1)
    current_tunnel(session)
    assert len(reads) == 2
