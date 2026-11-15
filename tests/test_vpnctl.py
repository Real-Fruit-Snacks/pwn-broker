import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from helpers import NOW
from pwn_broker import vpnctl
from pwn_broker.model import VpnRecord
from pwn_broker.store import load_box, read_toml, write_toml
from pwn_broker.vpn import Tunnel
from pwn_broker.vpnctl import Marker, VpnError
from pwn_broker.vpnctl import process_comm as real_process_comm  # before the guard replaces it

PID = 4321
START = "123456"
TUN = Tunnel("tun0", "10.10.14.7")
LATER = NOW + timedelta(hours=1)
CONTENT = b"client\nremote 10.10.10.1 1194\n"


def ovpn(folder: Path, name: str = "lab_user.ovpn", content: bytes = CONTENT) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_bytes(content)
    return path


class Machine:
    """Stand-ins for OpenVPN, the process table and the clock's sleep."""

    def __init__(self, paths, *, status=0, pid=PID, start=START, comm="openvpn"):
        self.paths = paths
        self.status = status
        self.pid = pid
        self.start = start
        self.comm = comm
        self.alive_now = False
        self.calls: list[list[str]] = []
        self.sleeps: list[float] = []
        self.log = "line\n" * 3 + "a\nb\nc\nd\ne\n"
        self.tunnel_after: int | None = None  # tunnel reads before the tunnel appears
        self.die_after: int | None = None  # tunnel reads before the process dies
        self.reads = 0
        self.writes_pid = True

    def run(self, argv):
        self.calls.append(list(argv))
        if argv[0] == "openvpn":
            log = Path(argv[argv.index("--log") + 1])
            log.write_text(self.log, encoding="utf-8")
            if self.status == 0 and self.writes_pid:
                Path(argv[argv.index("--writepid") + 1]).write_text(f"{self.pid}\n")
                self.alive_now = True
        if argv[:2] == ["kill", "-TERM"]:
            self.alive_now = False
        return subprocess.CompletedProcess(argv, self.status if argv[0] == "openvpn" else 0)

    def tunnel(self):
        self.reads += 1
        if self.die_after is not None and self.reads > self.die_after:
            self.alive_now = False
        if self.tunnel_after is not None and self.reads > self.tunnel_after:
            return TUN
        return None

    def sleep(self, seconds):
        self.sleeps.append(seconds)

    def alive(self, pid):
        return self.alive_now and pid == self.pid

    def started(self, pid):
        return self.start if self.alive(pid) else None

    def comm_of(self, pid):
        return self.comm if self.alive(pid) else None

    @property
    def checks(self):
        return dict(alive=self.alive, started=self.started, comm=self.comm_of)

    def which(self, name):
        return "/usr/sbin/openvpn" if name == "openvpn" else None


@pytest.fixture
def machine(paths):
    return Machine(paths)


def start(paths, box, source, machine, **overrides):
    options = dict(
        run=machine.run, tunnel=machine.tunnel, clock=lambda: LATER, sleep=machine.sleep,
        which=machine.which, **machine.checks,
    )  # fmt: skip
    options.update(overrides)
    return vpnctl.start(paths, box, source, **options)


def write_marker(paths, pid=PID, start=START, **overrides):
    values = dict(
        pid=pid, start=start, box_id="id-forest", box_name="forest",
        file="lab_user.ovpn", sha256="ab" * 32, started=NOW,
    )  # fmt: skip
    values.update(overrides)
    write_toml(paths.run_vpn / "marker.toml", values)
    return Marker(**values)


# ---- copy_into_box


def test_copy_into_box_copies_a_new_file(box, tmp_path):
    source = ovpn(tmp_path / "dl")
    dest = vpnctl.copy_into_box(box, source)
    assert dest == box.path / "vpn" / "lab_user.ovpn"
    assert dest.read_bytes() == CONTENT


def test_copy_into_box_reuses_the_same_content(box, tmp_path):
    source = ovpn(tmp_path / "dl")
    first = vpnctl.copy_into_box(box, source)
    assert vpnctl.copy_into_box(box, source) == first
    assert sorted(p.name for p in first.parent.iterdir()) == ["lab_user.ovpn"]


def test_copy_into_box_numbers_different_content(box, tmp_path):
    vpnctl.copy_into_box(box, ovpn(tmp_path / "a"))
    second = vpnctl.copy_into_box(box, ovpn(tmp_path / "b", content=b"other\n"))
    third = vpnctl.copy_into_box(box, ovpn(tmp_path / "c", content=b"third\n"))
    assert second.name == "lab_user-2.ovpn" and second.read_bytes() == b"other\n"
    assert third.name == "lab_user-3.ovpn"
    # the same content again finds its numbered copy
    assert vpnctl.copy_into_box(box, ovpn(tmp_path / "d", content=b"other\n")) == second


@pytest.mark.skipif(sys.platform == "win32", reason="file modes are POSIX")
def test_copy_into_box_is_readable_only_by_me(box, tmp_path):
    dest = vpnctl.copy_into_box(box, ovpn(tmp_path / "dl"))
    assert dest.stat().st_mode & 0o777 == 0o600


def test_copy_into_box_refuses_a_file_larger_than_1_mib(box, tmp_path):
    source = ovpn(tmp_path / "dl", content=b"x" * (1024 * 1024 + 1))
    with pytest.raises(VpnError, match="larger than 1 MiB"):
        vpnctl.copy_into_box(box, source)
    assert not (box.path / "vpn").exists()


def test_copy_into_box_takes_exactly_1_mib(box, tmp_path):
    source = ovpn(tmp_path / "dl", content=b"x" * (1024 * 1024))
    assert vpnctl.copy_into_box(box, source).stat().st_size == 1024 * 1024


def test_copy_into_box_refuses_a_folder_and_a_missing_file(box, tmp_path):
    with pytest.raises(VpnError, match="not a regular file"):
        vpnctl.copy_into_box(box, tmp_path)
    with pytest.raises(VpnError, match="no such file"):
        vpnctl.copy_into_box(box, tmp_path / "missing.ovpn")


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_copy_into_box_refuses_a_link_at_vpn(box, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (box.path / "vpn").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(VpnError, match="not a folder"):
        vpnctl.copy_into_box(box, ovpn(tmp_path / "dl"))
    assert list(elsewhere.iterdir()) == []


def test_copy_into_box_refuses_a_file_at_vpn(box, tmp_path):
    (box.path / "vpn").write_text("x")
    with pytest.raises(VpnError, match="not a folder"):
        vpnctl.copy_into_box(box, ovpn(tmp_path / "dl"))


# ---- start


def test_start_runs_openvpn_with_the_exact_arguments(paths, box, tmp_path, machine):
    source = ovpn(tmp_path / "dl")
    machine.tunnel_after = 0
    marker, found = start(paths, box, source, machine)
    run = paths.run_vpn
    assert machine.calls == [[
        "openvpn", "--cd", str(source.parent), "--config", str(run / "config.ovpn"),
        "--daemon", "pwn-broker-vpn", "--writepid", str(run / "openvpn.pid"),
        "--log", str(run / "openvpn.log"),
    ]]  # fmt: skip
    assert found == TUN
    assert (run / "config.ovpn").read_bytes() == CONTENT
    if sys.platform != "win32":
        assert (run / "config.ovpn").stat().st_mode & 0o777 == 0o600


def test_start_writes_the_marker_and_the_box_record(paths, box, tmp_path, machine):
    machine.tunnel_after = 0
    marker, _ = start(paths, box, ovpn(tmp_path / "dl"), machine)
    import hashlib

    sha = hashlib.sha256(CONTENT).hexdigest()
    assert marker == Marker(PID, START, box.id, "forest", "lab_user.ovpn", sha, LATER)
    assert read_toml(paths.run_vpn / "marker.toml") == {
        "pid": PID, "start": START, "box_id": box.id, "box_name": "forest",
        "file": "lab_user.ovpn", "sha256": sha, "started": LATER,
    }  # fmt: skip
    assert load_box(box.path).vpn == [VpnRecord("lab_user.ovpn", sha, LATER)]
    assert box.vpn == [VpnRecord("lab_user.ovpn", sha, LATER)]
    assert vpnctl.ours(paths, **machine.checks) == marker


def test_start_reads_every_half_second_until_the_tunnel_comes(paths, box, tmp_path, machine):
    machine.tunnel_after = 3
    _, found = start(paths, box, ovpn(tmp_path / "dl"), machine)
    assert found == TUN and machine.reads == 4 and machine.sleeps == [0.5, 0.5, 0.5]


def test_start_returns_no_tunnel_after_wait(paths, box, tmp_path, machine):
    marker, found = start(paths, box, ovpn(tmp_path / "dl"), machine, wait=2.0)
    assert found is None and marker.pid == PID
    assert machine.sleeps == [0.5] * 4 and machine.reads == 5


def test_start_removes_an_old_pid_file_first(paths, box, tmp_path, machine):
    paths.run_vpn.mkdir(parents=True)
    old = paths.run_vpn / "openvpn.pid"
    old.write_text("999\n")
    machine.writes_pid = False
    with pytest.raises(VpnError, match="process ID"):
        start(paths, box, ovpn(tmp_path / "dl"), machine)
    assert not old.exists()


def test_start_raises_with_the_log_tail_when_openvpn_fails(paths, box, tmp_path, machine):
    machine.status = 1
    with pytest.raises(VpnError) as caught:
        start(paths, box, ovpn(tmp_path / "dl"), machine)
    assert "exited with status 1" in str(caught.value)
    assert caught.value.log == ["a", "b", "c", "d", "e"]
    assert not (paths.run_vpn / "marker.toml").exists()
    assert box.vpn == []


def test_start_raises_when_no_process_id_is_written(paths, box, tmp_path, machine):
    machine.writes_pid = False
    with pytest.raises(VpnError, match="process ID") as caught:
        start(paths, box, ovpn(tmp_path / "dl"), machine)
    assert caught.value.log == ["a", "b", "c", "d", "e"]
    assert not (paths.run_vpn / "marker.toml").exists()


def test_start_raises_with_the_log_tail_when_the_process_dies_while_waiting(
    paths, box, tmp_path, machine
):
    machine.die_after = 1
    with pytest.raises(VpnError, match="ended before the tunnel came up") as caught:
        start(paths, box, ovpn(tmp_path / "dl"), machine)
    assert caught.value.log == ["a", "b", "c", "d", "e"]


def test_start_without_openvpn_says_how_to_install_it(paths, box, tmp_path, machine):
    with pytest.raises(VpnError, match="apt install openvpn"):
        start(paths, box, ovpn(tmp_path / "dl"), machine, which=lambda name: None)
    assert machine.calls == [] and not (box.path / "vpn").exists()


# ---- ours and stop: a reused process ID is never signalled


def test_ours_is_the_marker_when_everything_matches(paths, machine):
    marker = write_marker(paths)
    machine.alive_now = True
    assert vpnctl.ours(paths, **machine.checks) == marker


def test_a_dead_marker_is_cleared(paths, machine):
    write_marker(paths)
    assert vpnctl.ours(paths, **machine.checks) is None
    assert not (paths.run_vpn / "marker.toml").exists()


def test_no_marker_is_none(paths, machine):
    assert vpnctl.ours(paths, **machine.checks) is None


def test_a_marker_that_cannot_be_parsed_is_none_and_left_alone(paths, machine):
    paths.run_vpn.mkdir(parents=True)
    marker = paths.run_vpn / "marker.toml"
    for text in ("not toml [", 'pid = "4321"\n'):
        marker.write_text(text)
        machine.alive_now = True
        assert vpnctl.ours(paths, **machine.checks) is None
        assert marker.read_text() == text


def _stop_refused(paths, machine):
    calls = []
    with pytest.raises(VpnError, match="no VPN started by pwn-broker is running"):
        vpnctl.stop(paths, run=calls.append, sleep=machine.sleep, **machine.checks)
    assert calls == []


def test_a_reused_pid_with_another_start_time_is_not_ours_and_never_signalled(paths, machine):
    write_marker(paths)
    machine.alive_now = True
    machine.start = "999999"
    assert vpnctl.ours(paths, **machine.checks) is None
    _stop_refused(paths, machine)
    # the process is alive, so the marker stays
    assert (paths.run_vpn / "marker.toml").exists()


def test_a_reused_pid_that_is_not_openvpn_is_not_ours_and_never_signalled(paths, machine):
    write_marker(paths)
    machine.alive_now = True
    machine.comm = "bash"
    assert vpnctl.ours(paths, **machine.checks) is None
    _stop_refused(paths, machine)


def test_a_start_time_that_cannot_be_read_is_not_ours(paths, machine):
    write_marker(paths)
    machine.alive_now = True
    checks = dict(machine.checks, started=lambda pid: None)
    assert vpnctl.ours(paths, **checks) is None
    calls = []
    with pytest.raises(VpnError):
        vpnctl.stop(paths, run=calls.append, sleep=machine.sleep, **checks)
    assert calls == []


def test_a_dead_process_is_never_signalled(paths, machine):
    write_marker(paths)
    _stop_refused(paths, machine)


def test_stop_signals_the_recorded_pid_and_returns_true_when_it_goes(paths, machine):
    write_marker(paths)
    machine.alive_now = True
    assert vpnctl.stop(paths, run=machine.run, sleep=machine.sleep, **machine.checks) is True
    assert machine.calls == [["kill", "-TERM", str(PID)]]
    assert not (paths.run_vpn / "marker.toml").exists()


def test_stop_returns_false_when_the_process_stays(paths, machine):
    write_marker(paths)
    machine.alive_now = True
    ran = []

    def run(argv):
        ran.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    assert vpnctl.stop(paths, run=run, sleep=machine.sleep, wait=2.0, **machine.checks) is False
    assert ran == [["kill", "-TERM", str(PID)]]
    assert machine.sleeps == [0.5] * 4


# ---- log_tail and use


def test_log_tail(paths):
    assert vpnctl.log_tail(paths) == []
    paths.run_vpn.mkdir(parents=True)
    log = paths.run_vpn / "openvpn.log"
    log.write_bytes(b"".join(b"line %d\r\n" % n for n in range(30)) + b"bad \xff\n")
    tail = vpnctl.log_tail(paths)
    assert len(tail) == 20 and tail[0] == "line 11" and tail[-1] == "bad �"
    assert vpnctl.log_tail(paths, 2) == ["line 29", "bad �"]


def test_log_tail_of_a_folder_is_empty(paths):
    (paths.run_vpn / "openvpn.log").mkdir(parents=True)
    assert vpnctl.log_tail(paths) == []


def test_use_records_once(paths, box):
    marker = write_marker(paths, box_id="id-other", box_name="cascade")
    vpnctl.use(paths, box, marker, LATER)
    vpnctl.use(paths, box, marker, LATER + timedelta(minutes=5))
    record = VpnRecord(marker.file, marker.sha256, LATER)
    assert box.vpn == [record] and load_box(box.path).vpn == [record]


def test_use_records_again_after_another_file(paths, box):
    marker = write_marker(paths)
    box.vpn = [VpnRecord("other.ovpn", "cd" * 32, NOW)]
    vpnctl.use(paths, box, marker, LATER)
    assert [r.file for r in load_box(box.path).vpn] == ["other.ovpn", "lab_user.ovpn"]


# ---- the real process checks


@pytest.mark.skipif(sys.platform != "linux", reason="reads /proc")
def test_process_comm_reads_proc():
    expected = Path(f"/proc/{os.getpid()}/comm").read_text().strip()
    assert expected and real_process_comm(os.getpid()) == expected


def test_process_comm_is_none_for_no_process():
    assert real_process_comm(2**30) is None


def test_tests_cannot_reach_the_real_process_checks_or_openvpn(paths, box, tmp_path):
    write_marker(paths)
    with pytest.raises(AssertionError, match="real"):
        vpnctl.ours(paths)
    with pytest.raises(AssertionError, match="real"):
        vpnctl.start(paths, box, ovpn(tmp_path / "dl"), tunnel=lambda: None, clock=lambda: NOW)
