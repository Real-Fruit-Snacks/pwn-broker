import json
import os
import signal
import sys
import time
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from helpers import NOW
from pwn_broker import config, scanning
from pwn_broker.console import FakeConsole
from pwn_broker.scanning import Marker, ScanError
from pwn_broker.shell import cmd_scan
from pwn_broker.shell.commands import dispatch
from pwn_broker.store import write_toml

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="a forked runner and a shell script need Linux")

GNMAP = "# Nmap done\nHost: 10.10.10.161 ()\tStatus: Up\nHost: 10.10.10.161 ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///, 88/filtered/tcp//kerberos///, 53/open/udp//domain///\n"


def lines(session, kind=None):
    return [t for k, t in session.console.lines if kind is None or k == kind]


@pytest.fixture
def nmap(system):
    system.programs["nmap"] = "/usr/bin/nmap"
    return system


def spec_of(system):
    [argv] = system.spawned
    return json.loads(argv[-1])


# ---- the pieces


def test_open_ports_reads_the_grepable_output(tmp_path):
    gnmap = tmp_path / "x.gnmap"
    gnmap.write_text(GNMAP + GNMAP)
    assert scanning.open_ports(gnmap) == ["22/tcp", "80/tcp", "53/udp"]
    assert scanning.open_ports(tmp_path / "missing.gnmap") == []


def test_parse_flags_splits_like_a_shell_and_says_what_it_cannot_read():
    assert scanning.parse_flags("-sC -sV --script 'smb-* and safe'", "quick") == ["-sC", "-sV", "--script", "smb-* and safe"]
    with pytest.raises(ScanError, match="^scan_full cannot be read as nmap options: "):
        scanning.parse_flags("-p '22", "full")


class Nmap:
    """Stands in for nmap in run_plan: writes the -oA files, with the ports a test gives."""

    def __init__(self, ports="22/open/tcp//ssh///, 80/open/tcp//http///", status=0):
        self.calls = []
        self.ports, self.status = ports, status

    def __call__(self, argv):
        self.calls.append(argv)
        base = Path(argv[argv.index("-oA") + 1])
        base.with_suffix(".nmap").write_text("nmap output\n")
        line = f"Host: 10.0.0.1 ()\tPorts: {self.ports}\n" if self.ports else "Host: 10.0.0.1 ()\tStatus: Up\n"
        base.with_suffix(".gnmap").write_text(line)
        return self.status


def plan_spec(tmp_path, plan):
    folder = tmp_path / "scans"
    done = tmp_path / "done"
    folder.mkdir()
    done.mkdir()
    flags = {m: scanning.parse_flags(scanning.DEFAULT_FLAGS[m], m) for m in scanning.MODES}
    return {"nmap": "/usr/bin/nmap", "ip": "10.0.0.1", "plan": plan, "flags": flags, "folder": str(folder),
            "stamp": "2026-11-18_010203", "target": "dc01", "done": str(done)}  # fmt: skip


def records(tmp_path):
    return [scanning.Done(**{k: v for k, v in __import__("tomllib").loads(p.read_text()).items()})
            for p in sorted((tmp_path / "done").glob("*.toml"))]  # fmt: skip


def test_quick_runs_scripts_and_versions_on_the_top_ports(tmp_path):
    spec, fake = plan_spec(tmp_path, ["quick"]), Nmap()
    scanning.run_plan(spec, run=fake)
    base = str(tmp_path / "scans" / "2026-11-18_010203-quick")
    assert fake.calls == [["/usr/bin/nmap", "-sC", "-sV", "-oA", base, "10.0.0.1"]]
    [done] = records(tmp_path)
    assert (done.mode, done.status, done.ports) == ("quick", 0, ["22/tcp", "80/tcp"])
    assert done.file == "targets/dc01/scans/2026-11-18_010203-quick.nmap"


def test_full_finds_every_port_then_looks_closer_at_those_it_found(tmp_path):
    spec, fake = plan_spec(tmp_path, ["full"]), Nmap()
    scanning.run_plan(spec, run=fake)
    first = str(tmp_path / "scans" / "2026-11-18_010203-full-ports")
    second = str(tmp_path / "scans" / "2026-11-18_010203-full")
    assert fake.calls == [
        ["/usr/bin/nmap", "-p-", "--min-rate", "5000", "-oA", first, "10.0.0.1"],
        ["/usr/bin/nmap", "-sC", "-sV", "-p", "22,80", "-oA", second, "10.0.0.1"],
    ]
    [done] = records(tmp_path)
    assert (done.mode, done.ports, done.file) == ("full", ["22/tcp", "80/tcp"], "targets/dc01/scans/2026-11-18_010203-full.nmap")


def test_full_with_no_open_port_stops_after_the_first_stage(tmp_path):
    spec, fake = plan_spec(tmp_path, ["full"]), Nmap(ports="")
    scanning.run_plan(spec, run=fake)
    assert len(fake.calls) == 1
    [done] = records(tmp_path)
    assert (done.ports, done.file) == ([], "targets/dc01/scans/2026-11-18_010203-full-ports.nmap")


def test_a_bare_scan_runs_quick_then_full_and_records_each(tmp_path):
    spec, fake = plan_spec(tmp_path, ["quick", "full"]), Nmap()
    scanning.run_plan(spec, run=fake)
    assert [c[1] for c in fake.calls] == ["-sC", "-p-", "-sC"]
    assert [d.mode for d in records(tmp_path)] == ["quick", "full"]


def test_a_failed_nmap_is_recorded_with_its_status(tmp_path):
    spec, fake = plan_spec(tmp_path, ["udp"]), Nmap(status=1)
    scanning.run_plan(spec, run=fake)
    assert fake.calls[0][1:4] == ["-sU", "--top-ports", "100"]
    assert records(tmp_path)[0].status == 1


# ---- the commands


def test_scan_needs_a_target(session, nmap):
    session.current = None
    dispatch(session, "scan")
    assert lines(session, "fail") == ["no target is selected; target use <target> first"]


def test_scan_refuses_a_mode_it_does_not_have(session, nmap):
    dispatch(session, "scan vuln")
    assert lines(session, "fail") == ["no scan mode vuln; the modes are quick, full and udp"]


def test_scan_without_nmap_says_how_to_install_it(session, system):
    dispatch(session, "scan")
    assert lines(session, "fail") == ["nmap is not installed. install it with: apt install nmap"]
    assert system.spawned == []


def test_scan_needs_an_ip(session, nmap):
    session.current = replace(session.current, ips=[])
    dispatch(session, "scan quick")
    assert lines(session, "fail") == ["dc01 has no IP address to scan"]


def test_a_udp_scan_needs_root(session, nmap):
    session.is_root = lambda: False
    dispatch(session, "scan udp")
    assert lines(session, "fail") == ["a UDP scan needs root"]
    assert nmap.spawned == []


def test_a_bare_scan_starts_quick_then_full_in_the_background(session, nmap):
    dispatch(session, "scan")
    spec = spec_of(nmap)
    assert spec["plan"] == ["quick", "full"] and spec["ip"] == "10.10.10.161" and spec["nmap"] == "/usr/bin/nmap"
    assert spec["flags"] == {"quick": ["-sC", "-sV"], "full": ["-p-", "--min-rate", "5000"], "udp": ["-sU", "--top-ports", "100"]}
    assert Path(spec["folder"]) == session.box.path / "targets" / "dc01" / "scans"
    assert scanning.MODULE in nmap.spawned[0]
    assert lines(session, "ok") == ["scanning dc01 (10.10.10.161): quick then full"]
    assert lines(session, "info") == ["results go to targets/dc01/scans; a line here when each is done"]


def test_the_settings_change_a_mode_s_options(session, nmap):
    session.settings = replace(session.settings, scan_quick="-sV -Pn")
    dispatch(session, "scan quick")
    assert spec_of(nmap)["flags"]["quick"] == ["-sV", "-Pn"]


def test_a_second_scan_of_the_same_target_waits(session, nmap):
    dispatch(session, "scan quick")
    session.console = FakeConsole()
    dispatch(session, "scan full")
    [failed] = lines(session, "fail")
    assert failed.startswith("a scan of dc01 is running (quick, since ") and failed.endswith("); scan stop first")
    assert len(nmap.spawned) == 1


def test_scan_stop_stops_the_runner_and_its_nmap(session, nmap):
    dispatch(session, "scan")
    session.console = FakeConsole()
    dispatch(session, "scan stop")
    assert nmap.killed == [(50001, signal.SIGTERM)]
    assert lines(session, "ok") == ["stopped the scan of dc01"]
    session.console = FakeConsole()
    dispatch(session, "scan stop")
    assert lines(session, "fail") == ["no scan of dc01 is running"]


def test_scan_log_before_any_scan(session):
    dispatch(session, "scan log")
    assert lines(session, "info") == ["no scan of dc01 has run yet"]


def test_scan_log_shows_the_last_lines(session):
    log = scanning.log_path(session.paths, session.box.id, "dc01")
    log.parent.mkdir(parents=True)
    log.write_text("".join(f"line {n}\n" for n in range(25)))
    dispatch(session, "scan log")
    assert lines(session, "log") == [f"line {n}" for n in range(5, 25)]


def done_record(session, mode="quick", status=0, ports=("22/tcp", "80/tcp", "53/udp")):
    folder = session.paths.run / "scans" / session.box.id / "done"
    folder.mkdir(parents=True, exist_ok=True)
    n = len(list(folder.iterdir()))
    write_toml(folder / f"{n:04d}-dc01-{mode}.toml", {
        "target": "dc01", "mode": mode, "status": status, "ports": list(ports),
        "file": f"targets/dc01/scans/2026-11-18_010203-{mode}.nmap", "finished": NOW,
    })  # fmt: skip


def test_a_finished_scan_is_said_once(session):
    done_record(session)
    done_record(session, mode="full", ports=())
    done_record(session, mode="udp", status=1)
    cmd_scan.notices(session)
    assert session.console.lines == [
        ("ok", "scan quick of dc01 done: 22, 80, 53/udp are open   targets/dc01/scans/2026-11-18_010203-quick.nmap"),
        ("ok", "scan full of dc01 done: no ports are open   targets/dc01/scans/2026-11-18_010203-full.nmap"),
        ("warn", "scan udp of dc01 ended with status 1; see: scan log"),
    ]
    session.console = FakeConsole()
    cmd_scan.notices(session)
    assert session.console.lines == []


def test_one_open_port_reads_is(session):
    done_record(session, ports=("445/tcp",))
    cmd_scan.notices(session)
    assert lines(session) == ["scan quick of dc01 done: 445 is open   targets/dc01/scans/2026-11-18_010203-quick.nmap"]


def test_a_finished_scan_is_said_after_the_next_command_s_output(session):
    from pwn_broker.shell import app

    done_record(session)
    app._run_line(session, "clear")
    # after the clear, so it is not wiped
    assert session.console.events[-1] == ("ok", lines(session)[-1])
    assert lines(session)[-1].startswith("scan quick of dc01 done:")
    assert ("clear", "") in session.console.events[: session.console.events.index(("ok", lines(session)[-1]))]


def test_finish_waits_while_a_scan_runs_and_the_bar_shows_it(session, nmap):
    assert cmd_scan.block(session) is None and cmd_scan.toolbar_part(session) is None
    dispatch(session, "scan")
    assert cmd_scan.block(session) == "a scan is still running: dc01 (quick then full). wait for it or scan stop, then finish again"
    assert cmd_scan.toolbar_part(session) == "scan dc01"


def test_the_scan_settings_are_read_from_the_config_file(tmp_path):
    opt = tmp_path / "opt"
    opt.mkdir()
    (opt / "config.toml").write_text('scan_quick = "-sV"\nscan_udp = ""\n')
    _paths, settings = config.load({"PWN_BROKER_OPT": str(opt)}, tmp_path)
    assert (settings.scan_quick, settings.scan_full, settings.scan_udp) == ("-sV", None, None)
    (opt / "config.toml").write_text("scan_full = 5\n")
    with pytest.raises(config.ConfigError, match="scan_full must be a str"):
        config.load({"PWN_BROKER_OPT": str(opt)}, tmp_path)


# ---- the real runner, with a stand-in nmap


FAKE_NMAP = """#!/bin/sh
base=""; prev=""
for a in "$@"; do
  if [ "$prev" = "-oA" ]; then base="$a"; fi
  prev="$a"
done
echo "$*" >> "$(dirname "$base")/calls.txt"
echo "# fake nmap $*" > "$base.nmap"
printf 'Host: 10.10.10.161 ()\\tPorts: 22/open/tcp//ssh///, 445/open/tcp//microsoft-ds///\\n' > "$base.gnmap"
echo '<nmaprun/>' > "$base.xml"
echo "fake nmap ran"
"""


@posix_only
def test_the_real_runner_scans_in_the_background_and_records_each_mode(session, tmp_path):
    nmap = tmp_path / "nmap"
    nmap.write_text(FAKE_NMAP)
    nmap.chmod(0o755)
    flags = {m: scanning.parse_flags(scanning.DEFAULT_FLAGS[m], m) for m in scanning.MODES}
    marker = scanning.start(session.paths, session.box, session.current, ["quick", "full"], nmap=str(nmap),
                            flags=flags, clock=lambda: NOW)  # fmt: skip
    assert os.getsid(marker.pid) == marker.pid
    deadline = time.monotonic() + 15
    found = []
    while time.monotonic() < deadline and len(found) < 2:
        found += scanning.take_done(session.paths, session.box.id)
        time.sleep(0.1)
    assert [(d.mode, d.status, d.ports) for d in found] == [
        ("quick", 0, ["22/tcp", "445/tcp"]), ("full", 0, ["22/tcp", "445/tcp"]),
    ]
    scans = session.box.path / "targets" / "dc01" / "scans"
    calls = (scans / "calls.txt").read_text().splitlines()
    assert calls[0].startswith("-sC -sV -oA ") and calls[1].startswith("-p- --min-rate 5000 -oA ")
    assert calls[2].startswith("-sC -sV -p 22,445 -oA ")
    stamp = f"{NOW:%Y-%m-%d_%H%M%S}"
    assert {p.name for p in scans.iterdir()} >= {
        f"{stamp}-quick.nmap", f"{stamp}-quick.gnmap", f"{stamp}-quick.xml",
        f"{stamp}-full-ports.gnmap", f"{stamp}-full.nmap", f"{stamp}-full.xml",
    }
    # the runner is gone, and its marker is forgotten at the next look
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and scanning.running(session.paths, session.box.id):
        time.sleep(0.1)
    assert scanning.running(session.paths, session.box.id) == []
    log = scanning.log_tail(session.paths, session.box.id, "dc01", 50)
    assert any(line.startswith("$ ") and "-sC -sV" in line for line in log)
    assert "fake nmap ran" in log


@posix_only
def test_the_real_runner_is_stopped_with_its_nmap(session, tmp_path):
    nmap = tmp_path / "nmap"
    nmap.write_text("#!/bin/sh\nsleep 60\n")
    nmap.chmod(0o755)
    flags = {m: scanning.parse_flags(scanning.DEFAULT_FLAGS[m], m) for m in scanning.MODES}
    marker = scanning.start(session.paths, session.box, session.current, ["udp"], nmap=str(nmap), flags=flags,
                            clock=lambda: NOW)  # fmt: skip
    time.sleep(0.5)
    scanning.stop(session.paths, session.box.id, "dc01")
    # nothing of its session is left: not the runner, not the sleeping nmap
    time.sleep(0.3)
    import subprocess

    shown = subprocess.run(["ps", "-o", "pid=", "-s", str(marker.pid)], capture_output=True, text=True, check=False)
    assert shown.stdout.split() == []
