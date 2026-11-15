import sys
from datetime import date
from pathlib import Path

import pytest

from conftest import NOW
from pwn_broker import (
    __version__, boxes, checks, cli, lifecycle, note, notewindow, privilege, session, setup,
)  # fmt: skip
from pwn_broker.boxes import BoxError, create_box
from pwn_broker.checks import CheckResult
from pwn_broker.cli import box_for_cwd, choose, main, new_box, start
from pwn_broker.config import Settings, load_state
from pwn_broker.console import Cancelled, FakeConsole
from pwn_broker.questions import BoxAnswers, ask_box
from pwn_broker.store import StoreError, load_box, save_box


@pytest.fixture
def quiet(monkeypatch):
    """Patches the launch's outside world; the list collects open_note calls."""
    calls = []
    monkeypatch.setattr(
        checks,
        "launch_checks",
        lambda *a, **k: [CheckResult("vim", "ok", "x"), CheckResult("tar", "ok", "y")],
    )
    monkeypatch.setattr(checks, "version_check", lambda settings: None)
    monkeypatch.setattr(notewindow, "open_note", lambda *a: calls.append(a) or True)
    monkeypatch.setattr(privilege, "wrong_owner", lambda path: None)
    return calls


def lines(env, kind):
    return [t for k, t in env.console.lines if k == kind]


def test_ask_box_defaults():
    a = ask_box(
        FakeConsole(["forest", "", "", "windows", "easy"]),
        default_platform="htb",
        today=date(2026, 11, 14),
    )
    assert a == BoxAnswers("forest", "htb", date(2026, 11, 14), "windows", "easy")


def test_ask_box_reasks_empty_name_and_bad_date():
    console = FakeConsole(["", "!!!", "forest", "", "14/11", "2026-11-15", "", ""])
    a = ask_box(console, default_platform="htb", today=date(2026, 11, 14))
    assert a.name == "forest" and a.day == date(2026, 11, 15)
    assert [k for k, _ in console.lines] == ["fail", "fail", "fail"]
    assert "YYYY-MM-DD" in console.lines[2][1]
    assert console.asked == ["box name"] * 3 + ["platform", "date", "date", "os", "difficulty"]


def test_ask_box_platform_stored_as_typed():
    a = ask_box(
        FakeConsole(["Forest ", "Other Lab", "", "", ""]),
        default_platform=" HTB",
        today=date(2026, 11, 14),
    )
    assert a.name == "Forest " and a.platform == "Other Lab"
    b = ask_box(
        FakeConsole(["x", "", "", "", ""]), default_platform=" HTB", today=date(2026, 11, 14)
    )
    assert b.platform == " HTB"


def test_new_box_with_two_targets(env):
    env.console = FakeConsole(
        ["forest", "", "", "windows", "easy",
         "", "10.10.10.161", "forest.htb.local", "", "dc01",
         "y", "10.10.10.162", "", "internal", "",
         ""]
    )  # fmt: skip
    s = new_box(env)
    assert [t.name for t in s.targets] == ["dc01", "10.10.10.162"]
    assert s.targets[1].scope == "internal"
    note = (s.box.path / "notes.md").read_text()
    assert note.startswith("#" * 64) and "#\n#  Box:         forest " in note
    assert "\nTarget: dc01   10.10.10.161   forest.htb.local   external\n" in note
    assert "\nTarget: 10.10.10.162   10.10.10.162   -   internal\n" in note
    assert (s.box.path / "lists/ips.txt").read_text() == "10.10.10.161\n10.10.10.162\n"
    assert load_state(env.paths.state_file).last_platform == "htb"
    assert s.current.name == "dc01"
    assert env.console.lines[-1] == ("ok", "box forest created")
    assert ("ok", "target dc01 created") in env.console.lines


def test_new_box_offers_the_hosts_line_and_pings_each_target(env, system):
    env.console = FakeConsole(
        ["forest", "", "", "windows", "easy",
         "", "10.10.10.161", "forest.htb.local", "", "dc01",
         "y", "10.10.10.162", "", "internal", "",
         "", ""]
    )  # fmt: skip
    s = new_box(env)
    assert env.console.asked[-2:] == ["add another?", "add dc01's hostnames to /etc/hosts?"]
    assert system.pings == ["10.10.10.161", "10.10.10.162"]
    assert s.box.hosts == ["dc01"] and load_box(s.box.path).hosts == ["dc01"]
    assert f"forest.htb.local  # pwn-broker {s.box.id}" in system.hosts_path.read_text()
    tail = [line for line in env.console.lines if line[0] != "info"][-5:]
    assert tail == [
        ("ok", "target 10.10.10.162 created"),
        ("ok", "/etc/hosts updated"),
        ("ok", "10.10.10.161 answered in 1 ms"),
        ("ok", "10.10.10.162 answered in 1 ms"),
        ("ok", "box forest created"),
    ]


def test_new_box_with_no_targets(env):
    env.console = FakeConsole(["forest", "", "", "", "", "n"])
    s = new_box(env)
    assert s.targets == [] and s.current is None and s.box.last_target is None
    assert (s.box.path / "notes.md").exists()


def test_new_box_cancel_in_target_loop_keeps_box(env):
    # the answers run out in the second target's questions
    env.console = FakeConsole(
        ["forest", "", "", "", "", "", "10.10.10.161", "", "", "", "y", "10.10.10.162"]
    )
    s = new_box(env)
    assert [t.name for t in s.targets] == ["10.10.10.161"]
    assert (s.box.path / "notes.md").exists()
    assert load_state(env.paths.state_file).last_platform == "htb"


def test_new_box_cancel_in_questions_propagates(env):
    env.console = FakeConsole(["forest"])
    with pytest.raises(Cancelled):
        new_box(env)
    assert not env.paths.active.exists()


def two_boxes(env):
    active = create_box(
        env.paths, name="Cascade", platform="htb", day=NOW.date(), os_name="", difficulty="",
        now=NOW, new_id=lambda: "a",
    )  # fmt: skip
    done = create_box(
        env.paths, name="Forest", platform="thm", day=date(2026, 10, 1), os_name="",
        difficulty="", now=NOW.replace(month=10, day=1), new_id=lambda: "b",
    )  # fmt: skip
    done.status = "finished"
    done.finished = NOW
    save_box(done)
    return active, done


def test_menu_lists_new_import_resume_reopen(env):
    two_boxes(env)
    env.console = FakeConsole(["x"])
    with pytest.raises(Cancelled):
        choose(env)
    assert lines(env, "info") == [
        "1  new box",
        "2  import a box from a file",
        "3  resume Cascade (htb, started 2026-11-14)",
        "4  reopen Forest (thm, finished 2026-11-14)",
    ]


def test_menu_reasks_on_a_bad_choice(env):
    active, _ = two_boxes(env)
    env.console = FakeConsole(["9", "resume", "3"])
    assert choose(env).box.path == active.path
    assert len(lines(env, "fail")) == 2


def test_menu_resume_choice_returns_that_box(env):
    active, _ = two_boxes(env)
    env.console = FakeConsole(["3"])
    assert choose(env).box.path == active.path


def test_menu_reopen_sets_active(env):
    _, done = two_boxes(env)
    env.console = FakeConsole(["4"])
    s = choose(env)
    assert s.box.path == done.path and s.box.status == "active" and s.box.finished is None


def test_menu_new_choice(env):
    env.console = FakeConsole(["1", "forest", "", "", "", "", "n"])
    assert choose(env).box.name == "forest"


def test_menu_import_choice(env, box, monkeypatch):
    seen = []
    monkeypatch.setattr(lifecycle, "import_box", lambda *a: seen.append(a) or box)
    env.console = FakeConsole(["2", "~/x.tar.gz"])
    assert choose(env).box.path == box.path
    assert seen[0][3] == Path("~/x.tar.gz").expanduser()


def test_menu_import_failure_returns_none(env, monkeypatch):
    monkeypatch.setattr(lifecycle, "import_box", lambda *a: None)
    env.console = FakeConsole(["2", "x.tar.gz"])
    assert choose(env) is None


def test_menu_mentions_unreadable_boxes(env):
    two_boxes(env)
    bad = env.paths.active / "2026-01-01_htb_bad"
    bad.mkdir()
    (bad / "box.toml").write_text("not = [valid", encoding="utf-8")
    env.console = FakeConsole(["3"])
    assert choose(env) is not None
    warns = lines(env, "warn")
    assert len(warns) == 1 and "2026-01-01_htb_bad" in warns[0]


def test_box_for_cwd(env, box):
    sub = box.path / "targets"
    sub.mkdir(exist_ok=True)
    env.cwd = sub
    assert box_for_cwd(env).path == box.path
    env.cwd = box.path
    assert box_for_cwd(env).path == box.path
    env.cwd = env.paths.active
    assert box_for_cwd(env) is None
    env.cwd = env.paths.home
    assert box_for_cwd(env) is None


def test_box_for_cwd_ignores_finished_and_broken(env):
    _, done = two_boxes(env)
    env.cwd = done.path
    assert box_for_cwd(env) is None
    junk = env.paths.active / "junk"
    junk.mkdir()
    env.cwd = junk
    assert box_for_cwd(env) is None


def test_start_version_and_help(env):
    assert start(env, ["--version"]) == 0
    assert lines(env, "info") == [f"pwn-broker {__version__}"]
    env.console = FakeConsole()
    assert start(env, ["-h"]) == 0
    assert any("import <file>" in t for t in lines(env, "info"))


def test_start_unknown_and_import_without_file(env, quiet, ran):
    assert start(env, ["frob"]) == 2
    assert "frob" in lines(env, "fail")[0] and "--help" in lines(env, "fail")[0]
    env.console = FakeConsole()
    assert start(env, ["import"]) == 2
    assert lines(env, "fail") and ran == []


def test_start_refuses_wrong_owner(env, quiet, monkeypatch, ran):
    monkeypatch.setattr(privilege, "wrong_owner", lambda path: "kali")
    assert start(env, []) == 1
    assert "kali" in lines(env, "fail")[0]
    assert ran == [] and not env.paths.vim_dir.exists()


def test_start_runs_checks_then_shell(env, quiet, box):
    env.cwd = box.path
    seen = []
    env.run = lambda s: seen.append(list(env.console.lines))
    assert start(env, []) == 0
    assert ("ok", "2 checks passed") in seen[0]
    assert (env.paths.vim_dir / "vimrc").exists()


def test_start_stops_on_failed_check(env, quiet, monkeypatch, ran):
    monkeypatch.setattr(
        checks, "launch_checks", lambda *a, **k: [CheckResult("vim", "fail", "vim not found")]
    )
    assert start(env, []) == 1
    assert ran == [] and lines(env, "fail")


def test_start_install_data_failure(env, quiet, monkeypatch, ran):
    def boom(paths):
        raise OSError("read-only")

    monkeypatch.setattr(setup, "install_data", boom)
    assert start(env, []) == 1
    assert "read-only" in lines(env, "fail")[0]


def test_start_version_warning(env, quiet, monkeypatch, box, ran):
    monkeypatch.setattr(
        checks, "version_check", lambda s: CheckResult("version", "warn", "9.9 is available")
    )
    env.cwd = box.path
    assert start(env, []) == 0
    assert ("warn", "version   9.9 is available") in env.console.lines


def test_start_version_check_errors_are_swallowed(env, quiet, monkeypatch, box, ran):
    def boom(settings):
        raise RuntimeError("no network")

    monkeypatch.setattr(checks, "version_check", boom)
    env.cwd = box.path
    assert start(env, []) == 0 and len(ran) == 1


def test_start_resumes_box_for_cwd(env, quiet, box, ran):
    env.cwd = box.path
    assert start(env, []) == 0
    assert ran[0].box.path == box.path
    assert env.console.asked == []


def test_start_menu_when_cwd_elsewhere(env, quiet, box, ran):
    env.console = FakeConsole(["3"])
    assert start(env, []) == 0
    assert ran[0].box.path == box.path


def test_start_cancel_at_menu_exits_zero(env, quiet, box, ran):
    assert start(env, []) == 0
    assert ran == [] and lines(env, "info")[-1] == "cancelled"


def test_start_new_subcommand(env, quiet, ran):
    env.console = FakeConsole(["newbox", "", "", "", "", "n"])
    assert start(env, ["new"]) == 0
    assert ran[-1].box.name == "newbox"


def test_start_import_subcommand(env, quiet, box, monkeypatch, ran):
    seen = []
    monkeypatch.setattr(lifecycle, "import_box", lambda *a: seen.append(a) or box)
    assert start(env, ["import", "a.tar.gz"]) == 0
    assert seen[0][3] == Path("a.tar.gz") and ran[-1].box.path == box.path

    monkeypatch.setattr(lifecycle, "import_box", lambda *a: None)
    assert start(env, ["import", "a.tar.gz"]) == 1


def test_start_resume_subcommand(env, quiet, box, ran):
    assert start(env, ["resume", "forest"]) == 0 and ran[-1].box.path == box.path
    assert start(env, ["resume", box.path.name]) == 0 and len(ran) == 2
    assert start(env, ["resume", "nope"]) == 1 and len(ran) == 2
    assert lines(env, "fail")


def test_start_resume_without_name(env, quiet, box, ran):
    assert start(env, ["resume"]) == 0 and ran[0].box.path == box.path
    create_box(
        env.paths, name="B", platform="htb", day=NOW.date(), os_name="", difficulty="", now=NOW
    )
    assert start(env, ["resume"]) == 1 and len(ran) == 1
    assert lines(env, "fail")


def test_start_refuses_second_open_box(env, quiet, box, monkeypatch, ran):
    monkeypatch.setattr(boxes, "pid_alive", lambda pid: pid == 999)
    boxes.acquire_open(env.paths, box, pid=999, alive=lambda pid: False)
    lock = env.paths.run / "open.toml"
    before = lock.read_bytes()
    assert start(env, ["new"]) == 1
    assert box.path.name in lines(env, "fail")[0]
    assert env.console.asked == [] and ran == []
    assert lock.read_bytes() == before


def test_start_acquire_failure(env, quiet, box, monkeypatch, ran):
    def boom(*a, **k):
        raise BoxError("busy")

    monkeypatch.setattr(boxes, "acquire_open", boom)
    env.cwd = box.path
    assert start(env, []) == 1 and ran == [] and "busy" in lines(env, "fail")[0]


def test_start_holds_then_releases_lock(env, quiet, box):
    lock = env.paths.run / "open.toml"
    held = []
    env.run = lambda s: held.append(lock.exists())
    env.cwd = box.path
    assert start(env, []) == 0
    assert held == [True] and not lock.exists()


def test_start_releases_lock_on_exit(env, quiet, box):
    def boom(s):
        raise RuntimeError("shell died")

    env.run = boom
    env.cwd = box.path
    with pytest.raises(RuntimeError):
        start(env, [])
    assert not (env.paths.run / "open.toml").exists()


def test_start_opens_note_window(env, quiet, box, ran):
    env.cwd = box.path
    assert start(env, []) == 0
    assert len(quiet) == 1 and quiet[0][3] == env.environ
    assert quiet[0][2].path == box.path and lines(env, "warn") == []


def test_start_prints_manual_command_without_display(env, quiet, box, monkeypatch, ran):
    monkeypatch.setattr(notewindow, "open_note", lambda *a: False)
    env.cwd = box.path
    assert start(env, []) == 0
    warn = lines(env, "warn")[0]
    assert "vim -u" in warn and "notes.md" in warn and len(ran) == 1


def test_start_setup_subcommand(env, monkeypatch, ran):
    calls = []
    monkeypatch.setattr(setup, "install_data", lambda p: calls.append("data"))
    monkeypatch.setattr(setup, "write_launcher", lambda p, py: calls.append(("launcher", py)))

    def nope(*a, **k):
        raise AssertionError("must not run")

    monkeypatch.setattr(checks, "launch_checks", nope)
    monkeypatch.setattr(privilege, "wrong_owner", nope)
    env.environ = {**env.environ, "PWN_BROKER_SKIP_ASCIINEMA": "1"}
    assert start(env, ["setup"]) == 0
    assert calls[0] == "data" and calls[1][0] == "launcher"
    assert len(lines(env, "ok")) == 2 and ran == []


def _setup_env(env, monkeypatch, **environ):
    monkeypatch.setattr(setup, "install_data", lambda p: None)
    monkeypatch.setattr(setup, "write_launcher", lambda p, py: Path("/opt/bin/pwn-broker"))
    env.environ = {**env.environ, **environ}
    fetched = []
    env.fetch = fetched.append
    return fetched


def test_setup_fetches_asciinema(env, monkeypatch):
    fetched = _setup_env(env, monkeypatch)
    assert start(env, ["setup"]) == 0
    assert fetched == [env.paths]
    assert lines(env, "ok")[-1] == f"asciinema 3.2.1 in {env.paths.asciinema}"


@pytest.mark.parametrize("value", ["1", "yes", "x"])
def test_setup_skips_asciinema_when_asked(env, monkeypatch, value):
    fetched = _setup_env(env, monkeypatch, PWN_BROKER_SKIP_ASCIINEMA=value)
    assert start(env, ["setup"]) == 0
    assert fetched == [] and len(lines(env, "ok")) == 2 and lines(env, "warn") == []


def test_setup_an_empty_skip_variable_does_not_skip(env, monkeypatch):
    fetched = _setup_env(env, monkeypatch, PWN_BROKER_SKIP_ASCIINEMA="")
    assert start(env, ["setup"]) == 0
    assert fetched == [env.paths]


def test_setup_does_not_fetch_what_is_present(env, monkeypatch):
    fetched = _setup_env(env, monkeypatch)
    monkeypatch.setattr(cli.recorder, "present", lambda p: True)
    assert start(env, ["setup"]) == 0
    assert fetched == []
    assert lines(env, "ok")[-1] == f"asciinema 3.2.1 in {env.paths.asciinema}"


def test_setup_warns_when_the_fetch_fails_and_still_succeeds(env, monkeypatch):
    _setup_env(env, monkeypatch)

    def refuse(paths):
        raise cli.recorder.RecorderError("the download does not match its checksum")

    env.fetch = refuse
    assert start(env, ["setup"]) == 0
    assert lines(env, "warn") == [
        "asciinema was not installed: the download does not match its checksum. "
        "record and replay will not work until it is: run check in the prompt"
    ]


def test_a_test_env_cannot_reach_the_network(env):
    from pwn_broker import recorder

    assert env.fetch is not recorder.fetch
    env.fetch(env.paths)


def test_launch_checks_can_skip_version(paths, tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(checks, "version_check", lambda s: called.append(1))
    checks.launch_checks(paths, Settings(), {}, tmp_path, include_version=False, tunnel=lambda: None, fetch=lambda p: None)
    assert called == []
    checks.launch_checks(paths, Settings(), {}, tmp_path, tunnel=lambda: None, fetch=lambda p: None)
    assert called == [1]


def test_main_reports_config_error(tmp_path, monkeypatch, capsys):
    (tmp_path / "config.toml").write_text("home = [", encoding="utf-8")
    monkeypatch.setenv("PWN_BROKER_OPT", str(tmp_path))
    assert main(["--version"]) == 1
    assert "fail" in capsys.readouterr().out


def test_main_version(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("PWN_BROKER_OPT", str(tmp_path))
    assert main(["--version"]) == 0
    assert __version__ in capsys.readouterr().out


def test_main_keyboard_interrupt(monkeypatch, tmp_path):
    monkeypatch.setenv("PWN_BROKER_OPT", str(tmp_path))

    def boom(env, argv):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "start", boom)
    assert main([]) == 130


def test_new_box_keeps_going_when_one_target_fails(env, monkeypatch):
    real = boxes.add_target

    def flaky(box, targets, **kw):
        if kw["name"] == "two":
            raise BoxError("disk full")
        return real(box, targets, **kw)

    monkeypatch.setattr(boxes, "add_target", flaky)
    env.console = FakeConsole(
        ["forest", "", "", "", "",
         "", "10.10.10.1", "", "", "one",
         "y", "10.10.10.2", "", "", "two",
         "y", "10.10.10.3", "", "", "three",
         ""]
    )  # fmt: skip
    s = new_box(env)
    assert [t.name for t in s.targets] == ["one", "three"]
    text = (s.box.path / "notes.md").read_text()
    assert "Target: one " in text and "Target: three " in text and "two" not in text
    assert len(lines(env, "fail")) == 1 and "disk full" in lines(env, "fail")[0]


def test_new_box_survives_a_note_that_cannot_be_written(env, monkeypatch):
    def boom(box, text):
        raise OSError("read-only")

    monkeypatch.setattr(session, "write_note", boom)
    env.console = FakeConsole(["forest", "", "", "", "", "y", "10.10.10.1", "", "", "", ""])
    s = new_box(env)
    assert s.box.path.is_dir() and [t.name for t in s.targets] == ["10.10.10.1"]
    warns = lines(env, "warn")
    assert len(warns) == 1 and "read-only" in warns[0]


def test_start_reports_a_box_that_could_not_be_finished(env, quiet, monkeypatch, ran):
    def boom(s):
        raise StoreError("bad toml")

    monkeypatch.setattr(session, "refresh", boom)
    env.console = FakeConsole(["forest", "", "", "", "", "n"])
    assert start(env, ["new"]) == 1
    fails = lines(env, "fail")
    assert len(fails) == 1 and "bad toml" in fails[0] and "forest" in fails[0]
    assert ran == [] and not (env.paths.run / "open.toml").exists()


def test_resume_prints_unreadable_folders(env, quiet, box):
    bad = env.paths.active / "2026-01-01_htb_bad"
    bad.mkdir()
    (bad / "box.toml").write_text("not = [valid", encoding="utf-8")
    assert start(env, ["resume", "nope"]) == 1
    kinds = [k for k, _ in env.console.lines]
    assert kinds.index("warn") < kinds.index("fail")


def test_install_failure_suggests_repair(env, quiet, monkeypatch):
    def boom(paths):
        raise OSError("read-only")

    monkeypatch.setattr(setup, "install_data", boom)
    start(env, [])
    assert env.console.lines[-1] == ("info", "run the installer again to repair the install")


def test_start_runs_the_checks_then_the_update_check(env, quiet, monkeypatch, box, ran):
    order = []
    monkeypatch.setattr(checks, "version_check", lambda s: order.append("version"))
    monkeypatch.setattr(
        checks, "launch_checks", lambda *a, **k: order.append(("checks", k)) or []
    )
    env.cwd = box.path
    start(env, [])
    assert order == [("checks", {"include_version": False, "tunnel": env.tunnel, "fetch": env.fetch}), "version"]


def test_main_reports_unexpected_errors(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("PWN_BROKER_OPT", str(tmp_path))

    def boom(env, argv):
        raise RuntimeError("odd")

    monkeypatch.setattr(cli, "start", boom)
    assert main([]) == 1
    assert "unexpected error: RuntimeError: odd" in capsys.readouterr().out


def test_main_survives_a_deleted_cwd(monkeypatch, tmp_path):
    monkeypatch.setenv("PWN_BROKER_OPT", str(tmp_path))
    seen = []
    monkeypatch.setattr(cli, "start", lambda env, argv: seen.append(env.cwd) or 0)

    def gone():
        raise FileNotFoundError("deleted")

    monkeypatch.setattr(Path, "cwd", staticmethod(gone))
    assert main([]) == 0 and seen == [Path.home()]


def test_reopen_runs_the_restore_hooks_with_the_loaded_session(env, monkeypatch):
    _, done = two_boxes(env)
    seen = []
    monkeypatch.setattr(lifecycle, "RESTORE_HOOKS", [lambda s: seen.append((s.box.path, s.box.status))])
    env.console = FakeConsole(["4"])
    choose(env)
    assert seen == [(done.path, "active")]


def test_resume_does_not_run_the_restore_hooks(env, monkeypatch):
    two_boxes(env)
    seen = []
    monkeypatch.setattr(lifecycle, "RESTORE_HOOKS", [seen.append])
    env.console = FakeConsole(["3"])
    choose(env)
    assert seen == []


def test_start_offers_to_remove_tools_left_by_finished_boxes(env, quiet, box, ran, monkeypatch):
    from pwn_broker import toolhooks

    seen = []
    monkeypatch.setattr(toolhooks, "leftovers", lambda paths, console: seen.append((paths, console)))
    env.cwd = box.path
    assert start(env, []) == 0
    assert seen == [(env.paths, env.console)]


def test_start_looks_for_no_leftovers_while_another_prompt_is_open(
    env, quiet, box, ran, monkeypatch
):
    from pwn_broker import toolhooks

    seen = []
    monkeypatch.setattr(toolhooks, "leftovers", lambda paths, console: seen.append(paths))
    monkeypatch.setattr(boxes, "pid_alive", lambda pid: pid == 999)
    boxes.acquire_open(env.paths, box, pid=999, alive=lambda pid: False)
    assert start(env, ["new"]) == 1
    assert seen == [] and ran == []


def test_main_registers_the_tool_hooks(tmp_path, monkeypatch):
    from pwn_broker import toolhooks

    for name in ("BLOCK_HOOKS", "SUMMARY_HOOKS", "PRE_PACK_HOOKS", "UNDO_HOOKS", "RESTORE_HOOKS"):
        monkeypatch.setattr(lifecycle, name, [])
    monkeypatch.setattr(cli, "start", lambda env, argv: 0)
    monkeypatch.setenv("PWN_BROKER_OPT", str(tmp_path))
    assert main([]) == 0
    assert toolhooks.block in lifecycle.BLOCK_HOOKS
    assert toolhooks.restore in lifecycle.RESTORE_HOOKS


def test_new_box_goes_on_when_the_hosts_record_cannot_be_saved(env, system, monkeypatch):
    from pwn_broker import hostflow

    def broken(box):
        raise StoreError("box.toml: disk full")

    monkeypatch.setattr(hostflow, "save_box", broken)
    env.console = FakeConsole(
        ["forest", "", "", "windows", "easy",
         "", "10.10.10.161", "forest.htb.local", "", "dc01",
         "y", "10.10.10.162", "", "internal", "",
         "", ""]
    )  # fmt: skip
    s = new_box(env)
    assert system.pings == ["10.10.10.161", "10.10.10.162"]
    assert s.box.hosts == []
    assert env.console.lines[-1] == ("ok", "box forest created")


def test_start_offers_to_remove_hosts_lines_left_by_finished_boxes(
    env, quiet, box, ran, monkeypatch, system
):
    from pwn_broker import hostflow

    seen = []
    monkeypatch.setattr(hostflow, "leftovers", lambda *a, **k: seen.append((a, k)))
    env.cwd = box.path
    assert start(env, []) == 0
    assert seen == [
        (
            (env.paths, env.console),
            dict(
                hosts_path=env.hosts_path,
                is_root=env.is_root,
                run=env.run_privileged,
            ),
        )
    ]
    assert env.hosts_path == system.hosts_path


def test_start_looks_for_no_hosts_leftovers_while_another_prompt_is_open(
    env, quiet, box, ran, monkeypatch
):
    from pwn_broker import hostflow

    seen = []
    monkeypatch.setattr(hostflow, "leftovers", lambda *a, **k: seen.append(a))
    monkeypatch.setattr(boxes, "pid_alive", lambda pid: pid == 999)
    boxes.acquire_open(env.paths, box, pid=999, alive=lambda pid: False)
    assert start(env, ["new"]) == 1
    assert seen == []


def test_env_and_its_sessions_never_reach_the_real_hosts_file(env, box):
    from pwn_broker import hosts

    assert env.hosts_path != hosts.DEFAULT_PATH
    assert env.is_root is not privilege.is_root
    assert env.run_privileged is not privilege.run_privileged
    opened = cli._load(env, box)
    assert opened.hosts_path == env.hosts_path
    assert opened.is_root is env.is_root
    assert opened.run_privileged is env.run_privileged


def test_start_puts_the_boxes_lines_back_before_the_note_window_opens(
    env, quiet, box, ran, monkeypatch
):
    from pwn_broker import hostflow

    order = []
    monkeypatch.setattr(hostflow, "on_open", lambda s: order.append(("on_open", s.box.id)))
    monkeypatch.setattr(notewindow, "open_note", lambda *a: order.append(("note",)) or True)
    real_acquire = boxes.acquire_open
    monkeypatch.setattr(
        boxes, "acquire_open", lambda *a, **k: order.append(("acquire",)) or real_acquire(*a, **k)
    )
    env.cwd = box.path
    assert start(env, []) == 0
    assert order == [("acquire",), ("on_open", box.id), ("note",)]


def test_start_does_not_open_a_box_it_could_not_acquire(env, quiet, box, ran, monkeypatch):
    from pwn_broker import hostflow

    seen = []
    monkeypatch.setattr(hostflow, "on_open", seen.append)
    monkeypatch.setattr(
        boxes, "acquire_open", lambda *a, **k: (_ for _ in ()).throw(BoxError("busy"))
    )
    env.cwd = box.path
    assert start(env, []) == 1
    assert seen == []


def test_main_registers_the_kali_hooks(tmp_path, monkeypatch):
    from pwn_broker import hostflow

    for name in ("BLOCK_HOOKS", "SUMMARY_HOOKS", "PRE_PACK_HOOKS", "UNDO_HOOKS", "RESTORE_HOOKS"):
        monkeypatch.setattr(lifecycle, name, [])
    monkeypatch.setattr(cli, "start", lambda env, argv: 0)
    monkeypatch.setenv("PWN_BROKER_OPT", str(tmp_path))
    assert main([]) == 0
    assert hostflow.undo in lifecycle.UNDO_HOOKS
    assert hostflow.summary in lifecycle.SUMMARY_HOOKS


def test_a_loaded_session_reads_the_tunnel_through_the_env(env, box):
    from pwn_broker.cli import _load
    from pwn_broker.vpn import Tunnel

    env.tunnel = lambda: Tunnel("tun0", "10.10.14.7")
    assert _load(env, box).tunnel() == Tunnel("tun0", "10.10.14.7")


def test_prepare_restores_a_missing_record_launcher(env, quiet):
    setup.install_data(env.paths)
    setup.write_launcher(env.paths, Path("/old/python"))
    env.paths.record_launcher.unlink()
    assert cli._prepare(env) is None
    assert env.paths.record_launcher.read_bytes().startswith(b"#!/bin/sh\nexec ")
    assert not any(k in ("warn", "fail") for k, _ in env.console.lines)


def test_prepare_leaves_an_existing_record_launcher_alone(env, quiet):
    setup.install_data(env.paths)
    env.paths.record_launcher.write_bytes(b"mine\n")
    assert cli._prepare(env) is None
    assert env.paths.record_launcher.read_bytes() == b"mine\n"


def test_prepare_passes_its_fetch_to_the_checks(env, monkeypatch):
    seen = {}
    monkeypatch.setattr(privilege, "wrong_owner", lambda path: None)
    monkeypatch.setattr(checks, "version_check", lambda settings: None)

    def fake(*a, **k):
        seen.update(k)
        return []

    monkeypatch.setattr(checks, "launch_checks", fake)
    setup.install_data(env.paths)
    assert cli._prepare(env) is None
    assert seen["fetch"] == env.fetch
