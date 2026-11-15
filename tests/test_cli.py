import sys
from datetime import date
from pathlib import Path

import pytest

from conftest import NOW
from pwn_broker import __version__, boxes, checks, cli, lifecycle, notewindow, privilege, setup
from pwn_broker.boxes import BoxError, create_box
from pwn_broker.checks import CheckResult
from pwn_broker.cli import box_for_cwd, choose, main, new_box, start
from pwn_broker.config import Settings, load_state
from pwn_broker.console import Cancelled, FakeConsole
from pwn_broker.questions import BoxAnswers, ask_box
from pwn_broker.store import save_box


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


def test_ask_box_platform_normalised_only_when_default():
    a = ask_box(
        FakeConsole(["Forest ", "Other Lab", "", "", ""]),
        default_platform=" HTB",
        today=date(2026, 11, 14),
    )
    assert a.name == "Forest " and a.platform == "Other Lab"
    b = ask_box(
        FakeConsole(["x", "", "", "", ""]), default_platform=" HTB", today=date(2026, 11, 14)
    )
    assert b.platform == "htb"


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
    assert note.startswith("# forest\n") and "## dc01" in note and "## 10.10.10.162" in note
    assert (s.box.path / "lists/ips.txt").read_text() == "10.10.10.161\n10.10.10.162\n"
    assert load_state(env.paths.state_file).last_platform == "htb"
    assert s.current.name == "dc01"
    assert env.console.lines[-1] == ("ok", "box forest created")
    assert ("ok", "target dc01 created") in env.console.lines


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
    monkeypatch.setattr(boxes, "open_box_folder", lambda paths: box.path)
    assert start(env, ["new"]) == 1
    assert box.path.name in lines(env, "fail")[0]
    assert env.console.asked == [] and ran == []


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
    assert start(env, ["setup"]) == 0
    assert calls[0] == "data" and calls[1][0] == "launcher"
    assert len(lines(env, "ok")) == 2 and ran == []


def test_launch_checks_can_skip_version(paths, tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(checks, "version_check", lambda s: called.append(1))
    checks.launch_checks(paths, Settings(), {}, tmp_path, include_version=False)
    assert called == []
    checks.launch_checks(paths, Settings(), {}, tmp_path)
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
