"""What the launch, the start menu and the questions put on screen, as TermConsole writes it."""

import io
from dataclasses import replace

import pytest

import toolkit
from pwn_broker import __version__, checks, cli, lifecycle, notewindow, privilege, toolhooks
from pwn_broker.checks import CheckResult
from pwn_broker.cli import start
from pwn_broker.console import FakeConsole, TermConsole
from pwn_broker.shell.commands import dispatch


@pytest.fixture
def quiet(monkeypatch):
    monkeypatch.setattr(
        checks,
        "launch_checks",
        lambda *a, **k: [
            CheckResult("vim", "ok", "x"),
            CheckResult("vpn", "warn", "no VPN tunnel is up", "start one with: vpn start"),
        ],
    )
    monkeypatch.setattr(checks, "version_check", lambda settings: None)
    monkeypatch.setattr(notewindow, "open_note", lambda *a: True)
    monkeypatch.setattr(privilege, "wrong_owner", lambda path: None)


def term(monkeypatch, *answers):
    """A TermConsole on a string; each question is drawn and answered the way a terminal would."""
    out = io.StringIO()
    queue = list(answers)

    def fake_prompt(message, **kwargs):
        answer = queue.pop(0)
        out.write("".join(text for _, text in message) + answer + "\n")
        return answer

    monkeypatch.setattr("prompt_toolkit.prompt", fake_prompt)
    return TermConsole({"NO_COLOR": "1"}, out=out), out


LAUNCH_INTO_A_NEW_BOX = """\
pwn-broker {version}

  ok    1 check passed
  warn  vpn   no VPN tunnel is up
        start one with: vpn start

Boxes
  1  new box
  2  import a box from a file

  choice       > 1

New box
  box name     > forest
  platform     [htb] > 
  date         [2026-11-14] > 
  os           > windows
  difficulty   > easy

  add a target? [Y/n] > 

Target 1
  ip           > 10.10.10.161
  hostname     > forest.htb.local
  scope        [external] > 
  name         [forest.htb.local] > dc01

  ok    target dc01 created

  add another? [y/N] > y

Target 2
  ip           > 10.10.10.162
  hostname     > 
  scope        [external] > internal
  name         [10.10.10.162] > 

  ok    target 10.10.10.162 created

  add another? [y/N] > 

  add dc01's hostnames to /etc/hosts? [Y/n] > n

  ok    10.10.10.161 answered in 1 ms
  ok    10.10.10.162 answered in 1 ms
  ok    box forest created

  install playbooks in this box and every new box? [Y/n] > n

  ok    saved: new boxes start without playbooks
        for this box only: tool install playbooks
        for every new box: playbooks = true in {config}

"""


def test_a_whole_launch_into_a_new_box_with_two_targets(env, quiet, monkeypatch):
    answers = [
        "1", "forest", "", "", "windows", "easy",
        "", "10.10.10.161", "forest.htb.local", "", "dc01",
        "y", "10.10.10.162", "", "internal", "",
        "", "n", "n",
    ]  # fmt: skip
    env.console, out = term(monkeypatch, *answers)
    assert start(env, []) == 0
    assert out.getvalue() == LAUNCH_INTO_A_NEW_BOX.format(
        version=__version__, config=env.paths.config_file
    )


THE_PLAYBOOKS_QUESTION_ANSWERED_YES = """\
  ok    box forest created

  install playbooks in this box and every new box? [Y/n] > 

  ok    saved: new boxes get the playbooks
        to change it: playbooks = false in {config}
  ok    playbooks 2026.11.19 installed (2 playbooks)
  read  :Pb <name>      in the note window
  list  playbook list   at the prompt

"""


def test_the_playbooks_question_answered_yes(env, quiet, monkeypatch, tmp_path):
    folder = tmp_path / "index"
    home = tmp_path / "user"
    home.mkdir(exist_ok=True)
    monkeypatch.setattr(toolhooks, "user_home", lambda: home)
    monkeypatch.setattr(toolhooks.tooldata, "_root_home", lambda: tmp_path / "no-root-home")
    toolkit.write_index(folder, [toolkit.make_notes_entry(folder)[1]])
    env.settings = replace(env.settings, tools_index=str(folder))
    env.console, out = term(monkeypatch, "forest", "", "", "", "", "n", "")
    assert start(env, ["new"]) == 0
    shown = out.getvalue()
    assert shown[shown.index("  ok    box forest created"):] == THE_PLAYBOOKS_QUESTION_ANSWERED_YES.format(
        config=env.paths.config_file
    )


def test_the_events_of_a_launch_into_a_new_box(env, quiet):
    env.console = FakeConsole(
        ["1", "forest", "", "", "windows", "easy", "", "10.10.10.161", "", "", "dc01", "", "n"]
    )
    assert start(env, []) == 0
    shown = [(kind, text) for kind, text in env.console.events if kind in ("header", "heading", "gap", "ask")]
    assert shown[:11] == [
        ("header", f"pwn-broker {__version__}"),
        ("gap", ""),
        ("gap", ""),
        ("heading", "Boxes"),
        ("gap", ""),
        ("ask", "choice"),
        ("gap", ""),
        ("heading", "New box"),
        ("ask", "box name"),
        ("ask", "platform"),
        ("ask", "date"),
    ]
    headings = [text for kind, text in shown if kind == "heading"]
    assert headings == ["Boxes", "New box", "Target 1"]


def test_new_shows_the_header_and_the_checks_and_then_the_new_box_group(env, quiet):
    env.console = FakeConsole(["forest", "", "", "", "", "n"])
    assert start(env, ["new"]) == 0
    kinds = [kind for kind, _ in env.console.events]
    assert kinds[0] == "header"
    assert ("heading", "New box") in env.console.events
    assert ("heading", "Boxes") not in env.console.events


def test_resume_and_a_box_folder_go_straight_on_after_the_header(env, quiet, box):
    env.cwd = box.path
    env.console = FakeConsole()
    assert start(env, []) == 0
    kinds = [kind for kind, _ in env.console.events]
    assert kinds[:2] == ["header", "gap"]
    assert "heading" not in kinds
    env.cwd = env.paths.home
    env.console = FakeConsole()
    assert start(env, ["resume"]) == 0
    assert env.console.events[0] == ("header", f"pwn-broker {__version__}")
    assert "heading" not in [kind for kind, _ in env.console.events]


@pytest.mark.parametrize("argv", [["--help"], ["--version"], ["setup"]])
def test_no_header_for_help_version_and_setup(env, quiet, argv):
    env.console = FakeConsole()
    start(env, argv)
    assert "header" not in [kind for kind, _ in env.console.events]


def test_no_header_for_import_with_a_file(env, quiet, monkeypatch, box):
    monkeypatch.setattr(lifecycle, "import_box", lambda *a: box)
    env.console = FakeConsole()
    assert start(env, ["import", "x.tar.gz"]) == 0
    assert "header" not in [kind for kind, _ in env.console.events]


def test_help_and_version_are_flush_left_and_byte_for_byte(env, monkeypatch):
    env.console, out = term(monkeypatch)
    assert start(env, ["--version"]) == 0
    assert out.getvalue() == f"pwn-broker {__version__}\n"
    env.console, out = term(monkeypatch)
    assert start(env, ["--help"]) == 0
    assert out.getvalue() == "".join(f"{line}\n" for line in cli.HELP)
    assert all(not line.startswith(" ") for line in out.getvalue().splitlines())


def test_the_header_is_flush_left_with_no_blank_line_above_and_one_below():
    out = io.StringIO()
    TermConsole({"NO_COLOR": "1"}, out=out).header("pwn-broker 1.2.3")
    assert out.getvalue() == "pwn-broker 1.2.3\n\n"


# the questions at the prompt


def prompt_text(session, monkeypatch, command, *answers):
    """What `command` writes at the prompt, with the command line drawn above it."""
    session.console, out = term(monkeypatch, *answers)
    out.write("forest/dc01 > " + command + "\n")
    session.console.typed()
    with session.console.block():
        dispatch(session, command)
    return out.getvalue()


def test_target_add_at_the_prompt(session, monkeypatch):
    text = prompt_text(session, monkeypatch, "target add", "10.10.10.50", "web.htb", "", "web01", "n")
    assert text == (
        "forest/dc01 > target add\n"
        "\n"
        "New target\n"
        "  ip           > 10.10.10.50\n"
        "  hostname     > web.htb\n"
        "  scope        [external] > \n"
        "  name         [web.htb] > web01\n"
        "\n"
        "  ok    target web01 created\n"
        "\n"
        "  add web01's hostnames to /etc/hosts? [Y/n] > n\n"
        "\n"
        "  ok    10.10.10.50 answered in 1 ms\n"
        "\n"
    )


def test_cred_add_at_the_prompt(session, monkeypatch):
    text = prompt_text(session, monkeypatch, "cred add", "bob", "", "pw", "", "", "")
    assert text == (
        "forest/dc01 > cred add\n"
        "\n"
        "New credential\n"
        "  username     > bob\n"
        "  domain       > \n"
        "  secret       > pw\n"
        "  kind         [password] > \n"
        "  found on     [dc01] > \n"
        "  note         > \n"
        "\n"
        "  ok    cred 1 saved, found on dc01\n"
        "  ok    lists updated: 1 username, 1 password, 1 pair\n"
        "\n"
    )


def test_cred_import_at_the_prompt(session, monkeypatch, tmp_path):
    names = tmp_path / "names.txt"
    names.write_text("alice\nbob\n", encoding="utf-8")
    text = prompt_text(session, monkeypatch, f"cred import {names}", "", "")
    assert text == (
        f"forest/dc01 > cred import {names}\n"
        "\n"
        "Import usernames\n"
        "  domain       > \n"
        "  found on     [dc01] > \n"
        "\n"
        "  ok    2 usernames added\n"
        "  ok    lists updated: 2 usernames, 0 passwords, 0 pairs\n"
        "\n"
    )


def test_target_edit_and_cred_edit_headings(session, monkeypatch):
    session.console = FakeConsole(["", "", "", ""])
    dispatch(session, "target edit dc01")
    assert session.console.lines[0] == ("heading", "Edit dc01")
    dispatch(session, "cred add")
    session.console = FakeConsole(["bob", "", "", "", ""])
    dispatch(session, "cred add")
    session.console = FakeConsole(["", "", "", "", "", "", ""])
    dispatch(session, "cred edit 1")
    assert session.console.lines[0] == ("heading", "Edit credential 1")


# import


def test_the_menu_asks_again_for_an_empty_file(env, monkeypatch, box):
    seen = []
    monkeypatch.setattr(lifecycle, "import_box", lambda *a: seen.append(a) or box)
    env.console = FakeConsole(["2", "", "x.tar.gz"])
    assert cli.choose(env).box.path == box.path
    assert ("fail", "give the path of an exported box") in env.console.lines
    assert env.console.asked == ["choice", "file", "file"]
    assert len(seen) == 1


def test_an_empty_argument_fails_once(env, quiet, monkeypatch):
    monkeypatch.setattr(lifecycle, "import_box", lambda *a: pytest.fail("nothing to import"))
    env.console = FakeConsole()
    assert start(env, ["import", ""]) == 1
    assert [line for line in env.console.lines if line[0] == "fail"] == [
        ("fail", "give the path of an exported box")
    ]


def test_a_folder_is_not_an_exported_box(env, tmp_path):
    env.console = FakeConsole()
    assert lifecycle.import_box(env.paths, env.settings, env.console, tmp_path, env.clock) is None
    assert env.console.lines == [("fail", f"{tmp_path} is a folder, not an exported box")]


def test_the_menu_import_of_a_folder_says_so(env, tmp_path):
    env.console = FakeConsole(["2", str(tmp_path)])
    assert cli.choose(env) is None
    assert ("fail", f"{tmp_path} is a folder, not an exported box") in env.console.lines


# folders


def test_setup_makes_the_box_folders(env, monkeypatch):
    monkeypatch.setattr(cli.recorder, "present", lambda p: True)
    assert not env.paths.active.exists()
    assert start(env, ["setup"]) == 0
    assert env.paths.active.is_dir() and env.paths.wrapped.is_dir()


def test_the_launch_makes_the_box_folders_without_asking(env, monkeypatch, system):
    monkeypatch.setattr(privilege, "wrong_owner", lambda path: None)

    def real_checks(paths, settings, environ, home, **kwargs):
        # the real folders check; the programs it looks for are found
        return checks.run_checks(
            paths, settings, environ, which=lambda name: f"/usr/bin/{name}",
            tunnel=kwargs["tunnel"],
        )  # fmt: skip

    monkeypatch.setattr(checks, "launch_checks", real_checks)
    monkeypatch.setattr(checks, "version_check", lambda settings: None)
    monkeypatch.setattr(notewindow, "open_note", lambda *a: True)
    env.cwd = env.paths.home
    env.console = FakeConsole(["1", "forest", "", "", "", "", "n"])
    assert not env.paths.active.exists()
    assert start(env, []) == 0
    assert env.paths.active.is_dir() and env.paths.wrapped.is_dir()
    assert not any(text.startswith("folders") for _, text in env.console.lines)


def test_a_launch_as_the_wrong_user_prints_the_header_a_gap_and_the_fail_line(env, monkeypatch):
    monkeypatch.setattr(privilege, "wrong_owner", lambda path: "kali")
    env.console, out = term(monkeypatch)
    assert start(env, []) == 1
    assert out.getvalue() == (
        f"pwn-broker {__version__}\n\n  fail  pwn-broker was installed by kali; run it as kali\n"
    )
    env.console = FakeConsole()
    assert start(env, []) == 1
    assert env.console.events[:3] == [
        ("header", f"pwn-broker {__version__}"),
        ("gap", ""),
        ("fail", "pwn-broker was installed by kali; run it as kali"),
    ]


def test_a_blank_line_stands_between_a_reopened_box_and_the_first_prompt(env, quiet, box, monkeypatch):
    monkeypatch.setattr(notewindow, "find_note", lambda paths, b: 99)
    env.cwd = box.path
    env.console, out = term(monkeypatch)
    assert start(env, []) == 0
    assert out.getvalue().endswith("  ok    the note is already open\n\n")


def test_setup_prints_flush_left_as_it_did_before_the_layout(env, monkeypatch):
    monkeypatch.setattr(cli.recorder, "present", lambda p: True)
    env.console, out = term(monkeypatch)
    env.console = TermConsole({"NO_COLOR": "1"}, out=out, indent="")
    assert start(env, ["setup"]) == 0
    assert out.getvalue() == (
        f"ok    data installed in {env.paths.opt}\n"
        f"ok    launcher {env.paths.opt / 'bin' / 'pwn-broker'}\n"
        f"ok    asciinema 3.2.1 in {env.paths.asciinema}\n"
    )


def test_setup_without_its_asciinema_fails_flush_left(env, monkeypatch):
    monkeypatch.setattr(cli.recorder, "present", lambda p: False)
    env.console, out = term(monkeypatch)
    env.console = TermConsole({"NO_COLOR": "1"}, out=out, indent="")
    assert start(env, ["setup"]) == 1
    assert out.getvalue().splitlines()[-1] == (
        f"fail  asciinema is missing from {env.paths.asciinema} or does not match its checksum. "
        "run the installer again"
    )
