import os
import shutil
import sys
import time
from pathlib import Path

import pytest

from helpers import NOW
from pwn_broker import reportflow
from pwn_broker.config import Settings
from pwn_broker.console import FakeConsole
from pwn_broker.model import ToolRecord

# stand-ins for the installed pwn-report: what each does with `build <archive> -o <folder>`
STAND_INS = {
    "ok": """
import json, os, pathlib, sys
args = sys.argv[1:]
out = pathlib.Path(args[3])
out.mkdir()
(out / "report.md").write_text("# a report\\n")
(out.parent / "ran.json").write_text(json.dumps({"argv": args, "cwd": os.getcwd(), "pythonpath": os.environ.get("PYTHONPATH")}))
print(f"ok    report {out}")
""",
    "fail": """
import sys
sys.stderr.write("fail  box.toml checksum differs from manifest.toml\\n")
sys.exit(1)
""",
    "silent": """
import sys
sys.exit(3)
""",
    "slow": """
import pathlib, signal, sys, time
out = pathlib.Path(sys.argv[4])
(out.parent / f".{out.name}.tmp-x1y2z3").mkdir()
(out.parent / f".{out.name}.tmp-x1y2z3" / "evidence").write_text("copied evidence")
if hasattr(signal, "SIGTERM"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)  # so the run has to be killed
time.sleep(60)
""",
    "no folder": """
print("ok    report somewhere")
""",
}


def lines(session, *kinds):
    return [(kind, text) for kind, text in session.console.lines if not kinds or kind in kinds]


@pytest.fixture
def archive(session):
    session.paths.wrapped.mkdir(parents=True, exist_ok=True)
    path = session.paths.wrapped / "2026-11-14_htb_forest.finished.tar.gz"
    path.write_bytes(b"an archive")
    return path


def give_report_tool(session):
    session.box.tools.append(ToolRecord("report", "0.1.0", 1, "ab" * 32, NOW))
    session.paths.bin.mkdir(parents=True, exist_ok=True)
    (session.paths.bin / "pwn-report").write_text("")


@pytest.fixture
def stand_in(session, tmp_path, monkeypatch):
    """Gives the box the report tool and makes the installed pwn-report the stand-in named."""

    def use(kind: str) -> Path:
        give_report_tool(session)
        script = tmp_path / f"stand-in-{kind.replace(' ', '-')}.py"
        script.write_text(STAND_INS[kind], encoding="utf-8")
        monkeypatch.setattr(reportflow, "_launcher", lambda s: [sys.executable, str(script)])
        return script

    return use


def test_the_report_folder_is_beside_the_archive(tmp_path):
    archive = tmp_path / "2026-11-14_htb_forest.finished.tar.gz"
    assert reportflow.report_folder(archive) == tmp_path / "2026-11-14_htb_forest.finished.report"


def test_an_existing_report_is_never_replaced(tmp_path):
    archive = tmp_path / "2026-11-14_htb_forest.finished.tar.gz"
    (tmp_path / "2026-11-14_htb_forest.finished.report").mkdir()
    assert reportflow.report_folder(archive).name == "2026-11-14_htb_forest.finished.report-2"
    (tmp_path / "2026-11-14_htb_forest.finished.report-2").write_text("a file counts too")
    assert reportflow.report_folder(archive).name == "2026-11-14_htb_forest.finished.report-3"


def test_wanted_needs_the_tool_in_the_box_and_its_command(session):
    assert not reportflow.wanted(session)
    session.box.tools.append(ToolRecord("report", "0.1.0", 1, "ab" * 32, NOW))
    assert not reportflow.wanted(session)  # no command in /opt/pwn-broker/bin
    session.paths.bin.mkdir(parents=True, exist_ok=True)
    (session.paths.bin / "pwn-report").write_text("")
    assert reportflow.wanted(session)
    session.box.tools[-1].removed = NOW
    assert not reportflow.wanted(session)


def test_the_summary_row_says_whether_a_report_will_be_built(session):
    assert reportflow.summary_rows(session) == [("report", "none: tool install report adds the tool that builds one")]
    give_report_tool(session)
    assert reportflow.summary_rows(session) == [("report", "will be built beside the archive")]


def test_a_built_report_is_said_with_its_folder(session, archive, stand_in, monkeypatch):
    stand_in("ok")
    monkeypatch.setenv("PYTHONPATH", "/somewhere/else")
    folder = reportflow.build(session, archive)
    expected = archive.parent / "2026-11-14_htb_forest.finished.report"
    assert folder == expected and (expected / "report.md").is_file()
    assert lines(session) == [("field", "report  building beside the archive"), ("ok", f"report {expected}")]
    import json

    ran = json.loads((archive.parent / "ran.json").read_text())
    assert ran["argv"] == ["build", str(archive), "-o", str(expected)]
    assert ran["pythonpath"] is None  # the environment other tool runs get, not the caller's


def test_a_second_report_goes_beside_the_first(session, archive, stand_in):
    stand_in("ok")
    (archive.parent / "2026-11-14_htb_forest.finished.report").mkdir()
    folder = reportflow.build(session, archive)
    assert folder.name == "2026-11-14_htb_forest.finished.report-2"
    assert ("ok", f"report {folder}") in lines(session)


def test_a_failed_report_is_a_warning_with_its_reason(session, archive, stand_in):
    stand_in("fail")
    assert reportflow.build(session, archive) is None
    assert lines(session, "warn", "fail", "ok") == [
        ("warn", "the report was not built: box.toml checksum differs from manifest.toml")
    ]


def test_a_failure_with_no_line_gives_its_status(session, archive, stand_in):
    stand_in("silent")
    assert reportflow.build(session, archive) is None
    assert lines(session, "warn") == [("warn", "the report was not built: pwn-report exited with status 3")]


def test_a_report_said_built_but_not_there_is_a_warning(session, archive, stand_in):
    stand_in("no folder")
    assert reportflow.build(session, archive) is None
    folder = archive.parent / "2026-11-14_htb_forest.finished.report"
    assert lines(session, "warn", "ok") == [("warn", f"the report was not built: pwn-report wrote no {folder}")]


def test_a_report_that_takes_too_long_is_ended_and_its_staging_folder_removed(
    session, archive, stand_in, monkeypatch
):
    stand_in("slow")
    monkeypatch.setattr(reportflow, "TIMEOUT", 2)
    monkeypatch.setattr(reportflow, "KILL_AFTER", 1)
    started = time.monotonic()
    assert reportflow.build(session, archive) is None
    assert time.monotonic() - started < 30
    assert lines(session, "warn") == [("warn", "the report was not built: it took longer than 2 seconds")]
    assert [p.name for p in archive.parent.iterdir()] == [archive.name]


def test_a_command_that_cannot_run_is_a_warning(session, archive, monkeypatch):
    give_report_tool(session)
    monkeypatch.setattr(reportflow, "_launcher", lambda s: [str(session.paths.bin / "no-such-pwn-report")])
    assert reportflow.build(session, archive) is None
    (kind, text), = lines(session, "warn")
    assert text.startswith("the report was not built: ")


def test_a_stop_during_the_report_ends_it_and_goes_on(session, archive, stand_in, monkeypatch):
    # Ctrl-C while the report is built stops the report, not the finish
    stand_in("slow")

    def stopped(process, timeout):
        raise KeyboardInterrupt

    monkeypatch.setattr(reportflow, "_wait", stopped)
    monkeypatch.setattr(reportflow, "KILL_AFTER", 1)
    assert reportflow.build(session, archive) is None
    assert lines(session, "warn") == [("warn", "the report was not built: interrupted")]


def test_with_copy_to_the_report_is_copied_too(session, archive, stand_in, tmp_path):
    stand_in("ok")
    out = tmp_path / "copies"
    out.mkdir()
    session.settings = Settings(copy_to=out)
    folder = reportflow.build(session, archive)
    copy = out / folder.name
    assert (copy / "report.md").read_text() == "# a report\n"
    assert lines(session, "ok") == [("ok", f"report {folder}"), ("ok", f"copy {copy}")]
    assert not list(out.glob("*.part"))


def test_a_failed_copy_of_the_report_is_a_warning(session, archive, stand_in, tmp_path):
    stand_in("ok")
    out = tmp_path / "copies"
    out.mkdir()
    (out / "2026-11-14_htb_forest.finished.report").write_text("in the way")
    session.settings = Settings(copy_to=out)
    folder = reportflow.build(session, archive)
    assert folder is not None and folder.is_dir()
    (kind, text), = lines(session, "warn")
    assert text.startswith(f"the report was not copied to {out}: ")
    assert (out / "2026-11-14_htb_forest.finished.report").read_text() == "in the way"
    assert not list(out.glob("*.part"))


@pytest.mark.skipif(os.name == "nt", reason="runs the command as installed, an executable file")
def test_the_installed_command_is_what_runs(session, archive):
    give_report_tool(session)
    command = session.paths.bin / "pwn-report"
    command.write_text(f"#!{sys.executable}\n" + STAND_INS["ok"], encoding="utf-8")
    command.chmod(0o755)
    folder = reportflow.build(session, archive)
    assert folder == archive.parent / "2026-11-14_htb_forest.finished.report" and folder.is_dir()


def test_the_copy_needs_no_file_modes_a_fat_copy_to_refuses(session, archive, stand_in, tmp_path, monkeypatch):
    # a FAT or exFAT stick refuses chmod: the copy is by content alone, as the archive's is
    stand_in("ok")
    out = tmp_path / "stick"
    out.mkdir()
    session.settings = Settings(copy_to=out)

    def refused(*args, **kwargs):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(shutil, "copystat", refused)
    monkeypatch.setattr(shutil, "copymode", refused)
    folder = reportflow.build(session, archive)
    copy = out / folder.name
    assert (copy / "report.md").read_text() == "# a report\n"
    assert lines(session, "warn") == [] and ("ok", f"copy {copy}") in lines(session)


def test_a_copy_to_that_has_gone_is_never_made_again(session, archive, stand_in, tmp_path):
    # unmounted while pwn-report ran: nothing is written where the stick was
    stand_in("ok")
    gone = tmp_path / "media" / "stick"
    session.settings = Settings(copy_to=gone)
    assert reportflow.build(session, archive) is not None
    (kind, text), = lines(session, "warn")
    assert text.startswith(f"the report was not copied to {gone}: ")
    assert not gone.exists()


@pytest.mark.skipif(os.name == "nt", reason="Windows gives a folder no mode bits")
def test_the_copy_is_as_private_as_the_report(session, archive, stand_in, tmp_path):
    import stat

    stand_in("ok")
    out = tmp_path / "copies"
    out.mkdir()
    session.settings = Settings(copy_to=out)
    folder = reportflow.build(session, archive)
    assert stat.S_IMODE((out / folder.name).stat().st_mode) == 0o700


def test_a_relative_home_still_gets_its_report(session, archive, stand_in, tmp_path, monkeypatch):
    # home = "pwn-broker" in config.toml: pwn-report runs in the archive's folder, so every path it
    # is given is whole
    from pwn_broker.paths import AppPaths

    stand_in("ok")
    monkeypatch.chdir(tmp_path)
    session.paths = AppPaths(opt=session.paths.opt, home=Path("home"))
    relative = Path("home") / "wrapped" / archive.name
    folder = reportflow.build(session, relative)
    assert lines(session, "warn") == []
    assert (tmp_path / "home" / "wrapped" / "2026-11-14_htb_forest.finished.report" / "report.md").is_file()
    assert folder is not None and folder.is_dir()


def test_a_copy_to_that_is_the_wrapped_folder_is_no_warning(session, archive, stand_in):
    # copy_to = wrapped/: the report is already there, as the archive is
    stand_in("ok")
    session.settings = Settings(copy_to=archive.parent)
    folder = reportflow.build(session, archive)
    assert folder is not None and folder.is_dir()
    assert lines(session, "warn") == []
    assert sorted(p.name for p in archive.parent.iterdir()) == sorted([archive.name, folder.name, "ran.json"])


def test_a_part_folder_left_by_a_stopped_copy_is_no_obstacle(session, archive, stand_in, tmp_path):
    # the power went during an earlier copy: its .part folder is replaced, as the archive's .part is
    stand_in("ok")
    out = tmp_path / "copies"
    left = out / "2026-11-14_htb_forest.finished.report.part"
    left.mkdir(parents=True)
    (left / "report.md").write_text("half a copy")
    session.settings = Settings(copy_to=out)
    folder = reportflow.build(session, archive)
    copy = out / folder.name
    assert lines(session, "warn") == []
    assert (copy / "report.md").read_text() == "# a report\n"
    assert not list(out.glob("*.part"))


def test_the_report_is_built_in_the_archive_folder(session, archive, stand_in):
    import json

    stand_in("ok")
    reportflow.build(session, archive)
    ran = json.loads((archive.parent / "ran.json").read_text())
    assert Path(ran["cwd"]) == archive.parent
    assert ran["argv"] == ["build", str(archive), "-o", str(archive.parent / "2026-11-14_htb_forest.finished.report")]


def test_a_stopped_report_has_ended_before_finish_goes_on(session, archive, stand_in, monkeypatch):
    stand_in("slow")
    seen = []
    real_end = reportflow._end

    def stopped(process, timeout):
        seen.append(process)
        raise KeyboardInterrupt

    monkeypatch.setattr(reportflow, "_wait", stopped)
    monkeypatch.setattr(reportflow, "KILL_AFTER", 1)
    monkeypatch.setattr(reportflow, "_end", real_end)
    assert reportflow.build(session, archive) is None
    (process,) = seen
    assert process.poll() is not None
