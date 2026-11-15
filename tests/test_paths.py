from datetime import date

import pytest

from pwn_broker.paths import AppPaths, box_folder_name, safe_name


def test_safe_name():
    assert safe_name("My Box") == "my-box"
    assert safe_name("../etc") == "etc"
    assert safe_name("dc01.forest.htb") == "dc01.forest.htb"
    assert safe_name("10.10.10.161") == "10.10.10.161"
    assert safe_name("a_b") == "a-b"
    with pytest.raises(ValueError):
        safe_name("///")


def test_box_folder_name():
    assert box_folder_name(date(2026, 11, 14), "HTB", "Forest") == "2026-11-14_htb_forest"


def test_tool_folders(tmp_path):
    paths = AppPaths(opt=tmp_path / "o", home=tmp_path / "h")
    o = tmp_path / "o"
    assert paths.tools == o / "tools" and paths.upload == o / "upload"
    assert paths.cache == o / "cache" and paths.tools_state == o / "tools" / "installed.toml"
    assert paths.run_box == o / "run" / "box" and paths.run_tools == o / "run" / "tools"


def test_recording_and_vpn_paths(tmp_path):
    paths = AppPaths(opt=tmp_path / "o", home=tmp_path / "h")
    o = tmp_path / "o"
    assert paths.run_recordings == o / "run" / "recordings"
    assert paths.run_vpn == o / "run" / "vpn"
    assert paths.run_shell == o / "run" / "shell"
    assert paths.run_asciinema == o / "run" / "asciinema"
    assert paths.box_lock == o / "run" / "box.lock"
    assert paths.asciinema == o / "app" / "bin" / "asciinema"
    assert paths.record_launcher == o / "bin" / "record"
