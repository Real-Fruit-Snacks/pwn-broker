import os
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone

import pytest

from conftest import NOW, make_cred
from pwn_broker.boxes import (
    TARGET_FOLDERS,
    BoxError,
    acquire_open,
    add_target,
    create_box,
    edit_target,
    find_target,
    list_boxes,
    open_box_folder,
    parse_values,
    pid_alive,
    release_open,
    remove_target,
    rename_target,
)
from pwn_broker.model import FileRecord
from pwn_broker.store import (
    StoreError,
    load_box,
    load_creds,
    load_files,
    load_targets,
    save_box,
    save_creds,
    save_files,
)


def yes(pid):
    return True


def no(pid):
    return False


def make(paths, name="Forest", day=date(2026, 11, 14), now=NOW, new_id=lambda: "id-1"):
    return create_box(
        paths, name=name, platform="htb", day=day, os_name="windows",
        difficulty="easy", now=now, new_id=new_id,
    )  # fmt: skip


def add(box, targets, name, ips=("10.0.0.1",), hostnames=(), scope="external"):
    return add_target(
        box, targets, ips=list(ips), hostnames=list(hostnames), scope=scope, name=name, now=NOW
    )


def test_create_box_layout(paths):
    box = make(paths)
    assert box.path == paths.active / "2026-11-14_htb_forest"
    assert box.id == "id-1" and box.status == "active" and box.started == NOW
    for sub in ("lists", "screenshots", "targets"):
        assert (box.path / sub).is_dir()
    assert load_box(box.path) == box


def test_create_box_name_collision(paths):
    first = make(paths)
    second = make(paths, new_id=lambda: "id-2")
    assert second.path == paths.active / "2026-11-14_htb_forest-2"
    assert first.path.is_dir() and second.path.is_dir()


def test_create_box_other_day_keeps_time_and_zone(paths):
    box = make(paths, day=date(2026, 11, 10))
    assert box.started == datetime(2026, 11, 10, 12, 0, tzinfo=timezone(timedelta(hours=2)))
    assert box.path.name.startswith("2026-11-10_")


def test_create_box_default_id_is_unique(paths):
    ids = {
        create_box(
            paths, name=n, platform="htb", day=NOW.date(), os_name="linux",
            difficulty="easy", now=NOW,
        ).id
        for n in ("a", "b")
    }  # fmt: skip
    assert len(ids) == 2 and all(len(i) == 36 for i in ids)


def test_create_box_rejects_unusable_name(paths):
    with pytest.raises(BoxError):
        make(paths, name="///")


def test_add_target_creates_folders_and_metadata(box):
    t = add(box, [], "dc01", ips=["10.10.10.161"], hostnames=["forest.htb.local"])
    for sub in TARGET_FOLDERS:
        assert (box.path / "targets" / "dc01" / sub).is_dir()
    assert t.box_id == box.id and t.box == box.name
    assert load_targets(box) == [t]


def test_target_name_defaults(box):
    targets = []
    a = add(box, targets, None, hostnames=["Web.Example.com", "x"], scope="internal")
    b = add(box, targets, None, ips=["10.0.0.2"], scope="internal")
    assert a.name == "web.example.com" and b.name == "10.0.0.2"
    assert targets == [a, b]


def test_target_needs_ip_or_hostname(box):
    with pytest.raises(BoxError):
        add(box, [], "x", ips=[])


def test_target_rejects_bad_ip_scope_and_duplicate_name(box):
    targets = []
    with pytest.raises(BoxError):
        add(box, targets, "a", ips=["10.10.10.999"])
    with pytest.raises(BoxError):
        add(box, targets, "a", scope="dmz")
    add(box, targets, "dc01")
    with pytest.raises(BoxError):
        add(box, targets, "dc01", ips=["10.0.0.2"])
    assert len(targets) == 1


def test_parse_values():
    assert parse_values("  a  b\tc ") == ["a", "b", "c"] and parse_values("") == []


def test_edit_target_changes_addresses(box, dc01):
    t = edit_target(box, [dc01], "dc01", ips=["10.0.0.5", "fe80::1"], hostnames=[], scope="internal")
    assert t.name == "dc01" and (box.path / "targets/dc01").is_dir()
    saved = load_targets(box)[0]
    assert saved.ips == ["10.0.0.5", "fe80::1"] and saved.hostnames == []
    assert saved.scope == "internal"


def test_edit_target_validates(box, dc01):
    with pytest.raises(BoxError):
        edit_target(box, [dc01], "dc01", ips=[], hostnames=[], scope="internal")
    assert load_targets(box)[0].ips == ["10.10.10.161"]


def test_rename_target_everywhere(box, dc01):
    targets = [dc01]
    box.last_target = "dc01"
    save_box(box)
    save_creds(box, [
        make_cred(found_on="dc01", works_on=["dc01", "web"]),
        make_cred(n=2, found_on="web", works_on=["web"]),
    ])  # fmt: skip
    save_files(box, [
        FileRecord(path="targets/dc01/loot/a.txt", target="dc01", first_seen=NOW, size=1, mtime=1.0, sha256="x"),
        FileRecord(path="lists/dc01-notes.txt", target="web", first_seen=NOW, size=1, mtime=1.0, sha256="y"),
    ])  # fmt: skip
    (box.path / "targets/dc01/loot/a.txt").write_text("a")

    t = rename_target(box, targets, "dc01", "DC")
    assert t.name == "dc" and targets == [t]
    assert not (box.path / "targets/dc01").exists()
    assert (box.path / "targets/dc/loot/a.txt").read_text() == "a"
    assert load_targets(box)[0].name == "dc"
    assert box.last_target == "dc" and load_box(box.path).last_target == "dc"
    creds = load_creds(box)
    assert creds[0].found_on == "dc" and creds[0].works_on == ["dc", "web"]
    assert creds[1].found_on == "web"
    files = load_files(box)
    assert files[0].path == "targets/dc/loot/a.txt" and files[0].target == "dc"
    assert files[1].path == "lists/dc01-notes.txt" and files[1].target == "web"


def test_rename_target_refuses_existing_name(box, dc01):
    web = add(box, [dc01], "web", ips=["10.0.0.2"])
    with pytest.raises(BoxError):
        rename_target(box, [dc01, web], "dc01", "web")
    assert (box.path / "targets/dc01").is_dir()


def test_rename_target_updates_the_given_creds_list(box, dc01):
    save_creds(box, [make_cred(found_on="other", works_on=[])])
    creds = [make_cred(found_on="dc01", works_on=["web", "dc01"])]
    rename_target(box, [dc01], "dc01", "dc", creds=creds)
    assert (creds[0].found_on, creds[0].works_on) == ("dc", ["web", "dc"])
    assert load_creds(box) == creds


def test_rename_target_refuses_a_folder_already_on_disk(box, dc01):
    (box.path / "targets/dc").mkdir()
    with pytest.raises(BoxError, match="dc"):
        rename_target(box, [dc01], "dc01", "dc")
    assert (box.path / "targets/dc01").is_dir() and dc01.name == "dc01"


@pytest.mark.parametrize("broken", ["creds.toml", "files.toml"])
def test_rename_target_stops_before_moving_on_corrupt_metadata(box, dc01, broken):
    (box.path / broken).write_text("= broken", encoding="utf-8")
    with pytest.raises(StoreError, match=broken):
        rename_target(box, [dc01], "dc01", "dc")
    assert (box.path / "targets/dc01").is_dir() and not (box.path / "targets/dc").exists()
    assert dc01.name == "dc01" and load_targets(box)[0].name == "dc01"


def test_remove_empty_target(box, dc01):
    targets = [dc01]
    remove_target(box, targets, "dc01")
    assert targets == [] and not (box.path / "targets/dc01").exists()


def test_remove_refuses_target_with_files(box, dc01):
    targets = [dc01]
    (box.path / "targets/dc01/loot/SAM.bak").write_text("x")
    with pytest.raises(BoxError, match="loot/SAM.bak"):
        remove_target(box, targets, "dc01")
    assert (box.path / "targets/dc01").is_dir() and targets == [dc01]


def test_remove_lists_at_most_five_files(box, dc01):
    for i in range(7):
        (box.path / f"targets/dc01/loot/f{i}").write_text("x")
    with pytest.raises(BoxError) as info:
        remove_target(box, [dc01], "dc01")
    assert "7" in str(info.value) and "f5" not in str(info.value)


def test_find_target(box):
    targets = []
    for name in ("dc01", "dc02", "web"):
        add(box, targets, name)
    assert find_target(targets, "dc01").name == "dc01"
    assert find_target(targets, "we").name == "web"
    for bad in ("dc", "zzz", "DC01", ""):
        with pytest.raises(BoxError):
            find_target(targets, bad)


def test_list_boxes_skips_unreadable(paths):
    good = make(paths)
    bad = paths.active / "2026-11-14_htb_broken"
    bad.mkdir()
    (bad / "box.toml").write_text('schema = 1\nid = "x')
    (paths.active / "2026-11-14_htb_empty").mkdir()
    (paths.active / ".hidden").mkdir()
    boxes, problems = list_boxes(paths)
    assert boxes == [good]
    assert len(problems) == 2
    assert any("broken" in p for p in problems) and any("empty" in p for p in problems)


def test_list_boxes_sorted_and_missing_folder(paths):
    assert list_boxes(paths) == ([], [])
    late = make(paths, name="late", now=NOW + timedelta(hours=1), new_id=lambda: "l")
    early = make(paths, name="early", new_id=lambda: "e")
    assert list_boxes(paths)[0] == [early, late]


def test_lock_blocks_second_box(paths, box, other):
    acquire_open(paths, box, pid=100, alive=yes)
    with pytest.raises(BoxError, match="forest"):
        acquire_open(paths, other, pid=200, alive=yes)


def test_lock_same_pid_same_box_succeeds(paths, box):
    acquire_open(paths, box, pid=100, alive=yes)
    acquire_open(paths, box, pid=100, alive=yes)
    assert open_box_folder(paths, alive=yes) == box.path


def test_stale_lock_is_taken_over(paths, box, other):
    acquire_open(paths, box, pid=100, alive=yes)
    acquire_open(paths, other, pid=200, alive=no)
    assert open_box_folder(paths, alive=yes) == other.path


def test_corrupt_lock_is_replaced(paths, box):
    paths.run.mkdir(parents=True)
    (paths.run / "open.toml").write_text('box_id = "tr')
    assert open_box_folder(paths, alive=yes) is None
    acquire_open(paths, box, pid=100, alive=yes)
    assert open_box_folder(paths, alive=yes) == box.path


def test_open_box_folder_none_when_dead_or_missing(paths, box):
    assert open_box_folder(paths, alive=yes) is None
    acquire_open(paths, box, pid=100, alive=yes)
    assert open_box_folder(paths, alive=no) is None


def test_release_only_by_owner(paths, box):
    acquire_open(paths, box, pid=100, alive=yes)
    release_open(paths, pid=999)
    assert open_box_folder(paths, alive=yes) == box.path
    release_open(paths, pid=100)
    assert open_box_folder(paths, alive=yes) is None
    release_open(paths, pid=100)


def test_release_without_run_folder(paths):
    release_open(paths, pid=1)
    assert open_box_folder(paths, alive=yes) is None


@pytest.mark.skipif(sys.platform == "win32", reason="uses os.kill")
def test_pid_alive_posix():
    assert pid_alive(os.getpid())
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    # reaped, so the pid names no process (reuse this soon is vanishingly unlikely)
    assert pid_alive(child.pid) is False


@pytest.mark.skipif(sys.platform != "win32", reason="windows only")
def test_pid_alive_never_signals_on_windows():
    assert pid_alive(os.getpid()) is False


def test_target_contents_lists_files_but_not_target_toml(box, dc01):
    from pwn_broker.boxes import ensure_removable, target_contents

    assert target_contents(box, "dc01") == []
    ensure_removable(box, "dc01")
    (box.path / "targets" / "dc01" / "loot" / "a.txt").write_text("x")
    assert target_contents(box, "dc01") == ["loot/a.txt"]
    with pytest.raises(BoxError, match="still has 1 file"):
        ensure_removable(box, "dc01")


def test_rename_target_renames_its_hosts_entry(box, dc01):
    box.hosts = ["dc01", "web"]
    save_box(box)
    rename_target(box, [dc01], "dc01", "dc")
    assert box.hosts == ["dc", "web"] and load_box(box.path).hosts == ["dc", "web"]


def test_rename_target_without_a_hosts_entry_leaves_hosts(box, dc01):
    box.hosts = ["web"]
    save_box(box)
    rename_target(box, [dc01], "dc01", "dc")
    assert load_box(box.path).hosts == ["web"]


def test_remove_target_drops_its_hosts_entry(box, dc01):
    box.hosts = ["dc01", "web"]
    save_box(box)
    remove_target(box, [dc01], "dc01")
    assert box.hosts == ["web"] and load_box(box.path).hosts == ["web"]
