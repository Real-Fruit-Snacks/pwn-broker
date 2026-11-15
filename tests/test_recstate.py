import pytest

from pwn_broker import recstate
from pwn_broker.recstate import Recording


def cast_in(box, target="dc01", name="2026-11-14_1432.cast", data=b"{}\n"):
    path = box.path / "targets" / target / "recordings" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def test_mark_writes_start_target_and_cast(paths, box):
    cast = cast_in(box)
    marker = recstate.mark(paths, 4242, "777", "dc01", cast)
    assert marker == paths.run_recordings / "4242"
    assert marker.read_text(encoding="utf-8") == f"777\ndc01\n{cast}\n"


def test_clear_removes_the_marker_and_a_missing_one_is_fine(paths, box):
    recstate.mark(paths, 4242, "777", "dc01", cast_in(box))
    recstate.clear(paths, 4242)
    assert not (paths.run_recordings / "4242").exists()
    recstate.clear(paths, 4242)


def test_a_line_break_cannot_go_in_a_marker(paths, box):
    with pytest.raises(OSError):
        recstate.mark(paths, 4242, "777", "dc01", box.path / "a\nb.cast")
    assert not (paths.run_recordings / "4242").exists()


def test_recording_lists_live_markers(paths, box):
    cast = cast_in(box)
    recstate.mark(paths, 4242, "777", "dc01", cast)
    found = recstate.recording(paths, alive=lambda pid: True, started=lambda pid: "777")
    assert found == [Recording(4242, "dc01", cast)]


def test_no_folder_means_nothing_is_recording(paths):
    assert recstate.recording(paths, alive=lambda pid: True, started=lambda pid: "1") == []


def test_a_marker_whose_window_is_gone_is_dropped(paths, box):
    # Review focus 4: a killed window leaves its marker behind
    recstate.mark(paths, 4242, "777", "dc01", cast_in(box))
    assert recstate.recording(paths, alive=lambda pid: False, started=lambda pid: "777") == []
    assert not (paths.run_recordings / "4242").exists()


def test_a_reused_process_id_is_dropped(paths, box):
    # Review focus 4: the window died and another program now has its process ID
    recstate.mark(paths, 4242, "777", "dc01", cast_in(box))
    assert recstate.recording(paths, alive=lambda pid: True, started=lambda pid: "999") == []
    assert not (paths.run_recordings / "4242").exists()


def test_a_start_time_that_cannot_be_read_keeps_the_marker(paths, box):
    cast = cast_in(box)
    recstate.mark(paths, 4242, "777", "dc01", cast)
    recstate.mark(paths, 4243, "", "dc01", cast)
    found = recstate.recording(paths, alive=lambda pid: True, started=lambda pid: None)
    assert [r.pid for r in found] == [4242, 4243]


def test_a_damaged_marker_is_dropped(paths):
    paths.run_recordings.mkdir(parents=True)
    (paths.run_recordings / "4242").write_text("777\ndc01\n", encoding="utf-8")
    (paths.run_recordings / "0").write_text("777\ndc01\n/x.cast\n", encoding="utf-8")
    assert recstate.recording(paths, alive=lambda pid: True, started=lambda pid: "777") == []
    assert sorted(paths.run_recordings.iterdir()) == []


def test_a_file_that_is_not_a_marker_is_left_alone(paths, box):
    # a marker half way through being written has a temporary name
    paths.run_recordings.mkdir(parents=True)
    other = paths.run_recordings / ".pwn-broker-abc.tmp"
    other.write_text("x", encoding="utf-8")
    assert recstate.recording(paths, alive=lambda pid: True, started=lambda pid: "1") == []
    assert other.exists()


def test_with_a_box_only_its_casts_are_listed(paths, box, other):
    mine = cast_in(box)
    theirs = cast_in(other)
    recstate.mark(paths, 4242, "777", "dc01", mine)
    recstate.mark(paths, 4243, "777", "dc01", theirs)
    found = recstate.recording(paths, box, alive=lambda pid: True, started=lambda pid: "777")
    assert found == [Recording(4242, "dc01", mine)]
    # the other box's window is still recording: its marker stays
    assert (paths.run_recordings / "4243").exists()


def test_live_casts_gives_the_size_up_to_the_last_whole_line(paths, box):
    cast = cast_in(box, data=b'{"version": 3}\n[0.1, "o", "a"]\n[0.2, "o"')
    recstate.mark(paths, 4242, "777", "dc01", cast)
    live = recstate.live_casts(paths, box, alive=lambda pid: True, started=lambda pid: "777")
    assert live == {"targets/dc01/recordings/2026-11-14_1432.cast": len(b'{"version": 3}\n[0.1, "o", "a"]\n')}


def test_live_casts_leaves_out_a_cast_that_has_vanished(paths, box):
    gone = cast_in(box, name="gone.cast")
    kept = cast_in(box, name="kept.cast", data=b"{}\n")
    recstate.mark(paths, 4242, "777", "dc01", gone)
    recstate.mark(paths, 4243, "777", "dc01", kept)
    gone.unlink()
    live = recstate.live_casts(paths, box, alive=lambda pid: True, started=lambda pid: "777")
    assert live == {"targets/dc01/recordings/kept.cast": 3}


def test_live_casts_of_a_box_with_nothing_recording(paths, box):
    assert recstate.live_casts(paths, box, alive=lambda pid: True, started=lambda pid: "1") == {}



@pytest.mark.parametrize(
    "seconds, shown",
    [(-5, "under a minute"), (0, "under a minute"), (59.9, "under a minute"), (60, "1 min"), (899, "14 min")],
)
def test_length_counts_whole_minutes(seconds, shown):
    assert recstate.length(seconds) == shown
