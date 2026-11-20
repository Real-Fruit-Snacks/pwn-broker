from pwn_broker.note import FOLD_END, FOLD_START
from pwn_broker.playbooks import template_lines
from toolkit import built_playbook

BODY = "## Null session\nnxc smb <TargetIP>\nnxc smb 10.10.10.161\nplain prose\n"


def numbered(text):
    return {n: line for n, line in enumerate(text.splitlines(), start=1)}


def test_template_lines():
    text = "before <TargetIP>\n" + built_playbook("smb", "SMB", "02-enum/smb", ["<TargetIP>"], BODY) + "after <TargetIP>\n"
    lines = numbered(text)
    skipped = {lines[n] for n in template_lines(text.splitlines())}
    assert skipped == {
        "my",
        "/^END OF smb PLAYBOOK$",
        "mz",
        ":'y,'zs/<TargetIP>/<Replace>/ge",
        "'y",
        "Fill in:  <TargetIP>",
        "nxc smb <TargetIP>",
    }
    assert "nxc smb 10.10.10.161" not in skipped and "plain prose" not in skipped
    numbers = template_lines(text.splitlines())
    for n, line in lines.items():
        if line in (FOLD_START, FOLD_END) or line.startswith("Playbook: ") or line.startswith(("before", "after")):
            assert n not in numbers


def test_template_lines_finds_a_playbook_inside_a_target_fold():
    text = (
        f"{FOLD_START}\nTarget: dc01   10.10.10.161   -   external\n"
        + built_playbook("smb", "SMB", "02-enum/smb", ["<TargetIP>"], BODY)
        + f"dc01 <TargetIP> note of my own\n{FOLD_END}\n"
    )
    lines = numbered(text)
    skipped = {lines[n] for n in template_lines(text.splitlines())}
    assert "nxc smb <TargetIP>" in skipped
    assert "dc01 <TargetIP> note of my own" not in skipped


def test_template_lines_without_playbooks_is_empty():
    assert template_lines([FOLD_START, "Target: a", "<TargetIP>", FOLD_END]) == set()
