"""Playbooks read into the note: which of their lines are still template text."""

import re

from pwn_broker.note import FOLD_END, FOLD_START

# the same pattern the note's highlighting colours: a capital letter, then single spaces between
# words, as in <TargetIP> or <Target Host>
PLACEHOLDER = re.compile(r"<[A-Z][0-9A-Za-z_-]*(?: [0-9A-Za-z_-]+)*>")
PLAYBOOK_PREFIX = "Playbook: "
# the first and last lines of a playbook's run block
RUN_BLOCK_START = "my"
RUN_BLOCK_END = "'y"


def _end(lines: list[str], start: int) -> int:
    """The index of the fold end matching the fold start at `start`, or the last line."""
    depth = 0
    for n in range(start, len(lines)):
        stripped = lines[n].strip()
        if stripped == FOLD_START:
            depth += 1
        elif stripped == FOLD_END:
            depth -= 1
            if depth == 0:
                return n
    return len(lines) - 1


def template_lines(lines: list[str]) -> set[int]:
    """The 1-based numbers of the note's lines that are still a playbook's template text: each
    playbook's run block, and any other line of a playbook that still holds a placeholder."""
    found: set[int] = set()
    n = 0
    while n < len(lines) - 1:
        if lines[n].strip() != FOLD_START or not lines[n + 1].startswith(PLAYBOOK_PREFIX):
            n += 1
            continue
        end = _end(lines, n)
        # a run block is there only while its first line follows the Playbook: line and its last
        # line is still in the playbook; once deleted, only the placeholder rule applies
        m = n + 1
        if n + 2 < end and lines[n + 2] == RUN_BLOCK_START and RUN_BLOCK_END in lines[n + 2 : end]:
            m = lines.index(RUN_BLOCK_END, n + 2)
            found.update(range(n + 3, m + 2))
        for k in range(m + 1, end):
            if lines[k].strip() not in (FOLD_START, FOLD_END) and PLACEHOLDER.search(lines[k]):
                found.add(k + 1)
        n = end + 1
    return found
