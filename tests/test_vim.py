"""The packaged vimrc run by a real vim, headless (-es), on a note the app rendered.

Ex mode never reaches vim's main loop, so timers, focus events and TextChanged do not fire on their
own: the scripts call the vimrc's check function or run :checktime by hand.
"""

import json
import shutil
import subprocess
from dataclasses import replace
from importlib import resources
from pathlib import Path

import pytest

from helpers import NOW
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker.config import Settings
from pwn_broker.console import FakeConsole
from pwn_broker.note import FOLD_END, FOLD_START, render_note, title_text, update_box
from pwn_broker.session import Session

pytestmark = pytest.mark.skipif(shutil.which("vim") is None, reason="vim not installed")

DATA = resources.files("pwn_broker.data")
VIMRC = Path(str(DATA.joinpath("vimrc")))
TEMPLATE = DATA.joinpath("notes.md").read_text(encoding="utf-8")

PRELUDE = r"""
let g:out = {}
function! Put(name, value) abort
  let g:out[a:name] = a:value
endfunction
function! Find(pattern) abort
  return search(a:pattern, 'nw')
endfunction
" calls a function the vimrc keeps to itself
function! Script(name, ...) abort
  return call(function('<SNR>' . getscriptinfo({'name': 'data/vimrc$'})[0].sid . '_' . a:name), a:000)
endfunction
" every fold start in order: open, closed, or hidden inside a closed fold
function! Folds() abort
  let found = []
  for n in range(1, line('$'))
    if stridx(getline(n), g:pwn_fold_start) >= 0
      let c = foldclosed(n)
      call add(found, c == -1 ? 'open' : c == n ? 'closed' : 'hidden')
    endif
  endfor
  return found
endfunction
"""


def run_vim(folder: Path, work: Path, script: str) -> dict:
    """Opens folder/notes.md in vim with the packaged vimrc, runs script, returns what it Put."""
    out = work / "out.json"
    out.unlink(missing_ok=True)
    source = work / "check.vim"
    source.write_text(
        PRELUDE + script + f"\ncall writefile([json_encode(g:out)], '{out.as_posix()}')\nqa!\n",
        encoding="utf-8",
    )
    argv = ["vim", "-u", VIMRC.as_posix(), "-N", "-es", "-S", source.as_posix(), (folder / "notes.md").as_posix()]
    proc = subprocess.Popen(
        argv, cwd=folder, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    try:
        _, err = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, err = proc.communicate()
        pytest.fail(f"vim did not finish within 30 seconds: {err.decode(errors='replace')}")
    assert out.exists(), f"vim wrote no results (exit {proc.returncode}): {err.decode(errors='replace')}"
    return json.loads(out.read_text(encoding="utf-8"))


NESTED = f"{FOLD_START}\nnested title\nnested body 10.10.10.99\n{FOLD_END}\n"


@pytest.fixture
def web(dc01):
    return replace(dc01, name="web", ips=["10.10.10.5"], hostnames=[], scope="internal")


@pytest.fixture
def note(box, dc01, web):
    text = render_note(TEMPLATE, box, [dc01, web])
    dc01_part, web_part = text.split("Target: web", 1)
    dc01_part = dc01_part.replace(
        "## enumeration\n", "## enumeration\nlogin as <DomainUser> on 10.10.10.77/24 then\n", 1
    ).replace("## foothold\n", "## foothold\n" + NESTED, 1)
    web_part = web_part.replace("## foothold\n", "## foothold\n" + NESTED, 1)
    text = dc01_part + "Target: web" + web_part
    text += f"\n{FOLD_START}\n\nonly a body\n{FOLD_END}\n\n{FOLD_START}\n{FOLD_END}\n"
    (box.path / "notes.md").write_text(text, encoding="utf-8", newline="")
    return text


@pytest.fixture
def work(tmp_path):
    folder = tmp_path / "vim-work"
    folder.mkdir()
    return folder


def test_settings(box, note, work):
    got = run_vim(box.path, work, r"""
for name in ['number', 'modeline', 'swapfile', 'backup', 'writebackup', 'hlsearch', 'autoread',
           \ 'updatetime', 'foldmethod', 'foldmarker', 'fillchars', 'foldlevel', 'filetype',
           \ 'expandtab', 'shiftwidth', 'softtabstop', 'scrolloff', 'laststatus', 'belloff']
  call Put(name, eval('&' . name))
endfor
call Put('mapleader', g:mapleader)
call Put('leader_maps', execute('map <Leader>') . execute('imap <Leader>'))
call Put('F8n', maparg('<F8>', 'n'))
call Put('F8i', maparg('<F8>', 'i'))
call Put('statusline_bg', synIDattr(hlID('StatusLine'), 'bg#', 'gui'))
call Put('folded_fg', synIDattr(hlID('Folded'), 'fg#', 'gui'))
call Put('folded_bg', synIDattr(hlID('Folded'), 'bg#', 'gui'))
call Put('normal_bg', synIDattr(hlID('Normal'), 'bg#', 'gui'))
""")
    assert got["number"] == 0 and got["modeline"] == 0
    assert got["swapfile"] == 0 and got["backup"] == 0 and got["writebackup"] == 0
    assert got["hlsearch"] == 0 and got["autoread"] == 0 and got["updatetime"] == 1000
    assert got["mapleader"] == ","
    assert "No mapping found" in got["leader_maps"] and "<Leader>" not in got["leader_maps"].replace("No mapping found", "")
    assert got["foldmethod"] == "marker"
    assert got["foldmarker"] == f"{FOLD_START},{FOLD_END}"
    assert "fold: " in got["fillchars"]
    assert got["foldlevel"] == 0
    assert got["filetype"] == "pwnnote"
    assert (got["expandtab"], got["shiftwidth"], got["softtabstop"]) == (1, 4, 4)
    assert (got["scrolloff"], got["laststatus"], got["belloff"]) == (3, 2, "all")
    assert "NewFold(0)" in got["F8n"] and "NewFold(1)" in got["F8i"]
    assert got["statusline_bg"].upper() == "#13151A"
    assert (got["folded_fg"].upper(), got["folded_bg"].upper()) == ("#E8E6E1", "#1A1D24")
    assert got["normal_bg"].upper() == "#0C0D10"


def test_target_folds_start_closed_and_show_their_title(box, note, work, dc01, web):
    got = run_vim(box.path, work, r"""
let box_end = 1
while getline(box_end + 1) =~# '^#' | let box_end += 1 | endwhile
call Put('box_end', box_end)
call Put('box_folded', map(range(1, box_end), 'foldlevel(v:val)'))
for name in ['dc01', 'web']
  let title = Find('^Target: ' . name . ' ')
  call Put(name . '_closed', foldclosed(title))
  call Put(name . '_start', title - 1)
  call Put(name . '_text', foldtextresult(foldclosed(title)))
endfor
let empty = Find('^only a body$') - 2
call Put('empty_closed', foldclosed(empty))
call Put('empty_text', foldtextresult(empty))
call Put('bare_text', foldtextresult(line('$') - 1))
""")
    assert got["box_end"] == 11
    assert got["box_folded"] == [0] * 11
    for name, target in (("dc01", dc01), ("web", web)):
        assert got[f"{name}_closed"] == got[f"{name}_start"] > 11
        assert got[f"{name}_text"].rstrip() == "Target: " + title_text(target)
    assert got["empty_closed"] != -1
    assert got["empty_text"] == "(empty fold)"
    assert got["bare_text"] == "(empty fold)"


def test_a_nested_fold_folds_on_its_own(box, note, work):
    got = run_vim(box.path, work, r"""
let outer = Find('^Target: dc01 ') - 1
let inner = Find('^nested title$') - 1
call Put('inner_hidden', foldclosed(inner))
execute outer . 'foldopen'
call Put('outer_open', foldclosed(outer))
call Put('inner_closed', foldclosed(inner))
call Put('inner_text', foldtextresult(inner))
call Put('inner_level', foldlevel(inner))
call Put('outer', outer)
call Put('inner', inner)
""")
    assert got["inner_hidden"] == got["outer"]
    assert got["outer_open"] == -1
    assert got["inner_closed"] == got["inner"]
    assert got["inner_text"] == "nested title"
    assert got["inner_level"] == 2


@pytest.mark.parametrize("keys", [r"normal \<F8>", r"normal A\<F8>"], ids=["normal", "insert"])
def test_f8_inserts_an_open_empty_fold_below_the_line(box, note, work, keys):
    got = run_vim(box.path, work, r"""
let outer = Find('^Target: dc01 ') - 1
execute outer . 'foldopen'
let row = Find('^login as ')
call cursor(row, 3)
execute "KEYS"
call Put('row', row)
call Put('lines', getline(row, row + 4))
call Put('cursor', line('.'))
call Put('closed', foldclosed('.'))
call Put('outer_closed', foldclosed(outer))
call Put('level', foldlevel('.'))
""".replace("KEYS", keys))
    row = got["row"]
    assert got["lines"][1:4] == [FOLD_START, "", FOLD_END]
    assert got["lines"][0].startswith("login as ")
    assert got["lines"][4] == "" and got["lines"][0] == got["lines"][0].rstrip()
    assert got["cursor"] == row + 2
    assert got["closed"] == -1 and got["outer_closed"] == -1
    assert got["level"] == 2


RELOADS = {"check": "call Script('Check')", "checktime": "checktime"}

# opens dc01's fold, and the fold inside web, then closes web again around it
OPEN_FOLDS = r"""
let dc01 = Find('^Target: dc01 ') - 1
let web = Find('^Target: web ') - 1
execute dc01 . 'foldopen'
execute web . 'foldopen'
call cursor(web + 1, 1)
let web_inner = search('^nested title$', 'nW') - 1
execute web_inner . 'foldopen'
execute web . 'foldclose'
"""
AT_LOGIN = "call cursor(Find('^login as '), 10)\n"

AFTER = r"""
call Put('after', [line('.'), col('.'), getline('.'), line('$')])
call Put('after_folds', Folds())
call Put('box', getline(1, 20))
let web = Find('^Target: web ') - 1
execute web . 'foldopen'
call cursor(web + 1, 1)
let web_inner = search('^nested title$', 'nW') - 1
call Put('web_inner', foldclosed(web_inner))
call Put('modified', &modified)
"""

# dc01 open, the fold in it closed, web closed, the fold in web hidden, the two at the end closed
BEFORE_FOLDS = ["open", "closed", "closed", "hidden", "closed", "closed"]


def reload_vim(box: Path, work: Path, newer: str, how: str = "check", place: str = AT_LOGIN) -> dict:
    """Opens the note with folds set as in OPEN_FOLDS, writes newer over it from inside vim, and
    makes vim check the file the way `how` names."""
    source = work / "newer.md"
    source.write_text(newer, encoding="utf-8", newline="")
    script = (
        OPEN_FOLDS
        + place
        + "call Put('before', [line('.'), col('.'), getline('.'), line('$')])\n"
        + "call Put('before_folds', Folds())\n"
        + f"call writefile(readfile('{source.as_posix()}', 'b'), expand('%:p'), 'b')\n"
        + RELOADS[how]
        + AFTER
    )
    got = run_vim(box, work, script)
    assert got["before_folds"] == BEFORE_FOLDS
    assert got["modified"] == 0
    return got


def assert_same_text(got: dict, moved: int) -> None:
    line, col, text, _ = got["before"]
    assert got["after"][:3] == [line + moved, col, text]


@pytest.mark.parametrize("how", ["check", "checktime"])
@pytest.mark.parametrize("extra", [1, 2, 12])
def test_reload_after_the_box_grows_keeps_folds_and_cursor(box, note, work, dc01, web, how, extra):
    more = [replace(web, name=f"ws{i}", ips=[f"10.10.20.{i}"]) for i in range(extra)]
    got = reload_vim(box.path, work, update_box(note, box, [dc01, web, *more]), how)
    assert_same_text(got, extra)
    assert got["before"][2].startswith("login as <DomainUser>")
    assert got["after_folds"] == BEFORE_FOLDS
    assert any(row.startswith("#    ws0 ") for row in got["box"])
    # the fold inside web was opened before web was closed, and is still open inside it
    assert got["web_inner"] == -1


def test_reload_after_the_box_shrinks(box, note, work, dc01):
    got = reload_vim(box.path, work, update_box(note, box, [dc01]))
    assert_same_text(got, -1)
    assert got["after_folds"] == BEFORE_FOLDS


def test_reload_after_target_add_by_the_app(box, note, work, paths, dc01, web):
    from pwn_broker.shell.commands import dispatch

    session = Session(paths, Settings(), FakeConsole(["10.10.10.50", "", "", "web01"]), box, [dc01, web], [], dc01, lambda: NOW)
    dispatch(session, "target add")
    assert ("ok", "target web01 created") in session.console.lines
    path = box.path / "notes.md"
    added = path.read_text(encoding="utf-8")
    path.write_text(note, encoding="utf-8", newline="")
    got = reload_vim(box.path, work, added)
    assert_same_text(got, 1)
    assert got["after_folds"] == [*BEFORE_FOLDS, "closed"]
    assert got["after"][3] > got["before"][3] + 10
    assert got["web_inner"] == -1


def test_reload_after_an_append_at_the_end(box, note, work):
    got = reload_vim(box.path, work, note + "x\n\nmore\n")
    assert_same_text(got, 0)
    assert got["after"][3] == got["before"][3] + 3
    assert got["after_folds"] == BEFORE_FOLDS


def test_reload_with_the_cursor_in_the_box(box, note, work, dc01, web):
    more = [replace(web, name=f"ws{i}", ips=[f"10.10.20.{i}"]) for i in range(2)]
    got = reload_vim(box.path, work, update_box(note, box, [dc01, web, *more]), place="call cursor(3, 6)\n")
    assert got["before"][:2] == [3, 6]
    assert got["after"][:2] == [3, 6]
    assert got["after_folds"] == BEFORE_FOLDS


def test_unsaved_changes_are_not_reloaded_over(box, note, work, dc01, web):
    newer = work / "newer.md"
    newer.write_text(update_box(note, box, [dc01]), encoding="utf-8", newline="")
    got = run_vim(box.path, work, f"""
normal! Gotyped
let v:errmsg = ''
call writefile(readfile('{newer.as_posix()}', 'b'), expand('%:p'), 'b')
silent! call Script('Check')
call Put('last', getline('$'))
call Put('modified', &modified)
""")
    assert got["last"] == "typed" and got["modified"] == 1


def test_check_on_an_unchanged_note_is_cheap(box, work, dc01):
    text = render_note(TEMPLATE, box, [dc01])
    body = "".join(f"line {n} with 10.10.10.{n % 250} and <DomainUser>\n" for n in range(168))
    text += "".join(f"\n{FOLD_START}\nTarget: t{i}\n{body}{FOLD_END}\n" for i in range(29))
    (box.path / "notes.md").write_text(text, encoding="utf-8", newline="")
    got = run_vim(box.path, work, r"""
call Put('lines', line('$'))
call Put('folds', len(Folds()))
let start = reltime()
for i in range(200)
  call Script('Check')
endfor
call Put('ms', reltimefloat(reltime(start)) * 1000.0 / 200)
""")
    assert got["lines"] > 4900 and got["folds"] == 30
    assert got["ms"] < 5, got["ms"]


def test_highlighting(box, note, work):
    got = run_vim(box.path, work, r"""
function! Group(line, text) abort
  let col = stridx(getline(a:line), a:text) + 1
  let id = synID(a:line, col, 1)
  return [synIDattr(id, 'name'), synIDattr(synIDtrans(id), 'fg#', 'gui'), synIDattr(synIDtrans(id), 'bold', 'gui')]
endfunction
let box_row = Find('^#    dc01 ')
let title = Find('^Target: dc01 ')
let free = Find('^login as ')
let heading = Find('^## enumeration')
call Put('ip_box', Group(box_row, '10.10.10.161'))
call Put('ip_title', Group(title, '10.10.10.161'))
call Put('ip_free', Group(free, '10.10.10.77/24'))
call Put('ip_free_end', Group(free, '/24'))
call Put('placeholder', Group(free, '<DomainUser>'))
call Put('free_text', Group(free, 'login'))
call Put('rule', Group(1, '#'))
call Put('border_left', Group(2, '#'))
call Put('border_right', [synIDattr(synID(2, col([2, '$']) - 1, 1), 'name')])
call Put('box_label', Group(2, 'Box:'))
call Put('fold_start', Group(title - 1, '#'))
call Put('fold_end', Group(Find('^' . g:pwn_fold_end . '$'), '@'))
call Put('heading', Group(heading, 'enumeration'))
call Put('title_word', Group(title, 'Target:'))
call Put('title_rest', Group(title, 'dc01'))
let names = {}
for lnum in range(1, line('$'))
  for col in range(1, max([1, col([lnum, '$']) - 1]))
    for id in synstack(lnum, col)
      let names[synIDattr(id, 'name')] = 1
    endfor
  endfor
endfor
call Put('all_groups', sort(keys(names)))
""")
    amber, ember, mute, text = "#FFC247", "#FF6A3D", "#8A8F99", "#E8E6E1"
    for key in ("ip_box", "ip_title", "ip_free", "ip_free_end"):
        assert got[key][:2] == ["pwnnoteIP", amber.lower()] or [got[key][0], got[key][1].upper()] == ["pwnnoteIP", amber], key
    assert [got["placeholder"][0], got["placeholder"][1].upper()] == ["pwnnotePlaceholder", ember]
    assert got["free_text"][0] == ""
    for key in ("rule", "border_left", "fold_start", "fold_end"):
        assert got[key][1].upper() == mute, key
    assert got["border_right"] == ["pwnnoteBorder"]
    assert got["box_label"][0] == "pwnnoteBox" and got["box_label"][2] == ""
    assert got["heading"][0] == "pwnnoteHeading" and got["heading"][1].upper() == text and got["heading"][2] == "1"
    assert got["title_word"][0] == "pwnnoteTitle" and got["title_word"][2] == "1"
    assert got["title_rest"][0] == ""
    assert not [name for name in got["all_groups"] if name.lower().startswith("markdown")]
    assert set(got["all_groups"]) <= {
        "pwnnoteIP", "pwnnotePlaceholder", "pwnnoteBox", "pwnnoteBorder", "pwnnoteRule",
        "pwnnoteFoldMarker", "pwnnoteHeading", "pwnnoteTitle",
    }  # fmt: skip
    colours = (Path(str(DATA.joinpath("nightshift.vim"))).read_text(encoding="utf-8")).upper()
    assert "#3DDC97" not in colours


def test_vim_leaves_nothing_but_the_note_in_the_box_folder(box, note, work):
    before = sorted(p.name for p in box.path.iterdir())
    got = run_vim(box.path, work, r"""
call Put('swap', swapname('%'))
normal! Goone more line
write
call Put('state', readfile(expand('%:p:h') . '/.note-state'))
""")
    assert got["swap"] == ""
    assert got["state"] == ["0"]
    assert sorted(p.name for p in box.path.iterdir()) == before
    assert (box.path / "notes.md").read_text(encoding="utf-8").endswith("one more line\n")


@pytest.mark.parametrize("event", ["FocusLost", "CursorHold", "CursorHoldI"])
def test_a_save_the_vimrc_makes_by_itself_clears_the_unsaved_mark(box, note, work, event):
    # the vimrc saves the note when its window loses focus or goes quiet. That save has to count
    # as one: finish refuses a note whose mark says it has unsaved changes
    got = run_vim(box.path, work, rf"""
normal! Gotyped by hand
doautocmd <nomodeline> TextChanged
call Put('typed', readfile(expand('%:p:h') . '/.note-state'))
doautocmd <nomodeline> {event}
call Put('modified', &modified)
call Put('saved', readfile(expand('%:p:h') . '/.note-state'))
""")
    assert got["typed"] == ["1"]
    assert got["modified"] == 0
    assert (box.path / "notes.md").read_text(encoding="utf-8").endswith("typed by hand\n")
    assert got["saved"] == ["0"]


IP_YES = ["10.10.10.161", "10.10.10.0/24", "(10.10.10.161)", "10.10.10.161:445", "http://10.10.10.161/", "0.0.0.0/0", "255.255.255.255/32"]
IP_NO = ["1.2.3.4.5", "999.999.999.999", "10.10.10.256", "1.2.3.4.5.6"]
PLACEHOLDER_YES = ["<DomainUser>", "<IP>", "<Target Host>", "<Password_1>", "<Dc-01 Name>"]
PLACEHOLDER_NO = ["cat <input >out", "<a href>", "<ports>", "</port>", "<!-- x -->", "<html>", "< User>", "<User >", "<Two  Spaces>"]


def _spans(box, work, cases: list[str], group: str) -> dict:
    """For each case, on a line of its own, the columns vim gives `group`."""
    text = render_note(TEMPLATE, box, []) + "".join(f"seen {case} here\n" for case in cases)
    (box.path / "notes.md").write_text(text, encoding="utf-8", newline="")
    got = run_vim(box.path, work, r"""
let found = {}
for lnum in range(1, line('$'))
  let line = getline(lnum)
  if line !~# '^seen '
    continue
  endif
  let cols = []
  for col in range(1, len(line))
    if index(map(synstack(lnum, col), 'synIDattr(v:val, "name")'), 'GROUP') >= 0
      call add(cols, col)
    endif
  endfor
  let found[line[5:-6]] = cols
endfor
call Put('found', found)
""".replace("GROUP", group))
    return got["found"]


def _expected(case: str, part: str) -> list[int]:
    start = len("seen ") + case.index(part) + 1
    return list(range(start, start + len(part)))


def test_ip_addresses_coloured_only_when_real(box, work):
    found = _spans(box, work, IP_YES + IP_NO, "pwnnoteIP")
    for case in IP_YES:
        address = case.strip("()/").removeprefix("http://").split(":")[0]
        assert found[case] == _expected(case, address), case
    for case in IP_NO:
        assert found[case] == [], case


def test_placeholders_coloured_only_when_real(box, work):
    found = _spans(box, work, PLACEHOLDER_YES + PLACEHOLDER_NO, "pwnnotePlaceholder")
    for case in PLACEHOLDER_YES:
        assert found[case] == _expected(case, case), case
    for case in PLACEHOLDER_NO:
        assert found[case] == [], case


def test_f8_on_a_box_line_puts_the_fold_below_the_box(box, note, work, dc01, web):
    got = run_vim(box.path, work, r"""
call cursor(3, 5)
execute "normal \<F8>"
call Put('lines', getline(1, 15))
call Put('cursor', line('.'))
""")
    box_lines = note.splitlines()[:11]
    assert got["lines"][:11] == box_lines
    assert got["lines"][11:14] == [FOLD_START, "", FOLD_END]
    assert got["cursor"] == 13
    edited = "\n".join(got["lines"]) + "\n" + "\n".join(note.splitlines()[11:]) + "\n"
    assert update_box(edited, box, [dc01, web]) == edited


def test_markdown_never_loads(box, note, work):
    got = run_vim(box.path, work, r"""
call Put('filetype', &filetype)
call Put('markdown', map(getscriptinfo({'name': 'syntax/markdown'}), 'v:val.name'))
call Put('syntax', b:current_syntax)
""")
    assert got["filetype"] == "pwnnote" and got["syntax"] == "pwnnote"
    assert got["markdown"] == []


def test_comma_h_lists_the_note_keys(box, note, work):
    got = run_vim(box.path, work, r"""
call Put('map', maparg(',h', 'n'))
call Put('lines', Script('HelpLines'))
call Script('Help')
call Put('popups', len(popup_list()))
let ids = popup_list()
if !empty(ids)
  call Put('shown', getbufline(winbufnr(ids[0]), 1, '$'))
  call Put('title', popup_getoptions(ids[0]).title)
  " vim's own events, such as the idle CursorHold the save and reload hang on, leave it open
  call Put('idle', Script('HelpKey', ids[0], "\x80\xfd`"))
  call Put('still', len(popup_list()))
  " a typed key closes it
  call Script('HelpKey', ids[0], 'x')
  call Put('after', len(popup_list()))
endif
""")
    assert "Help()" in got["map"]
    keys = [line.split()[0] for line in got["lines"] if line[:1] in (",", "F", "z", ":")]
    assert keys == [",h", ",t", ",i", ",c", ",x", "F8", ":Pb", "za", "zo", "zR"]
    assert got["popups"] == 1
    assert got["shown"] == got["lines"] + ["", "any key closes this"]
    assert got["title"] == " note keys "
    assert got["idle"] == 0 and got["still"] == 1
    assert got["after"] == 0


def test_comma_t_i_c_are_mapped(box, note, work):
    got = run_vim(box.path, work, r"""
for key in [',t', ',i', ',c']
  call Put(key, maparg(key, 'n'))
endfor
""")
    assert "Insert(strftime(" in got[",t"]
    assert "InsertIp()" in got[",i"]
    assert "PickCred()" in got[",c"]


def test_insert_puts_text_after_the_cursor_as_it_is(box, note, work):
    got = run_vim(box.path, work, r"""
call setline(1, 'abcd')
call cursor(1, 2)
call Script('Insert', 'X|<Esc>\y')
call Put('one', [getline(1), col('.')])
call setline(2, '')
call cursor(2, 1)
call Script('Insert', "pass\nword")
call Put('empty', [getline(2), col('.')])
call setline(3, 'é!')
call cursor(3, 1)
call Script('Insert', 'Z')
call Put('wide', getline(3))
""")
    # after the b, keys and backslashes kept, the cursor on the last character put in
    assert got["one"] == ["abX|<Esc>\\ycd", 11]
    # a line break never splits the line
    assert got["empty"] == ["password", 8]
    # after a whole character, not inside it
    assert got["wide"] == "éZ!"


def test_comma_i_takes_the_ip_of_the_section_the_cursor_is_in(box, note, work):
    got = run_vim(box.path, work, r"""
call cursor(Find('^Target: dc01'), 1)
normal! j
call Put('dc01', Script('TargetIp'))
call cursor(Find('^Target: web'), 1)
call Put('web', Script('TargetIp'))
call cursor(1, 1)
call Put('box', Script('TargetIp'))
""")
    assert got == {"dc01": "10.10.10.161", "web": "10.10.10.5", "box": ""}


def test_comma_i_with_no_ip_says_so_and_inserts_nothing(box, note, work):
    got = run_vim(box.path, work, r"""
call cursor(1, 1)
let before = getline(1)
call Script('InsertIp')
call Put('same', getline(1) ==# before)
""")
    assert got["same"] == 1


def test_comma_c_offers_the_box_s_pairs(box, note, work):
    lists = box.path / "lists"
    lists.mkdir(exist_ok=True)
    (lists / "userpass.txt").write_text("svc-alfresco:s3rvice\nadmin:P@ss|w0rd\n", encoding="utf-8")
    (lists / "userhash.txt").write_text("administrator:32693b11e6aa90eb43d32c72a07ceea6\n", encoding="utf-8")
    got = run_vim(box.path, work, r"""
call Put('choices', Script('CredChoices'))
""")
    assert got["choices"] == [
        "svc-alfresco:s3rvice", "admin:P@ss|w0rd", "administrator:32693b11e6aa90eb43d32c72a07ceea6",
    ]


def test_comma_c_with_no_lists_offers_nothing(box, note, work):
    got = run_vim(box.path, work, r"""
call Put('choices', Script('CredChoices'))
""")
    assert got["choices"] == []


# ---- playbooks: :Pb and ,x


@pytest.fixture
def notes_file(work):
    """Two playbooks installed for the box, as the app lays them out, and the run/notes file."""
    import toolkit

    root = work / "tools" / "playbooks" / "2026.11.19-1" / "files" / "playbooks"
    for rel, data in toolkit.notes_files().items():
        path = root / rel.removeprefix("files/playbooks/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    listing = work / "run-notes"
    listing.write_text(root.as_posix() + "\n", encoding="utf-8")
    return listing


def with_notes(listing, script):
    return f"let g:pwn_notes_file = '{listing.as_posix()}'\n" + script


def smb_lines():
    import toolkit

    return toolkit.notes_files()["files/playbooks/02-enum/smb.md"].decode().splitlines()


def test_pb_reads_below_the_cursor_with_its_fold_open(box, note, work, notes_file):
    got = run_vim(box.path, work, with_notes(notes_file, r"""
let outer = Find('^Target: dc01 ') - 1
execute outer . 'foldopen'
let row = Find('^login as ')
call cursor(row, 3)
Pb smb
call Put('row', row)
call Put('lines', getline(row + 1, row + 3))
call Put('cursor', line('.'))
call Put('here', getline('.'))
call Put('closed', foldclosed('.'))
"""))
    assert got["lines"][0] == FOLD_START
    assert got["lines"][1].startswith("Playbook: SMB enumeration   02-enum/smb   ")
    assert got["cursor"] == got["row"] + 3 and got["here"] == "my"
    assert got["closed"] == -1


def test_pb_on_a_box_line_reads_below_the_box(box, note, work, notes_file):
    got = run_vim(box.path, work, with_notes(notes_file, r"""
call cursor(3, 5)
Pb smb
call Put('lines', getline(1, 14))
"""))
    assert got["lines"][:11] == note.splitlines()[:11]
    assert got["lines"][11] == FOLD_START and got["lines"][12].startswith("Playbook: SMB")


def test_pb_on_a_closed_fold_reads_below_the_fold(box, note, work, notes_file):
    got = run_vim(box.path, work, with_notes(notes_file, r"""
let start = Find('^Target: dc01 ') - 1
call cursor(start, 1)
let end = foldclosedend(start)
Pb smb
call Put('end', end)
call Put('after', getline(end + 1, end + 2))
"""))
    assert got["end"] > 0
    assert got["after"][0] == FOLD_START and got["after"][1].startswith("Playbook: SMB")


def test_pb_completion_matches_any_part_of_the_name(box, note, work, notes_file):
    got = run_vim(box.path, work, with_notes(notes_file, r"""
call Put('erv', PwnPbComplete('erv', '', 0))
call Put('all', PwnPbComplete('', '', 0))
call Put('upper', PwnPbComplete('SM', '', 0))
call Put('none', PwnPbComplete('zzz', '', 0))
"""))
    assert got == {"erv": ["services"], "all": ["services", "smb"], "upper": ["smb"], "none": []}


@pytest.mark.parametrize("listing", ["missing", "empty", "gone"])
def test_pb_with_no_playbooks_says_so(box, note, work, listing):
    path = work / "run-notes"
    if listing == "empty":
        path.write_text("", encoding="utf-8")
    elif listing == "gone":
        path.write_text((work / "no-such-folder").as_posix() + "\n", encoding="utf-8")
    got = run_vim(box.path, work, with_notes(path, r"""
let before = getline(1, '$')
call Put('msg', execute('Pb smb'))
call Put('same', getline(1, '$') ==# before)
"""))
    assert "no playbooks for this box: tool install playbooks at the prompt" in got["msg"]
    assert got["same"] == 1


def test_pb_unknown_name_says_so(box, note, work, notes_file):
    got = run_vim(box.path, work, with_notes(notes_file, r"""
let before = getline(1, '$')
call Put('msg', execute('Pb nope'))
call Put('same', getline(1, '$') ==# before)
"""))
    assert "no playbook named nope; :Pb on its own lists them" in got["msg"]
    assert got["same"] == 1


def copies(lines):
    """Each copy of the smb playbook in the note, from its Playbook: line to its END OF line."""
    found = []
    for n, line in enumerate(lines):
        if line.startswith("Playbook: SMB"):
            end = lines.index("END OF smb PLAYBOOK", n)
            found.append((n, lines[n : end + 1]))
    return found


FILL_FIRST = r"""
let outer = Find('^Target: dc01 ') - 1
execute outer . 'foldopen'
call cursor(Find('^login as '), 1)
Pb smb
let first = line('.')
let web = Find('^Target: web') - 1
execute web . 'foldopen'
call cursor(Find('^Target: web'), 1)
Pb smb
call cursor(first, 1)
let t = search('^:''y,''zs/<TargetIP>/', 'W')
call setline(t, ":'y,'zs/<TargetIP>/10.10.10.161/ge")
let u = search('^:''y,''zs/<Username>/', 'W')
execute u . 'delete'
BEFORE_RUN
call cursor(first, 1)
execute "normal! V}\"qy"
normal @q
call Put('cursor', line('.'))
call Put('lines', getline(1, '$'))
"""


def test_run_block_fills_only_its_own_playbook(box, note, work, notes_file):
    got = run_vim(box.path, work, with_notes(notes_file, FILL_FIRST.replace("BEFORE_RUN", "")))
    lines = got["lines"]
    (first_at, first), (_second_at, second) = copies(lines)
    original = smb_lines()[1:-1]
    assert second == original
    body = first[first.index("Fill in:  10.10.10.161  <Username>") :]
    assert "nxc smb 10.10.10.161 -u '' -p ''" in body
    assert "nxc smb 10.10.10.161 -u <Username> -p ''" in body
    assert not any("<TargetIP>" in line for line in body)
    # back at the first copy's run block: 'y goes to its my line, and the Enter ending that line
    # and the blank line after it each move one line down (vim counts from 1)
    assert got["cursor"] == first_at + 2 + 2


def test_run_block_with_its_end_line_gone_replaces_nothing(box, note, work, notes_file):
    script = FILL_FIRST.replace(
        "BEFORE_RUN",
        "let gone = search('^END OF smb PLAYBOOK$', 'W')\nexecute gone . 'delete'\n"
        "let second = search('^END OF smb PLAYBOOK$', 'W')\nexecute second . 'delete'",
    )
    got = run_vim(box.path, work, with_notes(notes_file, script))
    assert sum("<TargetIP>" in line for line in got["lines"]) == sum(
        "<TargetIP>" in line for line in smb_lines()
    ) * 2


FILL_SECOND_WITH_ITS_END_GONE = r"""
let outer = Find('^Target: dc01 ') - 1
execute outer . 'foldopen'
call cursor(Find('^login as '), 1)
Pb smb
let web = Find('^Target: web') - 1
execute web . 'foldopen'
call cursor(Find('^Target: web'), 1)
call append(line('.'), 'my own note between: <TargetIP> still to check')
call cursor(line('.') + 1, 1)
Pb smb
let second = line('.')
let t = search('^:''y,''zs/<TargetIP>/', 'W')
call setline(t, ":'y,'zs/<TargetIP>/10.10.10.5/ge")
let gone = search('^END OF smb PLAYBOOK$', 'W')
execute gone . 'delete'
call cursor(second, 1)
execute "normal! V}\"qy"
let v:errmsg = ''
silent! normal @q
call Put('error', v:errmsg)
call Put('lines', getline(1, '$'))
"""


def test_run_block_with_its_end_line_gone_never_reaches_a_copy_above(box, note, work, notes_file):
    # the search must not wrap round to the END OF line of an earlier copy: that range runs
    # backwards, and interactive vim offers to swap it, taking the answer from the register
    got = run_vim(box.path, work, with_notes(notes_file, FILL_SECOND_WITH_ITS_END_GONE))
    assert "E486" in got["error"] and "E493" not in got["error"]
    assert "my own note between: <TargetIP> still to check" in got["lines"]
    assert not any("10.10.10.5 -u" in line for line in got["lines"])


def test_comma_x_toggles(box, note, work):
    got = run_vim(box.path, work, r"""
call append(line('$'), ['- [ ] a', 'plain'])
call cursor(line('$') - 1, 1)
call Script('ToggleBox')
call Put('ticked', getline('.'))
call Script('ToggleBox')
call Put('unticked', getline('.'))
call cursor(line('$'), 1)
call Put('msg', execute("call Script('ToggleBox')"))
call Put('plain', getline('.'))
call Put('map', maparg(',x', 'n'))
""")
    assert (got["ticked"], got["unticked"], got["plain"]) == ("- [x] a", "- [ ] a", "plain")
    assert "no [ ] or [x] on this line" in got["msg"]
    assert "ToggleBox()" in got["map"]
