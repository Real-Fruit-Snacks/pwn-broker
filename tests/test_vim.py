"""The packaged vimrc run by a real vim, headless (-es), on a note the app rendered.

Ex mode never reaches vim's main loop, so timers, focus events and TextChanged do not fire on their
own: the scripts call the timer's function or fire the autocommand by hand.
"""

import json
import shutil
import subprocess
from dataclasses import replace
from importlib import resources
from pathlib import Path

import pytest

from pwn_broker.note import FOLD_END, FOLD_START, render_note, title_text, update_box

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
function! Script(name) abort
  return call(function('<SNR>' . getscriptinfo({'name': 'data/vimrc$'})[0].sid . '_' . a:name), [0])
endfunction
"""


def run_vim(folder: Path, work: Path, script: str) -> dict:
    """Opens folder/notes.md in vim with the packaged vimrc, runs script, returns what it Put."""
    out = work / "out.json"
    source = work / "check.vim"
    source.write_text(
        PRELUDE + script + f"\ncall writefile([json_encode(g:out)], '{out.as_posix()}')\nqa!\n",
        encoding="utf-8",
    )
    argv = ["vim", "-u", VIMRC.as_posix(), "-N", "-es", "-S", source.as_posix(), (folder / "notes.md").as_posix()]
    proc = subprocess.Popen(
        argv, cwd=folder, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
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
    assert got["hlsearch"] == 0 and got["autoread"] == 1 and got["updatetime"] == 1000
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


def _reload_script(newer: Path, how: str) -> str:
    reload = {
        "timer": "call Script('Reload')",
        "focus": "doautocmd FocusLost\nchecktime",
    }[how]
    return r"""
let dc01 = Find('^Target: dc01 ') - 1
let web = Find('^Target: web ') - 1
execute dc01 . 'foldopen'
execute web . 'foldopen'
call cursor(web + 1, 1)
let web_inner = search('^nested title$', 'nW') - 1
execute web_inner . 'foldopen'
execute web . 'foldclose'
let row = Find('^login as ')
call cursor(row, 10)
call Put('before', [line('.'), col('.'), getline('.'), line('$')])
call Put('before_folds', [foldclosed(dc01), foldclosed(web)])
call writefile(readfile('NEWER', 'b'), expand('%:p'), 'b')
RELOAD
let dc01 = Find('^Target: dc01 ') - 1
let web = Find('^Target: web ') - 1
let ws = Find('^Target: ws ')
call Put('after', [line('.'), col('.'), getline('.'), line('$')])
call Put('after_folds', [foldclosed(dc01), foldclosed(web), dc01, web])
call Put('box_has_ws', getline(1, 20))
call Put('dc01_inner', foldclosed(search('^nested title$', 'nW')))
execute web . 'foldopen'
call cursor(web + 1, 1)
let web_inner = search('^nested title$', 'nW') - 1
call Put('web_inner', [foldclosed(web_inner), web_inner])
call Put('modified', &modified)
""".replace("NEWER", newer.as_posix()).replace("RELOAD", reload)


@pytest.mark.parametrize("how", ["timer", "focus"])
@pytest.mark.parametrize("extra", [1, 12])
def test_reload_keeps_open_folds_and_the_cursor(box, note, work, dc01, web, how, extra):
    more = [replace(web, name=f"ws{i}" if i else "ws", ips=[f"10.10.20.{i}"]) for i in range(extra)]
    newer = work / "newer.md"
    newer.write_text(update_box(note, box, [dc01, web, *more]), encoding="utf-8", newline="")
    got = run_vim(box.path, work, _reload_script(newer, how))
    line, col, text, count = got["before"]
    assert got["before_folds"][0] == -1 and got["before_folds"][1] != -1
    assert got["after"] == [line + extra, col, text, count + extra]
    assert text.startswith("login as <DomainUser>")
    dc01_closed, web_closed, dc01_start, web_start = got["after_folds"]
    assert dc01_closed == -1
    assert web_closed == web_start
    assert any(row.startswith("#    ws ") for row in got["box_has_ws"])
    # the fold inside web was opened before web was closed, and is still open inside it
    assert got["web_inner"][0] == -1
    # the one inside dc01 was never opened
    assert got["dc01_inner"] != -1
    assert got["modified"] == 0


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
