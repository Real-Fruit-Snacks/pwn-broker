"""Draw the README's animated panel: docs/assets/panel-dark.svg and panel-light.svg.

The panel acts out one box in a 16 s loop. On the left, a session at the app's prompt:
pwn-broker new, cred add at the forest/dc01 prompt, then finish. On the right, the box's folder
as each command leaves it: the box and its target appear, the credential fills creds.toml and the
lists, and finish packs the box into one archive in wrapped/, after which the box's own files are
folded away under its folder (finish keeps the working folder unless told to remove it).

Every line is one the app prints or the user types, and every name is one it creates, taken from a
run of new, cred add and finish (box forest on htb, target dc01 at 10.10.10.161, svc-alfresco /
s3rvice); the archive's path is the one it prints for the user kali, whose boxes live in
/home/kali/pwn-broker. The questions each command asks are left out. The terminal is 44
columns wide and wraps a long line the way a terminal does. The right side shows part of the box:
of lists/ only the three files the credential fills, and not the box's own screenshots/.

The SVG's base styles are the moment after the credential is saved, with the folder complete,
which is what a viewer that skips the animation shows.

Text is converted to paths from the page's own fonts (docs/fonts), because an SVG shown through
<img> can't load fonts. Run from the repo root:

    python -m pip install -r docs/art/requirements.txt
    python docs/art/make-panel.py
"""
import os
import sys

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont

HERE = os.path.dirname(os.path.abspath(__file__))
FONTS = os.path.join(HERE, "..", "fonts")
OUT = os.path.join(HERE, "..", "assets")

# RFS Nightshift and Dayshift; the colours of the app's own terminal output (src/pwn_broker/theme.py)
THEMES = {
    "dark": dict(plate="#1A1D24", glass="#070809", line="#262A33", ink="#E8E6E1", mute="#8A8F99",
                 ember="#FF6A3D", mint="#3DDC97"),
    "light": dict(plate="#FFFFFF", glass="#ECEAE4", line="#D6D3CB", ink="#1A1B1E", mute="#666A73",
                  ember="#C03B0A", mint="#15794D"),
}

W, H = 1000, 430
CYCLE = 16.0        # seconds
TYPE = 0.045        # per typed character (BRAND.md section 8)
FADE = 0.25         # a row on the right appearing or going
EASE = "cubic-bezier(.2,.7,.2,1)"
STILL = 6.5         # the moment the base styles show
OUT_AT = 15.2       # everything fades out, then the loop starts again

MONO = "ibm-plex-mono-latin-400-normal.woff2"
MONO_B = "ibm-plex-mono-latin-600-normal.woff2"

COLS = 44
HOME = "/home/kali/pwn-broker"
BOX = "2026-11-14_htb_forest"
ARCHIVE = f"{BOX}.finished.tar.gz"
PROMPT = "forest/dc01 > "

# The session. ("cmd", prompt, typed, prompt shown at, typing starts at) or ("ok", text, printed at).
T_TARGET, T_BOX, T_CRED, T_LISTS, T_ARCHIVE = 1.9, 2.05, 4.3, 4.45, 9.5
SESSION = [
    ("cmd", "$ ", "pwn-broker new", 0.0, 0.5),
    ("ok", "target dc01 created", T_TARGET),
    ("ok", "box forest created", T_BOX),
    ("cmd", PROMPT, "cred add", 2.6, 3.2),
    ("ok", "cred 1 saved, found on dc01", T_CRED),
    ("ok", "lists updated: 1 username, 1 password, 1 pair", T_LISTS),
    ("cmd", PROMPT, "finish", 4.9, 8.4),
    ("ok", f"archive {HOME}/wrapped/{ARCHIVE}", T_ARCHIVE),
    ("cmd", "$ ", "", 9.8, None),
]

# The folder. (row, depth, pieces, shown at); a piece is (text, face, column, state) where state is
# "ink", "mute", or ("fill", t, contents): an empty file, muted until t, when it gets `contents`.
G1 = [T_TARGET + 0.05 * i for i in range(5)]
G2 = [T_BOX + 0.05 * i for i in range(7)]
FILLS = [T_LISTS + 0.05 * i for i in range(3)]
TREE = [
    (0, 0, [("active/", MONO, 0, "ink")], 0.0),
    (1, 1, [(f"{BOX}/", MONO_B, 0, "ink")], G1[0]),
    (2, 2, [("box.toml", MONO, 0, "ink")], G2[0]),
    (3, 2, [("notes.md", MONO, 0, "ink")], G2[1]),
    (4, 2, [("creds.toml", MONO, 0, ("fill", T_CRED, None))], G2[2]),
    (5, 2, [("lists/", MONO, 0, "ink")], G2[3]),
    (6, 3, [("usernames.txt", MONO, 0, ("fill", FILLS[0], "svc-alfresco"))], G2[4]),
    (7, 3, [("passwords.txt", MONO, 0, ("fill", FILLS[1], "s3rvice"))], G2[5]),
    (8, 3, [("userpass.txt", MONO, 0, ("fill", FILLS[2], "svc-alfresco:s3rvice"))], G2[6]),
    (9, 2, [("targets/dc01/", MONO, 0, "ink")], G1[1]),
    (10, 3, [("target.toml", MONO, 0, "ink"), ("creds/", MONO, 13, "mute"), ("exploits/", MONO, 21, "mute")], G1[2]),
    (11, 3, [("files/", MONO, 0, "mute"), ("loot/", MONO, 8, "mute"), ("recordings/", MONO, 15, "mute")], G1[3]),
    (12, 3, [("scans/", MONO, 0, "mute"), ("screenshots/", MONO, 8, "mute")], G1[4]),
]
CONTENTS_COL = 15   # where a list's first line is shown, in characters after the file name's start
# After finish: the box's files fold away under its folder and the archive shows in wrapped/.
FOLD = T_ARCHIVE
WRAPPED = [
    (2, 0, "wrapped/", MONO, T_ARCHIVE + FADE),
    (3, 1, ARCHIVE, MONO_B, T_ARCHIVE + FADE + 0.1),
]

# Layout
LX, RX, TOP, BOTTOM = 40, 544, 76, 404       # left window from LX, right window from RX to W - 40
L_SIZE, R_SIZE = 17, 16
L_PAD, L_FIRST, L_PITCH = 20, 108, 28
R_PAD, R_FIRST, R_PITCH, R_INDENT = 16, 106, 23.5, 16

_fonts = {}
_glyphs = {}   # (font, glyph name) -> (id, path in font units); drawn once in <defs>, reused by <use>


def font(name):
    if name not in _fonts:
        _fonts[name] = TTFont(os.path.join(FONTS, name))
    return _fonts[name]


def char_w(size, fname=MONO):
    f = font(fname)
    return f.getGlyphSet()[f.getBestCmap()[ord("0")]].width * size / f["head"].unitsPerEm


def text(s, x, y, size, fname, fill, ls=0.0, anchor="start"):
    """Path for `s` with its baseline at y. ls is letter spacing in em."""
    f = font(fname)
    gs, cmap, upm = f.getGlyphSet(), f.getBestCmap(), f["head"].unitsPerEm
    k = size / upm
    names = []
    for ch in s:
        if ord(ch) not in cmap:
            sys.exit(f"{fname} has no glyph for {ch!r}")
        names.append(cmap[ord(ch)])
    width = sum(gs[n].width * k for n in names) + ls * size * (len(names) - 1)
    pen_x = {"start": x, "middle": x - width / 2, "end": x - width}[anchor]
    uses = []
    for n in names:
        key = (fname, n)
        if key not in _glyphs:
            pen = SVGPathPen(gs, ntos=lambda v: "%g" % round(v, 1))
            gs[n].draw(pen)
            _glyphs[key] = (f"g{len(_glyphs)}", pen.getCommands())
        gid, d = _glyphs[key]
        if d:
            uses.append(f'<use href="#{gid}" transform="matrix({k:.5f} 0 0 {-k:.5f} {pen_x:.2f} {y:.2f})"/>')
        pen_x += gs[n].width * k + ls * size
    return f'<g fill="{fill}">{"".join(uses)}</g>'


def pct(t):
    return f"{t / CYCLE * 100:.3f}%"


def status_line(kind, s):
    """As the app prints it (src/pwn_broker/console.py): the word padded to four, two spaces, the text."""
    return f"{kind:<4}  {s}"


def wrap(s):
    """A line as a COLS-wide terminal shows it."""
    return [s[i:i + COLS] for i in range(0, len(s), COLS)] or [""]


class Anim:
    """Collects the keyframes and the still-frame styles, one class per animated element."""

    def __init__(self):
        self.css, self.rules, self.base = [], [], []

    def toggle(self, name, start):
        """Shown from `start` to the end of the loop, switched on at once (a terminal printing)."""
        self.base.append(f".{name}{{opacity:{int(start <= STILL)}}}")
        if start <= 0:
            return
        self.css.append(f"@keyframes {name}{{0%{{opacity:0}}{pct(start)}{{opacity:1}}100%{{opacity:1}}}}")
        self.rules.append(f".{name}{{animation:{name} {CYCLE}s step-end infinite}}")

    def fade(self, name, changes, init=0):
        """Opacity that eases to each (t, value) in turn, over FADE."""
        value, still = init, init
        frames = [f"0%{{opacity:{init}}}"]
        for t, v in changes:
            frames.append(f"{pct(t)}{{opacity:{value};animation-timing-function:{EASE}}}")
            frames.append(f"{pct(t + FADE)}{{opacity:{v}}}")
            value = v
            if t <= STILL:
                still = v
        frames.append(f"100%{{opacity:{value}}}")
        self.base.append(f".{name}{{opacity:{still}}}")
        if changes:
            self.css.append(f"@keyframes {name}{{{''.join(frames)}}}")
            self.rules.append(f".{name}{{animation:{name} {CYCLE}s linear infinite}}")

    def style(self):
        return f"<style>{''.join(self.base)}@media (prefers-reduced-motion:no-preference){{{''.join(self.css)}{''.join(self.rules)}}}</style>"


def build(theme):
    c = THEMES[theme]
    a = Anim()
    run = []                      # everything that plays, inside one group that fades out at the end
    cw = char_w(L_SIZE)
    lx0 = LX + L_PAD

    def left_y(row):
        return L_FIRST + row * L_PITCH

    # --- the session, and where the cursor is ---
    cursor = []                   # (t, row, col, shown)
    row = 0
    for n, line in enumerate(SESSION):
        if line[0] == "cmd":
            _, prompt, typed, shown, typing = line
            y = left_y(row)
            a.toggle(f"p{n}", shown)
            run.append(f'<g class="p{n}">{text(prompt, lx0, y, L_SIZE, MONO_B, c["ember"])}</g>')
            cursor.append((shown, row, len(prompt), 1))
            for i, ch in enumerate(typed):
                t = typing + i * TYPE
                a.toggle(f"p{n}c{i}", t)
                run.append(f'<g class="p{n}c{i}">{text(ch, lx0 + (len(prompt) + i) * cw, y, L_SIZE, MONO, c["ink"])}</g>')
                cursor.append((t, row, len(prompt) + i + 1, 1))
            row += 1
        else:
            _, s, shown = line
            # the cursor leaves the prompt line when the command's output starts
            if cursor and cursor[-1][3]:
                cursor.append((shown, cursor[-1][1], cursor[-1][2], 0))
            parts = wrap(status_line("ok", s))
            g = []
            for i, part in enumerate(parts):
                y = left_y(row)
                if i == 0:
                    g.append(text(part[:4], lx0, y, L_SIZE, MONO, c["mint"]))
                    g.append(text(part[4:], lx0 + 4 * cw, y, L_SIZE, MONO, c["ink"]))
                else:
                    g.append(text(part, lx0, y, L_SIZE, MONO, c["ink"]))
                row += 1
            a.toggle(f"o{n}", shown)
            run.append(f'<g class="o{n}">{"".join(g)}</g>')

    # The cursor blinks twice when a prompt waits a while, then stays.
    waits = [line[3] for line in SESSION if line[0] == "cmd" and (line[4] is None or line[4] - line[3] > 1.5)]
    blinks = list(cursor)
    for start in waits:
        held = [p for p in blinks if p[0] <= start][-1]
        for dt, s in ((0.45, 0), (0.7, 1), (1.15, 0), (1.4, 1)):
            blinks.append((start + dt, held[1], held[2], s))
    blinks.sort()
    cur_w, cur_h = cw, L_SIZE * 1.05

    def at(col, r):
        return f"translate({lx0 + col * cw:.2f}px,{left_y(r) - L_SIZE * 0.8:.2f}px)"

    frames = []
    still = blinks[0]
    for t, r, col, s in blinks:
        frames.append(f"{pct(t)}{{transform:{at(col, r)};opacity:{s}}}")
        if t <= STILL:
            still = (t, r, col, s)
    a.base.append(f".cur{{transform:{at(still[2], still[1])};opacity:{still[3]}}}")
    first = blinks[0]
    a.css.append(f"@keyframes cur{{{''.join(frames)}100%{{transform:{at(first[2], first[1])};opacity:0}}}}")
    a.rules.append(f".cur{{animation:cur {CYCLE}s step-end infinite}}")
    run.append(f'<rect class="cur" x="0" y="0" width="{cur_w:.2f}" height="{cur_h:.2f}" fill="{c["ink"]}" fill-opacity=".7"/>')

    # --- the folder ---
    rcw = char_w(R_SIZE)
    rx0 = RX + R_PAD

    def right_y(r):
        return R_FIRST + r * R_PITCH

    for r, depth, pieces, shown in TREE:
        y, x = right_y(r), rx0 + depth * R_INDENT
        gone = [(FOLD, 0)] if r > 1 else []
        for i, (s, face, col, state) in enumerate(pieces):
            px = x + col * rcw
            name = f"t{r}p{i}"
            if state in ("ink", "mute"):
                a.fade(name, ([(shown, 1)] if shown > 0 else []) + gone, init=int(shown <= 0))
                run.append(f'<g class="{name}">{text(s, px, y, R_SIZE, face, c[state])}</g>')
                continue
            _, filled, contents = state
            a.fade(name + "m", [(shown, 1), (filled, 0)])
            a.fade(name + "i", [(filled, 1)] + gone)
            run.append(f'<g class="{name}m">{text(s, px, y, R_SIZE, face, c["mute"])}</g>')
            run.append(f'<g class="{name}i">{text(s, px, y, R_SIZE, face, c["ink"])}</g>')
            if contents:
                a.fade(name + "c", [(filled, 1)] + gone)
                run.append(f'<g class="{name}c">{text(contents, px + CONTENTS_COL * rcw, y, R_SIZE, MONO, c["mute"])}</g>')
    for r, depth, s, face, shown in WRAPPED:
        a.fade(f"w{r}", [(shown, 1)])
        run.append(f'<g class="w{r}">{text(s, rx0 + depth * R_INDENT, right_y(r), R_SIZE, face, c["ink"])}</g>')

    # --- the end of the loop: everything goes, then the shell prompt starts it again ---
    a.base.append(".run{opacity:1}")
    a.css.append(f"@keyframes run{{0%{{opacity:1}}{pct(OUT_AT)}{{opacity:1;animation-timing-function:{EASE}}}"
                 f"{pct(OUT_AT + 0.5)}{{opacity:0}}100%{{opacity:0}}}}")
    a.rules.append(f".run{{animation:run {CYCLE}s linear infinite}}")

    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img">']
    o.append(a.style())
    # --- the plate, the terminal and the folder's pane ---
    o.append(f'<rect x="0.5" y="0.5" width="{W - 1}" height="{H - 1}" rx="22" fill="{c["plate"]}" stroke="{c["line"]}"/>')
    o.append(text("pwn-broker", LX, 52, 16, MONO_B, c["mute"]))
    o.append(text(f"{HOME}/", RX, 52, 16, MONO, c["mute"]))
    o.append(f'<rect x="{LX}" y="{TOP}" width="{RX - 20 - LX}" height="{BOTTOM - TOP}" rx="12" fill="{c["glass"]}" stroke="{c["line"]}"/>')
    o.append(f'<rect x="{RX}" y="{TOP}" width="{W - 40 - RX}" height="{BOTTOM - TOP}" rx="12" fill="none" stroke="{c["line"]}"/>')
    o.append(f'<g class="run">{"".join(run)}</g>')

    defs = "".join(f'<path id="{gid}" d="{d}"/>' for gid, d in _glyphs.values() if d)
    o.insert(1, f"<defs>{defs}</defs>")
    o.append("</svg>")
    return "".join(o)


for theme in THEMES:
    _glyphs.clear()
    path = os.path.join(OUT, f"panel-{theme}.svg")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(build(theme) + "\n")
    print(f"wrote {os.path.relpath(path)} ({os.path.getsize(path) // 1024} KB)")
