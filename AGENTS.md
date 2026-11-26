# Agent instructions — pwn-broker

Read before touching `src/pwn_broker/`, `install.sh`, `docs/`, or release panels.

## What this repo is

`pwn-broker` is the Kali Linux CLI workspace manager for Hack The Box / OSCP boxes (targets, notes, credentials, recordings, VPN, scans, tools, archives). Its `docs/` GitHub Pages site is part of the unified four-tab **pwn handbook** (`pwn-broker`, `pwn-shop`, `pwn-playbooks`, `pwn-report`).

## Brand contract (Cyclorama Dawn `v2.1.0`)

Source of truth: `Real-Fruit-Snacks/rfs-brand` (`v2.1.0`).

- **Dark-first (`LX 263` `#050507`)** default; **Light (`LX 512` `#F5F7F9`)** opt-in toggle with radial View Transition and cross-tab `rfs-theme` `localStorage` sync.
- **CLI & Vim (`src/pwn_broker/theme.py`, `src/pwn_broker/data/nightshift.vim`, `install.sh`):** Beacon Orange `#FF9254` prompt/placeholders, Signal Mint `#3DDC97` `ok`, Amber `#FFC247` `warn`/IPs, Signal Crimson `#FF5C6C` `fail`/errors (`256`-color `203`), matte `#050507`/`#0D0E12`/`#161820` vim surfaces, `#F2F4F8` text (`256`-color `231`), `#8F95A6` muted. Always keep `install.sh` escape codes in exact sync with `theme.py` (`test_install_sh.py`).
- **Fonts:** Self-hosted variable WOFF2 only (`Big Shoulders Stencil`, `Albert Sans`, `Azeret Mono`, `OFL.txt`) — zero external CDNs.
- **Chrome:** Below-header `.rfs-shell` scroll container (`<header class="rfs-shell-header">` + `<div class="rfs-scroll-region">`), wrapped command cards, Cartesian `in oklab` gradients only, zero neon glows, zero capsule pills, zero native `alert()`/`confirm()`/`prompt()`, semantic `[ok]` `popover="manual"` toasts.
- **Shared handbook contract:** The shared base of `docs/styles.css` and `docs/script.js` stays identical across `pwn-broker`, `pwn-shop`, `pwn-playbooks`, and `pwn-report` up to the `this page` comment.

## Required checks before pushing

```sh
python docs/art/make-panel.py
python -m pytest -q -W error
```

- Keep `install.sh` strictly LF and POSIX `sh` / `shellcheck` clean.
- `docs/assets/panel-{dark,light}.svg` must match `docs/art/make-panel.py` byte-for-byte.
- **README & Docs (`BRAND.md` §14):** Keep `README.md` ultra-minimal (40–60 lines); put walkthroughs, config tables, and known issues in `docs/USAGE.md`, `docs/guide.md`, and `docs/tested.md` (never GitHub Wiki).
- Never mention private repositories or unrelated internal tools in any public file.
