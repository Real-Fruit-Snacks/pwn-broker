from dataclasses import dataclass, field

from pwn_broker.model import Box, Cred, Target
from pwn_broker.store import write_text


@dataclass
class ListSummary:
    usernames: int
    passwords: int
    pairs: int
    hashes: int
    skipped: list[str] = field(default_factory=list)


def _unique(items) -> list[str]:
    return list(dict.fromkeys(items))


def _text(lines: list[str]) -> str:
    return "".join(line + "\n" for line in lines)


def _pairs(creds: list[Cred], kind: str) -> list[tuple[str, str]]:
    return _unique((c.username, c.secret) for c in creds if c.kind == kind)


def _colon_lines(pairs: list[tuple[str, str]]) -> list[str]:
    # a colon in the username would make "user:secret" ambiguous for the tools
    return [f"{u}:{s}" for u, s in pairs if ":" not in u]


def _hosts_lines(targets: list[Target]) -> list[str]:
    return [
        f"{ip} {' '.join(t.hostnames)}"
        for t in targets
        if t.hostnames
        for ip in t.ips
    ]  # fmt: skip


def rebuild_lists(box: Box, targets: list[Target], creds: list[Cred]) -> ListSummary:
    folder = box.path / "lists"
    folder.mkdir(parents=True, exist_ok=True)

    passwords = _pairs(creds, "password")
    hashes = _pairs(creds, "hash")
    pair_lines = _colon_lines(passwords)
    hash_lines = _colon_lines(hashes)

    files = {
        "usernames.txt": _unique(c.username for c in creds),
        "passwords.txt": _unique(c.secret for c in creds if c.kind == "password"),
        "userpass.txt": pair_lines,
        "hashes.txt": _unique(c.secret for c in creds if c.kind == "hash"),
        "userhash.txt": hash_lines,
        "pair-users.txt": [u for u, _ in passwords],
        "pair-passwords.txt": [s for _, s in passwords],
        "ips.txt": _unique(ip for t in targets for ip in t.ips),
        "hostnames.txt": _unique(h for t in targets for h in t.hostnames),
        "hosts.txt": _hosts_lines(targets),
    }

    for target in targets:
        working = [c for c in creds if target.name in c.works_on]
        for suffix, kind in (("userpass", "password"), ("userhash", "hash")):
            lines = _colon_lines(_pairs(working, kind))
            if lines:
                files[f"works-{target.name}-{suffix}.txt"] = lines

    for name, lines in files.items():
        write_text(folder / name, _text(lines))

    for pattern in ("works-*-userpass.txt", "works-*-userhash.txt"):
        for stale in folder.glob(pattern):
            if stale.name not in files and stale.is_file():
                stale.unlink()

    skipped = _unique(c.username for c in creds if c.kind in ("password", "hash") and ":" in c.username)
    return ListSummary(
        usernames=len(files["usernames.txt"]),
        passwords=len(files["passwords.txt"]),
        pairs=len(pair_lines),
        hashes=len(files["hashes.txt"]),
        skipped=skipped,
    )
