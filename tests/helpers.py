import os
from datetime import datetime, timedelta, timezone

from pwn_broker.model import Cred


def odd_name(folder, name: bytes = b"caf\xe9 \xff.txt", data: bytes = b"loot") -> bytes | None:
    """Makes a file whose name is not UTF-8 in the folder and returns its path as bytes.

    None where no file can have such a name: the test has nothing to run on.
    """
    try:
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(os.fsencode(folder), name)
        with open(path, "wb") as fh:
            fh.write(data)
    except (OSError, UnicodeError):
        return None
    return path


NOW = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone(timedelta(hours=2)))


NASTY = [
    'p@ss "word" with spaces\\',
    "[red]x[/red]",
    "a#b",
    "tab\there",
    "  lead and trail  ",
    "pässwörd",
    "'",
    "",
]


def make_cred(**overrides) -> Cred:
    values = dict(
        n=1,
        username="administrator",
        domain="HTB",
        secret="Passw0rd!",
        kind="password",
        found_on="forest",
        works_on=["dc01"],
        note="",
        added=NOW,
    )
    values.update(overrides)
    return Cred(**values)
