from datetime import datetime, timedelta, timezone

from pwn_broker.model import Cred

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
