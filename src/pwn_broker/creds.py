from collections.abc import Iterable
from datetime import datetime

from pwn_broker.model import Cred

KINDS = ("password", "hash", "token", "other")

TEXT_FIELDS = ("username", "domain", "secret", "found_on", "note")
EDITABLE = (*TEXT_FIELDS, "kind", "works_on")


class CredError(Exception):
    pass


def check_field(label: str, value: str) -> None:
    if "\n" in value or "\r" in value:
        raise CredError(
            f"{label} spans more than one line; save multi-line values "
            "as a file in the target's creds/ folder"
        )


def has_edge_space(value: str) -> bool:
    return value != value.strip()


def _validate(values: dict) -> None:
    for name in TEXT_FIELDS:
        check_field(name, values[name])
    for target in values["works_on"]:
        check_field("works_on", target)
    if values["username"] == "":
        raise CredError("username must not be empty")
    if values["secret"] != "" and values["kind"] not in KINDS:
        raise CredError(f"kind must be one of: {', '.join(KINDS)}")


def _targets(targets) -> list[str]:
    if isinstance(targets, str):
        raise CredError("targets must be a list of names, not one string")
    unique = list(dict.fromkeys(targets))
    for target in unique:
        check_field("works_on", target)
    return unique


def _find(creds: list[Cred], n: int) -> Cred:
    for cred in creds:
        if cred.n == n:
            return cred
    raise CredError(f"no credential numbered {n}")


def add_cred(
    creds: list[Cred],
    *,
    username: str,
    domain: str,
    secret: str,
    kind: str,
    found_on: str,
    note: str,
    now: datetime,
    floor: int = 0,
) -> Cred:
    values = dict(
        username=username, domain=domain, secret=secret, kind=kind,
        found_on=found_on, note=note, works_on=[],
    )  # fmt: skip
    _validate(values)
    if secret == "":
        values["kind"] = ""
    highest = max((c.n for c in creds), default=0)
    cred = Cred(n=max(floor, highest) + 1, added=now, **values)
    creds.append(cred)
    return cred


def edit_cred(creds: list[Cred], n: int, /, **changes) -> Cred:
    cred = _find(creds, n)
    unknown = sorted(set(changes) - set(EDITABLE))
    if unknown:
        raise CredError(f"cannot edit: {', '.join(unknown)}")
    values = {name: getattr(cred, name) for name in EDITABLE}
    values.update(changes)
    if "works_on" in changes:
        values["works_on"] = _targets(changes["works_on"])
    _validate(values)
    if values["secret"] == "":
        values["kind"] = ""
    for name, value in values.items():
        setattr(cred, name, value)
    return cred


def remove_cred(creds: list[Cred], n: int) -> Cred:
    cred = _find(creds, n)
    creds.remove(cred)
    return cred


def mark_works(creds: list[Cred], n: int, targets: list[str]) -> Cred:
    cred = _find(creds, n)
    for target in _targets(targets):
        if target not in cred.works_on:
            cred.works_on.append(target)
    return cred


def import_usernames(
    creds: list[Cred],
    lines: Iterable[str],
    *,
    domain: str,
    found_on: str,
    now: datetime,
    floor: int = 0,
) -> int:
    check_field("domain", domain)
    check_field("found_on", found_on)
    seen = {c.username for c in creds}
    added = 0
    for line in lines:
        # Only the line ending goes; spaces inside a username are the user's.
        for ending in ("\r\n", "\n", "\r"):
            if line.endswith(ending):
                line = line[: -len(ending)]
                break
        if line.strip() == "" or "\r" in line or "\n" in line or line in seen:
            continue
        add_cred(
            creds, username=line, domain=domain, secret="", kind="",
            found_on=found_on, note="", now=now, floor=floor,
        )  # fmt: skip
        seen.add(line)
        added += 1
    return added


def last_domain(creds: list[Cred]) -> str:
    with_domain = [c for c in creds if c.domain != ""]
    if not with_domain:
        return ""
    return max(with_domain, key=lambda c: (c.added, c.n)).domain
