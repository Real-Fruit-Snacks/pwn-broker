import ipaddress
from dataclasses import dataclass, field
from datetime import date

from pwn_broker.boxes import SCOPES, BoxError, find_target, parse_values
from pwn_broker.console import Console
from pwn_broker.creds import KINDS, CredError, check_field, has_edge_space, last_domain
from pwn_broker.model import Cred, Target
from pwn_broker.paths import safe_name
from pwn_broker.session import Session


@dataclass
class TargetAnswers:
    ips: list[str]
    hostnames: list[str]
    scope: str
    name: str


def _bad_ip(values: list[str]) -> str | None:
    for value in values:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return value
    return None


def _usable(name: str) -> bool:
    try:
        safe_name(name)
    except ValueError:
        return False
    return True


def _values(console: Console, label: str, default: str, clearable: bool) -> list[str]:
    answer = console.ask(label, default or None)
    # a lone "-" lets an edit empty a field that has a default
    if clearable and answer == "-":
        return []
    return parse_values(answer)


def ask_target(
    console: Console,
    *,
    heading: str,
    taken: set[str],
    defaults: Target | None = None,
    ask_name: bool = True,
    ips: list[str] | None = None,
    hostnames: list[str] | None = None,
) -> TargetAnswers:
    # `ips` and `hostnames` prefill a target that does not exist yet
    console.heading(heading)
    answers = _ask_target(console, taken, defaults, ask_name, ips, hostnames)
    console.gap()
    return answers


def _ask_target(
    console: Console,
    taken: set[str],
    defaults: Target | None,
    ask_name: bool,
    ips: list[str] | None,
    hostnames: list[str] | None,
) -> TargetAnswers:
    default_ips = " ".join(defaults.ips if defaults else ips or [])
    default_hosts = " ".join(defaults.hostnames if defaults else hostnames or [])

    while True:
        while True:
            ips = _values(console, "ip", default_ips, defaults is not None)
            bad = _bad_ip(ips)
            if bad is None:
                break
            console.fail(f"not an IP address: {bad}")
        hostnames = _values(console, "hostname", default_hosts, defaults is not None)
        if ips or hostnames:
            break
        console.fail("a target needs at least one IP address or hostname")

    while True:
        scope = console.ask("scope", defaults.scope if defaults else "external")
        if scope in SCOPES:
            break
        console.fail("scope must be external or internal")

    if defaults is not None and not ask_name:
        return TargetAnswers(ips, hostnames, scope, defaults.name)

    default_name = defaults.name if defaults else (hostnames or ips)[0]
    while True:
        name = console.ask("name", default_name)
        if name in taken or (_usable(name) and safe_name(name) in taken):
            console.fail(f"a target named {name} already exists")
        elif not _usable(name):
            console.fail(f"nothing usable in {name!r}")
        else:
            return TargetAnswers(ips, hostnames, scope, name)


@dataclass
class CredAnswers:
    username: str
    domain: str
    secret: str
    kind: str
    found_on: str
    note: str
    works_on: list[str] = field(default_factory=list)


def ask_value(
    console: Console, label: str, default: str | None = None, *, sentinel: str | None = None
) -> str:
    # `sentinel` is an answer with its own meaning (the "-" for no domain), returned as typed
    while True:
        answer = console.ask(label, default)
        try:
            check_field(label, answer)
        except CredError as exc:
            console.fail(str(exc))
            continue
        break
    if answer == sentinel or not has_edge_space(answer):
        return answer
    console.warn(f"the {label} starts or ends with a space")
    while True:
        choice = console.ask("keep or trim", "keep")
        if choice == "keep":
            return answer
        if choice == "trim":
            return answer.strip()


def ask_domain(console: Console, session: Session, current: str | None = None) -> str:
    default = last_domain(session.creds) if current is None else current
    answer = ask_value(console, "domain", default or None, sentinel="-")
    # a lone "-" is how a default domain is declined
    return "" if answer == "-" else answer


def ask_found_on(console: Console, session: Session, current: str | None = None) -> str:
    names = {t.name for t in session.targets}
    if current is None:
        default = session.current.name if session.current else None
    else:
        # a stored name that is empty or no longer a target is not worth offering
        default = current if current in names else None
    blank_ok = not names or (current is not None and default is None)
    while True:
        answer = console.ask("found on", default)
        if answer == "" and blank_ok:
            return ""
        if not names:
            console.fail("this box has no targets yet, leave found on blank")
            continue
        try:
            return find_target(session.targets, answer).name
        except BoxError as exc:
            console.fail(str(exc))


def ask_works_on(console: Console, session: Session, current: list[str]) -> list[str]:
    while True:
        answer = console.ask("works on", " ".join(current) or None)
        if answer.strip() == "-":
            return []
        names = []
        try:
            for word in answer.split():
                # a name already on the list is kept as it is, even if that target is gone
                names.append(word if word in current else find_target(session.targets, word).name)
        except BoxError as exc:
            console.fail(str(exc))
            continue
        return list(dict.fromkeys(names))


def ask_cred(
    console: Console, session: Session, defaults: Cred | None = None, *, heading: str
) -> CredAnswers:
    console.heading(heading)
    answers = _ask_cred(console, session, defaults)
    console.gap()
    return answers


def _ask_cred(console: Console, session: Session, defaults: Cred | None) -> CredAnswers:
    while True:
        username = ask_value(console, "username", defaults.username if defaults else None)
        if username != "":
            break
        console.fail("username must not be empty")
    domain = ask_domain(console, session, defaults.domain if defaults else None)
    secret = ask_value(console, "secret", defaults.secret if defaults else None)

    kind = ""
    if secret != "":
        while True:
            kind = console.ask("kind", (defaults.kind if defaults else "") or "password")
            if kind in KINDS:
                break
            console.fail(f"kind must be one of: {', '.join(KINDS)}")

    found_on = ask_found_on(console, session, defaults.found_on if defaults else None)
    works_on = ask_works_on(console, session, defaults.works_on) if defaults else []
    note = ask_value(console, "note", (defaults.note if defaults else "") or None)
    return CredAnswers(username, domain, secret, kind, found_on, note, works_on)


@dataclass
class BoxAnswers:
    name: str
    platform: str
    day: date
    os_name: str
    difficulty: str


def ask_box(console: Console, *, default_platform: str, today: date) -> BoxAnswers:
    console.heading("New box")
    answers = _ask_box(console, default_platform, today)
    console.gap()
    return answers


def _ask_box(console: Console, default_platform: str, today: date) -> BoxAnswers:
    while True:
        name = console.ask("box name")
        if name != "" and _usable(name):
            break
        console.fail("the box name needs at least one letter or digit")

    platform = console.ask("platform", default_platform)

    while True:
        text = console.ask("date", today.isoformat())
        try:
            day = date.fromisoformat(text)
        except ValueError:
            console.fail("use the date format YYYY-MM-DD")
            continue
        break

    os_name = console.ask("os")
    difficulty = console.ask("difficulty")
    return BoxAnswers(name, platform, day, os_name, difficulty)
