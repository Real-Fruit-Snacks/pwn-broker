import ipaddress
from dataclasses import dataclass

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
    taken: set[str],
    defaults: Target | None = None,
    ask_name: bool = True,
) -> TargetAnswers:
    default_ips = " ".join(defaults.ips) if defaults else ""
    default_hosts = " ".join(defaults.hostnames) if defaults else ""

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


def ask_value(console: Console, label: str, default: str | None = None) -> str:
    while True:
        answer = console.ask(label, default)
        try:
            check_field(label, answer)
        except CredError as exc:
            console.fail(str(exc))
            continue
        break
    if not has_edge_space(answer):
        return answer
    console.info(f"the {label} starts or ends with a space")
    while True:
        choice = console.ask("keep or trim", "keep")
        if choice == "keep":
            return answer
        if choice == "trim":
            return answer.strip()


def ask_domain(console: Console, session: Session, current: str | None = None) -> str:
    default = last_domain(session.creds) if current is None else current
    answer = console.ask("domain", default or None)
    # a lone "-" is how a default domain is declined
    return "" if answer == "-" else answer


def ask_found_on(console: Console, session: Session, current: str | None = None) -> str:
    if not session.targets:
        while True:
            answer = console.ask("found on")
            if answer == "":
                return ""
            console.fail("this box has no targets yet, leave found on blank")
    default = current if current is not None else (session.current.name if session.current else "")
    while True:
        try:
            return find_target(session.targets, console.ask("found on", default or None)).name
        except BoxError as exc:
            console.fail(str(exc))


def ask_cred(console: Console, session: Session, defaults: Cred | None = None) -> CredAnswers:
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
    note = console.ask("note", (defaults.note if defaults else "") or None)
    return CredAnswers(username, domain, secret, kind, found_on, note)
