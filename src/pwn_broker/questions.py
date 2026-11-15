import ipaddress
from dataclasses import dataclass

from pwn_broker.boxes import SCOPES, parse_values
from pwn_broker.console import Console
from pwn_broker.model import Target
from pwn_broker.paths import safe_name


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
