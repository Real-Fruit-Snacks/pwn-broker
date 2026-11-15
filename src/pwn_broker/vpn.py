import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass

TUN = re.compile(r"tun([0-9]+)")


@dataclass
class Tunnel:
    name: str
    address: str


def _address(entry: dict) -> str | None:
    for info in entry.get("addr_info") or []:
        if info.get("family") != "inet":
            continue
        try:
            return str(ipaddress.IPv4Address(info.get("local")))
        except ValueError:
            return None
    return None


def tunnel(run=subprocess.run) -> Tunnel | None:
    """The tun interface with the lowest number that has an IPv4 address; any failure means none."""
    try:
        done = run(
            ["ip", "-j", "-4", "addr", "show"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=1,
            check=False,
        )
        if done.returncode != 0:
            return None
        found: list[tuple[int, Tunnel]] = []
        for entry in json.loads(done.stdout):
            match = TUN.fullmatch(entry["ifname"])
            address = _address(entry) if match else None
            if match and address:
                found.append((int(match[1]), Tunnel(entry["ifname"], address)))
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError, AttributeError):
        return None
    return min(found, key=lambda pair: pair[0])[1] if found else None
