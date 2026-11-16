import dataclasses
import os
from pathlib import Path

from pwn_broker import config, vpnctl
from pwn_broker.session import Session, current_tunnel, vpn_checks
from pwn_broker.shell.commands import command, take_args
from pwn_broker.vpn import Tunnel

TUNNEL_NOT_OURS = "a tunnel is up that pwn-broker did not start"


def _where(found: Tunnel) -> str:
    return f"{found.address} on {found.name}"


def _source(session: Session) -> Path | None:
    console = session.console
    state = config.load_state(session.paths.state_file)
    answer = console.ask_path("vpn file", state.last_vpn_file)
    if answer == "":
        console.fail("no vpn file given")
        return None
    source = Path(os.path.expanduser(answer))
    if not source.is_file():
        console.fail(f"no such file: {answer}")
        return None
    return source.absolute()


def _remember(session: Session, source: Path) -> None:
    path = session.paths.state_file
    state = config.load_state(path)
    config.save_state(path, dataclasses.replace(state, last_vpn_file=str(source)))


@command("vpn start", "copy a .ovpn file into the box and start OpenVPN")
def vpn_start(session: Session, args: list[str]) -> None:
    take_args(args)
    console = session.console
    checks = vpn_checks(session)
    marker = vpnctl.ours(session.paths, **checks)
    found = current_tunnel(session, fresh=True)
    if marker is not None:
        where = f"up, {_where(found)}" if found else "running, no tunnel yet"
        console.ok(f"vpn already {where}, started for {marker.box_name}")
        vpnctl.use(session.paths, session.box, marker, session.clock())
        return
    if found is not None:
        console.warn(f"{TUNNEL_NOT_OURS}: {_where(found)}")
        if not console.confirm("start another?", default=False):
            return
    if session.which(vpnctl.COMMAND) is None:
        raise vpnctl.VpnError(vpnctl.INSTALL)
    source = _source(session)
    if source is None:
        return
    copy = vpnctl.copy_into_box(session.box, source)
    console.ok(f"copied to vpn/{copy.name}")
    wait = 15.0
    try:
        _marker, found = vpnctl.start(
            session.paths,
            session.box,
            source,
            copy=copy,
            before=found,
            run=session.run_privileged,
            tunnel=lambda: current_tunnel(session, fresh=True),
            clock=session.clock,
            sleep=session.sleep,
            wait=wait,
            which=session.which,
            **checks,
        )
    except vpnctl.VpnError as exc:
        console.fail(str(exc))
        for line in exc.log:
            console.raw(line)
        return
    _remember(session, source)
    if found is not None:
        console.ok(f"vpn up, {_where(found)}")
    else:
        console.warn(f"not up after {wait:g} s; see: vpn log")


@command("vpn stop", "stop the VPN pwn-broker started")
def vpn_stop(session: Session, args: list[str]) -> None:
    take_args(args)
    console = session.console
    checks = vpn_checks(session)
    marker = vpnctl.ours(session.paths, **checks)
    if marker is None:
        if current_tunnel(session, fresh=True) is not None:
            console.fail("this tunnel was not started by pwn-broker; stop it yourself")
            return
        raise vpnctl.VpnError(vpnctl.NONE_RUNNING)
    stop(session, marker)


def stop(session: Session, marker: vpnctl.Marker) -> None:
    """Stop the app's VPN and say whether it went; VpnError when it is no longer running."""
    gone = vpnctl.stop(
        session.paths, run=session.run_privileged, sleep=session.sleep, **vpn_checks(session)
    )
    # the status bar should not show the old address
    current_tunnel(session, fresh=True)
    if gone:
        session.console.ok("vpn stopped")
    else:
        session.console.warn(f"openvpn is still running (pid {marker.pid})")


@command("vpn status", "whether a tunnel is up, and which box started it")
def vpn_status(session: Session, args: list[str]) -> None:
    take_args(args)
    console = session.console
    marker = vpnctl.ours(session.paths, **vpn_checks(session))
    found = current_tunnel(session, fresh=True)
    if marker is None:
        console.info(TUNNEL_NOT_OURS if found else "not up")
        return
    since = marker.started.astimezone(session.clock().tzinfo)
    rows = [
        ("state", "up" if found else "starting"),
        ("address", _where(found) if found else "-"),
        ("since", since.strftime("%Y-%m-%d %H:%M")),
        ("file", marker.file),
        ("started for", marker.box_name),
    ]
    console.fields(rows)


@command("vpn log", "the last lines of OpenVPN's log")
def vpn_log(session: Session, args: list[str]) -> None:
    take_args(args)
    lines = vpnctl.log_tail(session.paths)
    if not lines:
        session.console.info("no log yet")
        return
    for line in lines:
        session.console.raw(line)
