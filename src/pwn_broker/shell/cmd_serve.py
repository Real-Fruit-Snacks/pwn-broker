import urllib.parse

from pwn_broker import serving
from pwn_broker.serving import Marker, ServeError
from pwn_broker.session import Session, current_tunnel
from pwn_broker.shell.commands import command, take_args


def _checks(session: Session) -> dict:
    return dict(alive=session.pid_alive, started=session.pid_started, cmdline=session.serve_cmdline)


def _where(marker: Marker) -> str:
    return serving.url(marker.address, marker.port)


def _show(session: Session, marker: Marker, *, fresh: bool) -> None:
    console = session.console
    whose = f"{marker.target}'s upload folder and the tools' files"
    base = serving.url(marker.address, marker.port, f"/{marker.secret}/")
    if fresh:
        console.ok(f"serving {whose} on {base}")
    else:
        since = f"{marker.started:%Y-%m-%d %H:%M}"
        console.ok(f"serving {whose} on {base}, for {marker.box_name}, since {since}")
    files = serving.offered(serving.Path(marker.folder), session.paths.upload)
    if not files:
        console.info(f"nothing to offer yet: put files in targets/{marker.target}/{serving.UPLOAD}")
    for path, found in files:
        link = serving.url(marker.address, marker.port, f"/{marker.secret}" + urllib.parse.quote(path))
        for line in serving.download_lines(session.box.os or "", link, found.name):
            console.detail(line)
    console.info("serve log shows who fetched what; serve stop ends it")


@command(
    "serve",
    "offer the target's upload folder and the tools' files over HTTP",
    "[<interface or address>] [<port>]",
)
def serve(session: Session, args: list[str]) -> None:
    given, port_text = take_args(args, optional=("interface or address", "port"))
    running = serving.ours(session.paths, **_checks(session))
    if running is not None:
        if given is not None or port_text is not None:
            raise ServeError(f"already serving on {_where(running)}; serve stop first")
        _show(session, running, fresh=False)
        return
    target = session.current
    if target is None:
        raise ServeError("no target is selected; target use <target> first")
    tunnel = current_tunnel(session, fresh=True)
    known = dict(session.interfaces()) if given is not None else {}
    if tunnel is not None:
        known.setdefault(tunnel.name, [tunnel.address])
    address = serving.resolve(given, tunnel.address if tunnel else None, known)
    port = serving.parse_port(port_text, session.is_root())
    marker = serving.start(
        session.paths, session.box, target, address, port,
        clock=session.clock, spawn=session.serve_spawn, alive=session.pid_alive,
        started=session.pid_started, sleep=session.sleep,
    )  # fmt: skip
    if address == "0.0.0.0":
        session.console.warn("listening on every interface, not only the tunnel")
    _show(session, marker, fresh=True)


@command("serve stop", "stop serving files")
def serve_stop(session: Session, args: list[str]) -> None:
    take_args(args)
    marker = serving.stop(session.paths, kill=session.kill, sleep=session.sleep, **_checks(session))
    session.console.ok(f"stopped serving on {_where(marker)}")


@command("serve log", "show the last 20 requests and server lines")
def serve_log(session: Session, args: list[str]) -> None:
    take_args(args)
    lines = serving.log_tail(session.paths)
    if not lines:
        session.console.info("the server has written nothing yet")
        return
    for line in lines:
        session.console.log(line)


# ---- finish


def summary(session: Session) -> list[tuple[str, str]]:
    marker = serving.ours(session.paths, **_checks(session))
    if marker is None or marker.box_id != session.box.id:
        return []
    return [("serving", f"{_where(marker)}   (will be stopped)")]


def undo(session: Session) -> None:
    """At finish, stop the server this box started; a problem is a warn line, never raised."""
    try:
        marker = serving.ours(session.paths, **_checks(session))
        if marker is None or marker.box_id != session.box.id:
            return
        serving.stop(session.paths, kill=session.kill, sleep=session.sleep, **_checks(session))
        session.console.ok(f"stopped serving on {_where(marker)}")
    except Exception as exc:
        session.console.warn(f"the file server could not be stopped: {exc}; run serve stop")
