from pwn_broker import scanning
from pwn_broker.scanning import Done, ScanError
from pwn_broker.session import Session
from pwn_broker.shell.commands import command, take_args


def checks(session: Session) -> dict:
    return dict(alive=session.pid_alive, started=session.pid_started, cmdline=session.cmdline)


def _target(session: Session):
    target = session.current
    if target is None:
        raise ScanError("no target is selected; target use <target> first")
    return target


def _flags(session: Session) -> dict[str, list[str]]:
    settings = session.settings
    given = {"quick": settings.scan_quick, "full": settings.scan_full, "udp": settings.scan_udp}
    return {mode: scanning.parse_flags(text or scanning.DEFAULT_FLAGS[mode], mode) for mode, text in given.items()}


@command("scan", "run nmap on the current target in the background: quick, full, udp", "[quick|full|udp]")
def scan(session: Session, args: list[str]) -> None:
    [mode] = take_args(args, optional=("mode",))
    if mode is not None and mode not in scanning.MODES:
        raise ScanError(f"no scan mode {mode}; the modes are quick, full and udp")
    target = _target(session)
    plan = list(scanning.BARE) if mode is None else [mode]
    found = scanning.running(session.paths, session.box.id, target.name, **checks(session))
    if found:
        raise ScanError(
            f"a scan of {target.name} is running ({found[0].plan}, since {found[0].started:%H:%M}); scan stop first"
        )
    if "udp" in plan and not session.is_root():
        raise ScanError("a UDP scan needs root")
    nmap = session.which("nmap")
    if nmap is None:
        raise ScanError(scanning.NOT_INSTALLED)
    marker = scanning.start(
        session.paths, session.box, target, plan, nmap=nmap, flags=_flags(session),
        clock=session.clock, spawn=session.scan_spawn, alive=session.pid_alive,
        started=session.pid_started, sleep=session.sleep,
    )  # fmt: skip
    session.console.ok(f"scanning {target.name} ({marker.ip}): {marker.plan}")
    session.console.info(f"results go to targets/{target.name}/{scanning.SCANS}; a line here when each is done")


@command("scan stop", "stop the current target's scan")
def scan_stop(session: Session, args: list[str]) -> None:
    take_args(args)
    target = _target(session)
    scanning.stop(
        session.paths, session.box.id, target.name, killpg=session.killpg, sleep=session.sleep, **checks(session)
    )
    session.console.ok(f"stopped the scan of {target.name}")


@command("scan log", "show the last 20 lines nmap wrote for the current target's scan")
def scan_log(session: Session, args: list[str]) -> None:
    take_args(args)
    target = _target(session)
    lines = scanning.log_tail(session.paths, session.box.id, target.name)
    if not lines:
        session.console.info(f"no scan of {target.name} has run yet")
        return
    for line in lines:
        session.console.log(line)


# ---- said between commands, the status bar, and finish


def _said(done: Done) -> tuple[str, str]:
    what = f"scan {done.mode} of {done.target}"
    if done.status != 0:
        return "warn", f"{what} ended with status {done.status}; see: scan log"
    ports = ", ".join(p.split("/")[0] if p.endswith("/tcp") else p for p in done.ports) or "no ports"
    verb = "is" if len(done.ports) == 1 else "are"
    return "ok", f"{what} done: {ports} {verb if done.ports else 'are'} open   {done.file}"


def notices(session: Session) -> None:
    """Say each scan mode that finished since the last command, once."""
    for done in scanning.take_done(session.paths, session.box.id):
        kind, text = _said(done)
        (session.console.ok if kind == "ok" else session.console.warn)(text)


def toolbar_part(session: Session) -> str | None:
    found = scanning.running(session.paths, session.box.id, **checks(session))
    return f"scan {', '.join(m.target for m in found)}" if found else None


def block(session: Session) -> str | None:
    """finish waits while a scan writes into the box: what it writes later would not be archived."""
    found = scanning.running(session.paths, session.box.id, **checks(session))
    if not found:
        return None
    names = ", ".join(f"{m.target} ({m.plan})" for m in found)
    return f"a scan is still running: {names}. wait for it or scan stop, then finish again"
